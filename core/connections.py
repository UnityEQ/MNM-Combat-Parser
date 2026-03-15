"""
Enumerate TCP/UDP connections owned by a specific PID using iphlpapi.dll.
"""

import ctypes
import ctypes.wintypes as wt
import socket
import struct
import threading
import time
from collections import namedtuple

from core.logger import get_logger


Connection = namedtuple("Connection", [
    "protocol", "local_ip", "local_port", "remote_ip", "remote_port"
])

# --- Constants ---
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

# TCP states
TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD",
    5: "ESTAB", 6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT",
    9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}


# --- TCP Structures ---
class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wt.DWORD),
        ("dwLocalAddr", wt.DWORD),
        ("dwLocalPort", wt.DWORD),
        ("dwRemoteAddr", wt.DWORD),
        ("dwRemotePort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wt.DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1),  # variable-length
    ]


# --- UDP Structures ---
class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wt.DWORD),
        ("dwLocalPort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    ]


class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wt.DWORD),
        ("table", MIB_UDPROW_OWNER_PID * 1),
    ]


iphlpapi = ctypes.windll.iphlpapi

iphlpapi.GetExtendedTcpTable.restype = wt.DWORD
iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL,
    wt.ULONG, ctypes.c_int, wt.DWORD
]

iphlpapi.GetExtendedUdpTable.restype = wt.DWORD
iphlpapi.GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL,
    wt.ULONG, ctypes.c_int, wt.DWORD
]


def _dword_to_ip(dword):
    """Convert a DWORD in network byte order to a dotted IP string."""
    return socket.inet_ntoa(struct.pack("<I", dword))


def _port_from_dword(dword):
    """Convert a port stored as DWORD (network byte order) to host order."""
    return socket.ntohs(dword & 0xFFFF)


def get_tcp_connections(pid):
    """Get all TCP connections owned by the given PID."""
    connections = []
    size = wt.DWORD(0)

    # First call to get required buffer size
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False,
                                  AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

    buf = (ctypes.c_byte * size.value)()
    ret = iphlpapi.GetExtendedTcpTable(ctypes.byref(buf), ctypes.byref(size),
                                        False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if ret != 0:
        get_logger().warning(f"GetExtendedTcpTable failed with error {ret}")
        return connections

    table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
    num_entries = table.dwNumEntries

    # Access the variable-length array properly
    row_array_type = MIB_TCPROW_OWNER_PID * num_entries
    row_offset = ctypes.sizeof(wt.DWORD)  # skip dwNumEntries
    rows = ctypes.cast(ctypes.byref(buf, row_offset),
                       ctypes.POINTER(row_array_type)).contents

    for i in range(num_entries):
        row = rows[i]
        if row.dwOwningPid == pid:
            state = row.dwState
            # Only include established or active connections
            if state in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
                connections.append(Connection(
                    protocol="TCP",
                    local_ip=_dword_to_ip(row.dwLocalAddr),
                    local_port=_port_from_dword(row.dwLocalPort),
                    remote_ip=_dword_to_ip(row.dwRemoteAddr),
                    remote_port=_port_from_dword(row.dwRemotePort),
                ))

    return connections


def get_udp_connections(pid):
    """Get all UDP endpoints owned by the given PID."""
    connections = []
    size = wt.DWORD(0)

    iphlpapi.GetExtendedUdpTable(None, ctypes.byref(size), False,
                                  AF_INET, UDP_TABLE_OWNER_PID, 0)

    buf = (ctypes.c_byte * size.value)()
    ret = iphlpapi.GetExtendedUdpTable(ctypes.byref(buf), ctypes.byref(size),
                                        False, AF_INET, UDP_TABLE_OWNER_PID, 0)
    if ret != 0:
        get_logger().warning(f"GetExtendedUdpTable failed with error {ret}")
        return connections

    table = ctypes.cast(buf, ctypes.POINTER(MIB_UDPTABLE_OWNER_PID)).contents
    num_entries = table.dwNumEntries

    row_array_type = MIB_UDPROW_OWNER_PID * num_entries
    row_offset = ctypes.sizeof(wt.DWORD)
    rows = ctypes.cast(ctypes.byref(buf, row_offset),
                       ctypes.POINTER(row_array_type)).contents

    for i in range(num_entries):
        row = rows[i]
        if row.dwOwningPid == pid:
            connections.append(Connection(
                protocol="UDP",
                local_ip=_dword_to_ip(row.dwLocalAddr),
                local_port=_port_from_dword(row.dwLocalPort),
                remote_ip="*",       # UDP is connectionless
                remote_port=0,
            ))

    return connections


def get_all_connections(pid):
    """Get all TCP + UDP connections for the given PID."""
    return get_tcp_connections(pid) + get_udp_connections(pid)


class ConnectionMonitor:
    """
    Background thread that periodically refreshes the list of game connections.

    Thread-safe: use get_connections() to read the current snapshot.
    """

    def __init__(self, pid, refresh_interval=5.0, exclude_ports=None):
        self._pid = pid
        self._interval = refresh_interval
        self._exclude_ports = set(exclude_ports or [])
        self._connections = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._local_endpoints = set()   # (ip, port) tuples for fast matching
        self._remote_endpoints = set()
        self._local_ports = set()       # port-only set for 0.0.0.0 wildcard matches

    def start(self):
        """Start the background refresh thread."""
        self._refresh()  # initial fetch
        self._thread = threading.Thread(target=self._run, daemon=True,
                                         name="ConnectionMonitor")
        self._thread.start()
        get_logger().info("Connection monitor started")

    def stop(self):
        """Signal the background thread to stop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self._interval + 1)

    def _run(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(self._interval)
            if not self._stop_event.is_set():
                self._refresh()

    def _refresh(self):
        log = get_logger()
        try:
            conns = get_all_connections(self._pid)
            # Apply port exclusions
            conns = [c for c in conns
                     if c.local_port not in self._exclude_ports
                     and c.remote_port not in self._exclude_ports]

            local_eps = set()
            remote_eps = set()
            local_ports = set()
            for c in conns:
                local_eps.add((c.local_ip, c.local_port))
                # Track port-only for wildcard (0.0.0.0) bindings
                if c.local_ip == "0.0.0.0":
                    local_ports.add(c.local_port)
                if c.remote_ip != "*":
                    remote_eps.add((c.remote_ip, c.remote_port))

            with self._lock:
                old = set(self._connections)
                new = set(conns)
                self._connections = conns
                self._local_endpoints = local_eps
                self._remote_endpoints = remote_eps
                self._local_ports = local_ports

            # Log changes
            added = new - old
            removed = old - new
            for c in added:
                log.info(f"[+] New connection: {c.protocol} "
                         f"{c.local_ip}:{c.local_port} -> "
                         f"{c.remote_ip}:{c.remote_port}")
            for c in removed:
                log.info(f"[-] Connection closed: {c.protocol} "
                         f"{c.local_ip}:{c.local_port} -> "
                         f"{c.remote_ip}:{c.remote_port}")

        except Exception as e:
            log.error(f"Connection refresh failed: {e}")

    def get_connections(self):
        """Return a snapshot of current connections."""
        with self._lock:
            return list(self._connections)

    def matches_game_traffic(self, src_ip, src_port, dst_ip, dst_port):
        """
        Check if a packet (identified by endpoints) belongs to the game process.

        Handles wildcard bindings (0.0.0.0) by matching on port alone when
        the socket is bound to all interfaces.
        """
        with self._lock:
            # Exact (ip, port) matches
            if (src_ip, src_port) in self._local_endpoints:
                return True
            if (dst_ip, dst_port) in self._local_endpoints:
                return True
            # Wildcard port matches — 0.0.0.0 means any local IP
            if src_port in self._local_ports:
                return True
            if dst_port in self._local_ports:
                return True
            # Remote endpoint matches
            if (src_ip, src_port) in self._remote_endpoints:
                return True
            if (dst_ip, dst_port) in self._remote_endpoints:
                return True
        return False

    def get_direction(self, src_ip, src_port, dst_ip, dst_port):
        """Determine packet direction: 'IN' if coming to us, 'OUT' if going out."""
        with self._lock:
            if (src_ip, src_port) in self._local_endpoints:
                return "OUT"
            if src_port in self._local_ports:
                return "OUT"
            if (dst_ip, dst_port) in self._local_endpoints:
                return "IN"
            if dst_port in self._local_ports:
                return "IN"
        return "UNK"
