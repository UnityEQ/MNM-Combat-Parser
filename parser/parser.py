"""
ZekParser — Standalone live combat log viewer.

Self-contained GUI that captures network traffic from mnm.exe, decrypts it,
parses game messages, and displays combat events in real-time.

No dependencies on core/ modules. Requires: pycryptodome, tkinter (stdlib).
Must run as Administrator (raw socket capture).

Usage:
    python parser/parser.py
"""

APP_VERSION = "V1.12"

import csv
import ctypes
import json
import re
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import io
import logging
import os
import queue
import socket
import struct
import sys
import threading
import time
import tkinter as tk
import winsound
from tkinter import filedialog, ttk
from collections import defaultdict
from datetime import datetime
from logging.handlers import RotatingFileHandler

try:
    from Crypto.Cipher import AES
except ImportError:
    import subprocess
    print("pycryptodome not found — installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Cipher import AES


# ===================================================================
# Debug logging — enabled for dev, disabled in frozen exe builds
# ===================================================================

def _setup_parser_log():
    logger = logging.getLogger("parser_debug")
    logger.handlers.clear()
    if getattr(sys, 'frozen', False):
        # --- Frozen exe: no debug logging ---
        logger.addHandler(logging.NullHandler())
        logger.setLevel(logging.CRITICAL)
    else:
        # --- Dev mode: full file logging for damage attribution debugging ---
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, f"parser_{ts}.log")
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=3,
                                 encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-5s] %(message)s",
                                           datefmt="%H:%M:%S"))
        logger.addHandler(fh)
        logger.setLevel(logging.DEBUG)
    return logger

_plog = _setup_parser_log()


# ===================================================================
# Windows API — Process finder
# ===================================================================

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MAX_PATH = 260
MAX_MODULE_NAME32 = 255
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD), ("hModule", wt.HMODULE),
        ("szModule", ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", ctypes.c_char * MAX_PATH),
    ]


# TCP/UDP table structures for connection monitoring
class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD),
        ("dwLocalPort", wt.DWORD), ("dwRemoteAddr", wt.DWORD),
        ("dwRemotePort", wt.DWORD), ("dwOwningPid", wt.DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwNumEntries", wt.DWORD), ("table", MIB_TCPROW_OWNER_PID * 1)]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    ]


class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwNumEntries", wt.DWORD), ("table", MIB_UDPROW_OWNER_PID * 1)]


kernel32 = ctypes.windll.kernel32
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Process32First.restype = wt.BOOL
kernel32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype = wt.BOOL
kernel32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Module32First.restype = wt.BOOL
kernel32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
kernel32.Module32Next.restype = wt.BOOL
kernel32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]

iphlpapi = ctypes.windll.iphlpapi
iphlpapi.GetExtendedTcpTable.restype = wt.DWORD
iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL,
    wt.ULONG, ctypes.c_int, wt.DWORD,
]
iphlpapi.GetExtendedUdpTable.restype = wt.DWORD
iphlpapi.GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL,
    wt.ULONG, ctypes.c_int, wt.DWORD,
]


def find_game_pid(process_name="mnm.exe"):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return None
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if not kernel32.Process32First(snap, ctypes.byref(entry)):
            return None
        while True:
            exe = entry.szExeFile.decode("utf-8", errors="replace").lower()
            if exe == process_name.lower():
                return entry.th32ProcessID
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return None


def is_process_alive(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return False
    kernel32.CloseHandle(h)
    return True


# ===================================================================
# Windows API — Connection monitoring (iphlpapi)
# ===================================================================

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1


def _dword_to_ip(dword):
    return socket.inet_ntoa(struct.pack("<I", dword))


def _port_from_dword(dword):
    return socket.ntohs(dword & 0xFFFF)


def get_game_connections(pid):
    """Get all TCP+UDP connections for a PID. Returns sets of endpoints."""
    local_eps = set()
    remote_eps = set()
    local_ports = set()  # for 0.0.0.0 wildcard

    # TCP
    size = wt.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if size.value > 0:
        buf = (ctypes.c_byte * size.value)()
        if iphlpapi.GetExtendedTcpTable(ctypes.byref(buf), ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
            table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
            rows = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(wt.DWORD)),
                               ctypes.POINTER(MIB_TCPROW_OWNER_PID * table.dwNumEntries)).contents
            for i in range(table.dwNumEntries):
                r = rows[i]
                if r.dwOwningPid == pid and r.dwState in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
                    lip = _dword_to_ip(r.dwLocalAddr)
                    lport = _port_from_dword(r.dwLocalPort)
                    rip = _dword_to_ip(r.dwRemoteAddr)
                    rport = _port_from_dword(r.dwRemotePort)
                    local_eps.add((lip, lport))
                    remote_eps.add((rip, rport))
                    if lip == "0.0.0.0":
                        local_ports.add(lport)

    # UDP
    size = wt.DWORD(0)
    iphlpapi.GetExtendedUdpTable(None, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
    if size.value > 0:
        buf = (ctypes.c_byte * size.value)()
        if iphlpapi.GetExtendedUdpTable(ctypes.byref(buf), ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0) == 0:
            table = ctypes.cast(buf, ctypes.POINTER(MIB_UDPTABLE_OWNER_PID)).contents
            rows = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(wt.DWORD)),
                               ctypes.POINTER(MIB_UDPROW_OWNER_PID * table.dwNumEntries)).contents
            for i in range(table.dwNumEntries):
                r = rows[i]
                if r.dwOwningPid == pid:
                    lip = _dword_to_ip(r.dwLocalAddr)
                    lport = _port_from_dword(r.dwLocalPort)
                    local_eps.add((lip, lport))
                    if lip == "0.0.0.0":
                        local_ports.add(lport)

    return local_eps, remote_eps, local_ports


# ===================================================================
# IL2CPP Memory reader — encryption key extraction
# ===================================================================

_DEFAULT_TYPEINFO_RVA = 0x5466F20
IL2CPP_STATIC_FIELDS_OFFSET = 0xB8
FIELD_AES_KEY = 0x40
FIELD_HMAC_KEY = 0x38
FIELD_XOR_KEY = 0x48
ARRAY_LENGTH_OFFSET = 0x18
ARRAY_DATA_OFFSET = 0x20


def _rva_config_path():
    """Return path to rva_cache.json next to the exe or .py file."""
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), "rva_cache.json")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "rva_cache.json")


def _load_rva():
    """Load cached RVA from config file, falling back to hardcoded default."""
    try:
        with open(_rva_config_path(), "r") as f:
            data = json.loads(f.read())
            rva = data.get("typeinfo_rva")
            if isinstance(rva, int) and rva > 0:
                return rva
    except Exception:
        pass
    return _DEFAULT_TYPEINFO_RVA


def _save_rva(rva):
    """Save discovered RVA to config file for fast load next time."""
    try:
        with open(_rva_config_path(), "w") as f:
            f.write(json.dumps({"typeinfo_rva": rva}))
        _plog.info(f"KEYS saved RVA 0x{rva:X} to {_rva_config_path()}")
    except Exception as e:
        _plog.info(f"KEYS failed to save RVA: {e}")


def _read_mem(handle, address, size):
    buf = ctypes.create_string_buffer(size)
    n_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(n_read))
    if not ok or n_read.value != size:
        return None
    return buf.raw


def _read_ptr(handle, address):
    raw = _read_mem(handle, address, 8)
    return struct.unpack("<Q", raw)[0] if raw else None


def _read_byte_array(handle, ptr):
    if not ptr:
        return None
    header = _read_mem(handle, ptr, 0x24)
    if not header:
        return None
    length = struct.unpack_from("<i", header, ARRAY_LENGTH_OFFSET)[0]
    if length <= 0 or length > 1024:
        return None
    return _read_mem(handle, ptr + ARRAY_DATA_OFFSET, length)


def find_module_base(pid, module_name="GameAssembly.dll"):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE:
        return None, 0
    try:
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)
        if not kernel32.Module32First(snap, ctypes.byref(entry)):
            return None, 0
        while True:
            name = entry.szModule.decode("utf-8", errors="replace").lower()
            if name == module_name.lower():
                base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
                return base, entry.modBaseSize
            if not kernel32.Module32Next(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return None, 0


_cached_class_ptr = None
_scan_attempted = False


def _validate_class_ptr(handle, class_ptr):
    """Check if a pointer looks like a valid Client.ConnectionInfo Il2CppClass."""
    try:
        name_ptr = _read_ptr(handle, class_ptr + 0x10)
        if not name_ptr:
            return False
        name_raw = _read_mem(handle, name_ptr, 32)
        if not name_raw:
            return False
        class_name = name_raw.split(b'\x00', 1)[0].decode("utf-8", errors="replace")
        if class_name != "ConnectionInfo":
            return False
        # Also check namespace = "Client"
        ns_ptr = _read_ptr(handle, class_ptr + 0x18)
        if ns_ptr:
            ns_raw = _read_mem(handle, ns_ptr, 32)
            if ns_raw:
                namespace = ns_raw.split(b'\x00', 1)[0].decode("utf-8", errors="replace")
                if namespace == "Client":
                    if _plog.isEnabledFor(logging.DEBUG):
                        _plog.debug(f"KEYS validated Client.ConnectionInfo at 0x{class_ptr:X}")
                    return True
                return False
        return True  # No namespace readable, but name matched
    except Exception:
        return False


def _scan_for_class(handle, base, mod_size):
    """Scan GameAssembly.dll data section for Il2CppClass* pointing to ConnectionInfo.

    The class name string lives in IL2CPP metadata (separate memory region, not in
    the DLL module), so we can't search for the string directly. Instead, we scan
    the data section for 8-byte aligned heap pointers and validate each one by
    reading Il2CppClass.name and checking it says "ConnectionInfo" in namespace "Client".
    """
    chunk_size = 65536  # 64KB chunks

    # Scan latter half of module (data section) for Il2CppClass* pointers
    search_start = mod_size // 2
    candidates_checked = 0
    chunks_read = 0

    for offset in range(search_start, mod_size, chunk_size):
        read_size = min(chunk_size, mod_size - offset)
        if read_size < 8:
            break
        try:
            chunk = _read_mem(handle, base + offset, read_size)
        except Exception:
            continue
        if not chunk:
            continue
        chunks_read += 1
        for i in range(0, read_size - 7, 8):
            ptr_val = struct.unpack_from("<Q", chunk, i)[0]
            # Quick filter: valid 64-bit user-space pointer
            if ptr_val < 0x10000 or ptr_val > 0x7FFFFFFFFFFF:
                continue
            # Skip module-internal pointers (Il2CppClass is on the heap)
            if base <= ptr_val < base + mod_size:
                continue
            candidates_checked += 1
            if candidates_checked > 2000000:
                _plog.info(f"KEYS_SCAN limit reached after {chunks_read} chunks, "
                           f"{candidates_checked} candidates")
                return None, None
            if _validate_class_ptr(handle, ptr_val):
                rva = offset + i
                _plog.info(f"KEYS_SCAN found ConnectionInfo at module+0x{rva:X} "
                           f"(checked {candidates_checked} candidates)")
                return ptr_val, rva

    _plog.info(f"KEYS_SCAN complete: {chunks_read} chunks, "
               f"{candidates_checked} candidates, no match")
    return None, None


def read_encryption_keys(pid):
    """Read AES/HMAC/XOR keys from game memory. Returns dict or None."""
    global _cached_class_ptr
    base, mod_size = find_module_base(pid)
    if not base:
        return None

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None

    try:
        global _cached_class_ptr, _scan_attempted
        class_ptr = _cached_class_ptr

        # Method 1: Use in-memory cached class pointer
        if class_ptr and _validate_class_ptr(handle, class_ptr):
            pass  # still valid
        else:
            class_ptr = None

        # Method 2: Use RVA from config file (or hardcoded default)
        if not class_ptr:
            rva = _load_rva()
            if rva < mod_size:
                ptr = _read_ptr(handle, base + rva)
                if ptr and _validate_class_ptr(handle, ptr):
                    class_ptr = ptr
                    _cached_class_ptr = ptr

        # Method 3: Scan module for ConnectionInfo class (handles game patches)
        if not class_ptr and not _scan_attempted:
            _scan_attempted = True
            _plog.info("KEYS module base=0x%X size=%.1fMB", base, mod_size / 1048576)
            _plog.info("KEYS RVA failed — scanning for ConnectionInfo class...")
            ptr, new_rva = _scan_for_class(handle, base, mod_size)
            if ptr:
                class_ptr = ptr
                _cached_class_ptr = ptr
                if new_rva:
                    _save_rva(new_rva)

        if not class_ptr:
            return None

        static_fields = _read_ptr(handle, class_ptr + IL2CPP_STATIC_FIELDS_OFFSET)
        if not static_fields:
            return None

        aes_ptr = _read_ptr(handle, static_fields + FIELD_AES_KEY)
        hmac_ptr = _read_ptr(handle, static_fields + FIELD_HMAC_KEY)
        xor_ptr = _read_ptr(handle, static_fields + FIELD_XOR_KEY)

        return {
            "aes_key": _read_byte_array(handle, aes_ptr),
            "hmac_key": _read_byte_array(handle, hmac_ptr),
            "xor_key": _read_byte_array(handle, xor_ptr),
        }
    finally:
        kernel32.CloseHandle(handle)


# ===================================================================
# Decryption pipeline — CRC32c + AES-256-CBC + PKCS7
# ===================================================================

_CRC32C_TABLE = None


def _init_crc32c_table():
    global _CRC32C_TABLE
    if _CRC32C_TABLE is not None:
        return
    poly = 0x82F63B78
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        table.append(crc)
    _CRC32C_TABLE = table


def crc32c(data):
    _init_crc32c_table()
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def pkcs7_unpad(data):
    if not data:
        return None
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or len(data) < pad_len:
        return None
    if any(data[-(i + 1)] != pad_len for i in range(pad_len)):
        return None
    return data[:-pad_len]


def decrypt_packet(raw_payload, aes_key, hmac_key=None, xor_key=None):
    """Full decryption: strip CRC -> strip HMAC -> AES-CBC -> PKCS7 -> XOR."""
    if len(raw_payload) < 36:
        return None

    # 1. CRC32c — strip and verify last 4 bytes
    data = raw_payload[:-4]
    expected_crc = struct.unpack_from("<I", raw_payload, len(raw_payload) - 4)[0]
    if expected_crc != crc32c(data):
        return None

    # 2. HMAC (if key present)
    if hmac_key and len(hmac_key) > 0:
        if len(data) < 33:
            return None
        msg = data[:-32]
        tag = data[-32:]
        expected_hmac = hmac_mod.new(hmac_key, msg, hashlib.sha256).digest()
        if not hmac_mod.compare_digest(tag, expected_hmac):
            return None
        data = msg

    # 3. AES-256-CBC
    if len(data) < 32 or len(data) % 16 != 0:
        return None
    iv = data[:16]
    ct = data[16:]
    raw = AES.new(aes_key, AES.MODE_CBC, iv=iv).decrypt(ct)
    plaintext = pkcs7_unpad(raw)
    if plaintext is None:
        return None

    # 4. XOR (if key present)
    if xor_key and len(xor_key) > 0:
        key_len = len(xor_key)
        plaintext = bytes(plaintext[i] ^ xor_key[i % key_len] for i in range(len(plaintext)))

    return plaintext


# ===================================================================
# Packet parsing — IP / UDP / TCP headers
# ===================================================================

def parse_ip_header(data):
    if len(data) < 20:
        return None
    if (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    protocol = data[9]
    src_ip = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
    dst_ip = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
    return protocol, src_ip, dst_ip, ihl


def parse_udp_header(data):
    if len(data) < 8:
        return None
    src_port, dst_port, length = struct.unpack("!HHH", data[0:6])
    payload = data[8:length] if length > 8 else b""
    return src_port, dst_port, payload


def parse_tcp_header(data):
    if len(data) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", data[0:4])
    data_offset = (data[12] >> 4) * 4
    if data_offset < 20 or len(data) < data_offset:
        return None
    return src_port, dst_port, data[data_offset:]


# ===================================================================
# LiteNetLib frame parser
# ===================================================================

PACKET_PROPERTIES = {
    0: "Unreliable", 1: "Channeled", 2: "Ack", 3: "Ping", 4: "Pong",
    5: "ConnectRequest", 6: "ConnectAccept", 7: "Disconnect",
    8: "UnconnectedMessage", 9: "MtuCheck", 10: "MtuOk", 11: "Broadcast",
    12: "Merged", 13: "ShutdownOk", 14: "PeerNotFound",
    15: "InvalidProtocol", 16: "NatMessage", 17: "Empty",
}

CONTROL_TYPES = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17}


def parse_lnl_frame(payload):
    """Parse LiteNetLib frame. Returns list of inner data payloads."""
    if not payload:
        return []
    prop = payload[0] & 0x1F
    is_frag = bool(payload[0] & 0x80)

    if prop in CONTROL_TYPES:
        return []

    if prop == 0:  # Unreliable
        hdr = 7 if is_frag and len(payload) >= 7 else 1
        return [payload[hdr:]] if len(payload) > hdr else []

    if prop == 1:  # Channeled
        if len(payload) < 4:
            return []
        hdr = 10 if is_frag and len(payload) >= 10 else 4
        return [payload[hdr:]] if len(payload) > hdr else []

    if prop == 12:  # Merged — contains nested LNL frames
        messages = []
        offset = 1
        while offset + 2 <= len(payload):
            msg_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            if msg_len == 0 or offset + msg_len > len(payload):
                break
            # Each sub-message is a nested LNL frame
            sub_payloads = parse_lnl_frame(payload[offset:offset + msg_len])
            messages.extend(sub_payloads)
            offset += msg_len
        return messages

    # Unknown type — pass through
    return [payload[1:]] if len(payload) > 1 else []


# ===================================================================
# Game message opcodes
# ===================================================================

MESSAGE_IDS = {
    0x0011: "ChangeTarget", 0x0012: "Autoattack", 0x0013: "Die",
    0x0014: "Consider", 0x0020: "SpawnEntity", 0x0021: "DespawnEntity",
    0x0022: "UpdateHealth", 0x0023: "UpdateMana", 0x0024: "UpdateExperience",
    0x0025: "UpdateLevel",
    0x0027: "UpdateHealthMana",
    0x0029: "UpdateStunState", 0x002A: "UpdateHostileState",
    0x002F: "UpdateState",
    0x0050: "CastAbility", 0x0053: "AddBuffIcon", 0x0054: "RemoveBuffIcon",
    0x0055: "BeginCasting", 0x0056: "EndCasting", 0x005C: "ParticleHit",
    0x005D: "CancelBuff", 0x005F: "UpdateClassHID", 0x0146: "ChannelAbility",
    0x0380: "ClientPartyUpdate",
    0x022F: "UpdateEndurance",
    # Loot/inventory
    0x0060: "InventoryItemPickup", 0x0063: "AddItemToInventory",
    0x0064: "RemoveItemFromCorpse", 0x0065: "LootItemFromCorpse",
    0x0066: "DropItem", 0x0067: "RemoveItemFromInventory",
    0x0068: "HandInItems", 0x0069: "HandInItemsResponse",
    0x006A: "DestroyItem", 0x006D: "MoveItemWithinInventory",
    0x006E: "InventoryItemPlace", 0x007D: "CoinDrop",
    0x007F: "ItemInformationRequest", 0x0080: "ItemInformation",
    0x0083: "UpdateEquipment",
    0x0110: "ItemUse", 0x0111: "ItemAutoEquip", 0x0112: "ItemIsActive",
    0x0260: "UpdateItemQuantityAndChargesInInventory",
    0x0320: "ItemUpdateContents",
}

COMBAT_MSG_IDS = {
    0x0011, 0x0012, 0x0013, 0x0014, 0x0020, 0x0021, 0x0022, 0x0023,
    0x0024, 0x0025, 0x0027, 0x0029, 0x002A, 0x002F, 0x0040, 0x0050, 0x0053, 0x0054,
    0x0055, 0x0056, 0x005C, 0x005D, 0x005F, 0x0146, 0x0380, 0x022F,
}

LOOT_MSG_IDS = {0x0063, 0x0065, 0x0080}

# All item-related opcodes — for discovery logging to find the real loot flow
ITEM_MSG_IDS = {
    0x0060, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069,
    0x006A, 0x006D, 0x006E, 0x007D, 0x007F, 0x0080, 0x0083,
    0x0110, 0x0111, 0x0112, 0x0260, 0x0320,
}

# Known melee attack verbs (base form).  Used to whitelist patterns 3-6
# and ChatCombat so non-combat verbs like "pulls", "binds", "summons"
# don't false-positive into the melee parser and corrupt entity names.
_MELEE_VERBS = (
    r"(?:slash|kick|punch|crush|bash|pierce|strike|bite|claw|stab|maul|"
    r"slam|smash|hack|rend|cleave|hit|swing|chop|thrust|gore|scratch|"
    r"swipe|pummel|bludgeon|whack|jab|rake|rip|tear|gnaw|chomp|"
    r"headbutt|backstab|gouge|mangle|thrash|lacerate|smite|cut|"
    r"slice|clobber|whip|lash|batter|flail)"
)


def get_message_name(msg_id):
    return MESSAGE_IDS.get(msg_id, f"Unknown_0x{msg_id:04X}")


# ===================================================================
# Game message extraction from decrypted plaintext
# ===================================================================

def extract_game_messages(plaintext):
    """Decrypt plaintext -> LNL frames -> game messages as (msg_id, body) tuples."""
    inner_payloads = parse_lnl_frame(plaintext)
    messages = []
    for data in inner_payloads:
        if len(data) >= 2:
            msg_id = struct.unpack_from("<H", data, 0)[0]
            messages.append((msg_id, data[2:]))
    return messages


# ===================================================================
# Combat event parsing — binary message body readers
# ===================================================================

def _r_u32(data, off):
    if off + 4 > len(data): return None, off
    return struct.unpack_from("<I", data, off)[0], off + 4

def _r_i32(data, off):
    if off + 4 > len(data): return None, off
    return struct.unpack_from("<i", data, off)[0], off + 4

def _r_u16(data, off):
    if off + 2 > len(data): return None, off
    return struct.unpack_from("<H", data, off)[0], off + 2

def _r_u8(data, off):
    if off + 1 > len(data): return None, off
    return data[off], off + 1

def _r_bool(data, off):
    if off + 1 > len(data): return None, off
    return bool(data[off]), off + 1

def _r_float(data, off):
    if off + 4 > len(data): return None, off
    return struct.unpack_from("<f", data, off)[0], off + 4

def _strip_msg_type_byte(text):
    """Strip the trailing message-type byte the game appends after the period.
    The game embeds a single byte (e.g. &, >, A, N, E, +, D, @, ', 0, etc.)
    right after the sentence-ending period.  Instead of maintaining a fragile
    allowlist, just strip ANY character that follows a period at the end."""
    if not text:
        return text
    text = text.rstrip('\x00 ')
    if len(text) >= 2 and text[-2] == '.' and text[-1] != '.':
        text = text[:-1]
    return text

def _r_str(data, off):
    if off + 2 > len(data): return None, off
    slen = struct.unpack_from("<H", data, off)[0]
    off += 2
    if slen == 0: return "", off
    if off + slen > len(data): return None, off - 2
    raw = data[off:off + slen]
    # Strip trailing null and control bytes (0x00-0x1F) then decode;
    # some wire strings terminate with 0x04 (EOT) instead of 0x00.
    stripped = raw
    while stripped and stripped[-1:] < b'\x20':
        stripped = stripped[:-1]
    s = stripped.decode("utf-8", errors="replace").rstrip()
    return s, off + slen

def _r_str_nn(data, off):
    """Read a LNL-style string where length includes +1 for null but null is NOT on wire."""
    if off + 2 > len(data): return None, off
    slen = struct.unpack_from("<H", data, off)[0]
    off += 2
    if slen == 0: return "", off
    actual = slen - 1  # length counts implicit null, subtract it
    if actual <= 0: return "", off
    if off + actual > len(data): return None, off - 2
    raw = data[off:off + actual]
    s = raw.decode("utf-8", errors="replace").rstrip()
    return s, off + actual


def parse_combat_event(msg_id, body, direction):
    """Parse a combat message body into a dict for display. Returns dict or None."""
    event = {"msg_id": msg_id, "msg_name": get_message_name(msg_id), "direction": direction}
    off = 0

    if msg_id == 0x0022:  # UpdateHealth
        event["type"] = "UpdateHealth"
        event["entity_id"], off = _r_u32(body, off)
        event["hp"], off = _r_i32(body, off)
        event["max_hp"], off = _r_i32(body, off)

    elif msg_id == 0x0027:  # UpdateHealthMana
        event["type"] = "UpdateHealthMana"
        event["entity_id"], off = _r_u32(body, off)
        event["hp"], off = _r_i32(body, off)
        event["max_hp"], off = _r_i32(body, off)
        event["mp"], off = _r_i32(body, off)
        event["max_mp"], off = _r_i32(body, off)

    elif msg_id == 0x0023:  # UpdateMana
        event["type"] = "UpdateMana"
        event["entity_id"], off = _r_u32(body, off)
        event["mp"], off = _r_i32(body, off)
        event["max_mp"], off = _r_i32(body, off)

    elif msg_id == 0x022F:  # UpdateEndurance
        event["type"] = "UpdateEndurance"
        event["entity_id"], off = _r_u32(body, off)
        event["endurance"], off = _r_i32(body, off)
        event["max_endurance"], off = _r_i32(body, off)

    elif msg_id == 0x0013:  # Die
        event["type"] = "Die"
        event["entity_id"], off = _r_u32(body, off)
        event["state"], off = _r_bool(body, off)
        event["killer_id"], off = _r_u32(body, off)
        event["feign"], off = _r_bool(body, off)

    elif msg_id == 0x0055:  # BeginCasting
        event["type"] = "BeginCasting"
        event["entity_id"], off = _r_u32(body, off)
        event["target_id"], off = _r_u32(body, off)
        event["ability_name"], off = _r_str(body, off)
        event["no_interrupt"], off = _r_bool(body, off)
        event["cast_time"], off = _r_u32(body, off)

    elif msg_id == 0x0040:  # ChatMessage (carries melee auto-attack combat text)
        channel, off = _r_u32(body, off)
        if channel == 1:  # combat text channel
            event["type"] = "ChatCombat"
            event["text"], off = _r_str(body, off)
        else:
            event["type"] = "ChatMessage"
            event["channel"] = channel
            try:
                event["text"], off = _r_str(body, off)
            except Exception:
                return None

    elif msg_id == 0x0056:  # EndCasting
        event["type"] = "EndCasting"
        event["entity_id"], off = _r_u32(body, off)
        event["target_id"], off = _r_u32(body, off)
        event["text"], off = _r_str(body, off)

    elif msg_id == 0x0050:  # CastAbility
        event["type"] = "CastAbility"
        event["gem_id"], off = _r_u16(body, off)
        event["target_id"], off = _r_u32(body, off)

    elif msg_id == 0x0053:  # AddBuffIcon
        event["type"] = "AddBuffIcon"
        event["entity_id"], off = _r_u32(body, off)
        event["buff_id"], off = _r_u32(body, off)
        event["buff_name"], off = _r_str(body, off)

    elif msg_id == 0x0054:  # RemoveBuffIcon
        event["type"] = "RemoveBuffIcon"
        event["entity_id"], off = _r_u32(body, off)
        event["entity_buff_id"], off = _r_u32(body, off)

    elif msg_id == 0x0020:  # SpawnEntity
        event["type"] = "SpawnEntity"
        event["entity_id"], off = _r_u32(body, off)
        event["entity_type"], off = _r_u16(body, off)
        event["name"], off = _r_str(body, off)
        name_end = off

        # Phase 2: HID strings + skinTone + level
        # Try sequential parsing first; fall back to scan if it fails
        hid_ok = False
        try:
            class_hid, hoff = _r_str(body, off)
            race_hid, hoff = _r_str(body, hoff)
            sex_hid, hoff = _r_str(body, hoff)
            skin_tone, hoff = _r_u16(body, hoff)
            level, hoff = _r_i32(body, hoff)
            if class_hid is not None and level is not None:
                # Sanity check: level should be reasonable, class_hid should be short
                if 0 <= level <= 200 and class_hid and len(class_hid) <= 10:
                    event["class_hid"] = class_hid
                    event["level"] = level
                    off = hoff
                    hid_ok = True
        except Exception:
            pass

        # Read stats: HP, max HP, MP, max MP
        if hid_ok:
            # Sequential parsing succeeded — stats are right at 'off'
            if off + 8 <= len(body):
                event["hp"], _ = _r_i32(body, off)
                event["max_hp"], _ = _r_i32(body, off + 4)
        else:
            # HID parsing failed — scan for stats block
            stats_off = _find_stats(body, name_end)
            if stats_off is not None:
                event["hp"], _ = _r_i32(body, stats_off)
                event["max_hp"], _ = _r_i32(body, stats_off + 4)
                # Fallback: extract class_hid via ASCII scanning of HID region
                hid_region = body[name_end:stats_off]
                class_hid = _scan_class_hid(hid_region)
                if class_hid:
                    event["class_hid"] = class_hid
                # Try level as i32 right before stats block
                if stats_off >= name_end + 4:
                    lvl, _ = _r_i32(body, stats_off - 4)
                    if lvl is not None and 0 <= lvl <= 200:
                        event["level"] = lvl

        # Scan for position (tick + flags + xyz)
        pos = _find_position(body, name_end)
        if pos:
            event["pos_x"], event["pos_y"], event["pos_z"] = pos
        # Scan for hostility flag
        event["is_hostile"] = _find_hostile(body, name_end)

        # Pet detection: last u16 == 5 means pet, parentID at body[len-93]
        if len(body) >= 95:
            tail_marker, _ = _r_u16(body, len(body) - 2)
            if tail_marker == 5:
                event["pet_state"] = True
                parent_id, _ = _r_u32(body, len(body) - 93)
                if parent_id and 0 < parent_id < 100000:
                    event["parent_id"] = parent_id
                else:
                    # body[len-93] gave garbage — pass body so handler can
                    # scan for known player eids at any offset
                    event["_pet_body"] = bytes(body)
                    if _plog.isEnabledFor(logging.DEBUG):
                        _plog.debug(f"PET_BAD_PARENT eid={event.get('entity_id')} "
                                    f"raw_parent=0x{parent_id:08X} bodylen={len(body)}")

    elif msg_id == 0x0021:  # DespawnEntity
        event["type"] = "DespawnEntity"
        event["entity_id"], off = _r_u32(body, off)

    elif msg_id == 0x0011:  # ChangeTarget
        event["type"] = "ChangeTarget"
        event["target_id"], off = _r_u32(body, off)

    elif msg_id == 0x0014:  # Consider
        event["type"] = "Consider"
        event["target_id"], off = _r_u32(body, off)

    elif msg_id == 0x0012:  # Autoattack
        event["type"] = "Autoattack"
        event["active"], off = _r_bool(body, off)

    elif msg_id == 0x0029:  # UpdateStunState
        event["type"] = "UpdateStunState"
        event["entity_id"], off = _r_u32(body, off)
        event["stunned"], off = _r_bool(body, off)

    elif msg_id == 0x002A:  # UpdateHostileState
        event["type"] = "UpdateHostileState"
        event["entity_id"], off = _r_u32(body, off)
        event["hostile"], off = _r_bool(body, off)

    elif msg_id == 0x002F:  # UpdateState — big packet with player class/level
        event["type"] = "UpdateState"
        try:
            event["entity_id"], off = _r_u32(body, off)       # uint id
            event["entity_state"], off = _r_bool(body, off)    # bool entityState
            event["current_state"], off = _r_bool(body, off)   # bool currentState
            event["visibility_state"], off = _r_bool(body, off)# bool visibilityState
            event["pet_state"], off = _r_bool(body, off)       # bool petState
            event["hp"], off = _r_i32(body, off)               # int health
            event["max_hp"], off = _r_i32(body, off)           # int maxHealth
            event["mana"], off = _r_i32(body, off)             # int mana
            event["max_mana"], off = _r_i32(body, off)         # int maxMana
            event["parent_id"], off = _r_u32(body, off)        # uint parentID
            # Vector3 position (3 floats = 12 bytes)
            _, off = _r_float(body, off)
            _, off = _r_float(body, off)
            _, off = _r_float(body, off)
            # Vector3 velocity (3 floats = 12 bytes)
            _, off = _r_float(body, off)
            _, off = _r_float(body, off)
            _, off = _r_float(body, off)
            event["facing"], off = _r_float(body, off)         # float facing
            event["entity_type"], off = _r_u16(body, off)      # ushort entityType
            event["name"], off = _r_str(body, off)             # string name
            event["surname"], off = _r_str(body, off)          # string surname
            event["guild_name"], off = _r_str(body, off)       # string guildName
            event["guild_rank"], off = _r_i32(body, off)       # int guildRank (enum)
            event["class_hid"], off = _r_str(body, off)        # string classHID
            event["race_hid"], off = _r_str(body, off)         # string raceHID
            event["sex_hid"], off = _r_str(body, off)          # string sexHID
            # After sexHID: bool noCollision, ushort skinTone, then 3 arrays
            # (attachments, textures, features), then more fields, then level.
            # Try to read through to level by skipping the arrays.
            _nc, off = _r_bool(body, off)                      # bool noCollision
            _st, off = _r_u16(body, off)                       # ushort skinTone
            # Skip AttachmentDefinitionRecord[] — ushort count, then each record
            _arr_count, off = _r_u16(body, off)
            if _arr_count is not None and _arr_count < 200:
                for _ in range(_arr_count):
                    _, off = _r_str(body, off)   # string attachmentHID
                    _, off = _r_u16(body, off)   # ushort materialIndex
                    _, off = _r_u16(body, off)   # ushort colorIndex
            # Skip TextureDefinitionRecord[] — ushort count, then each record
            _arr_count, off = _r_u16(body, off)
            if _arr_count is not None and _arr_count < 200:
                for _ in range(_arr_count):
                    _, off = _r_str(body, off)   # string textureHID
            # Skip ModelFeatureRecord[] — ushort count, then each record
            _arr_count, off = _r_u16(body, off)
            if _arr_count is not None and _arr_count < 200:
                for _ in range(_arr_count):
                    _, off = _r_str(body, off)   # string featureHID
                    _, off = _r_float(body, off)  # float value
            # After arrays: int light(4), Color lightColor(16), string materialOverride,
            # string modelOverride, 8 bools(8), byte animPresetID(1), bool showRangedWeapon(1),
            # then int level
            _light, off = _r_i32(body, off)                    # int light
            # Color = 4 floats (RGBA)
            _, off = _r_float(body, off)
            _, off = _r_float(body, off)
            _, off = _r_float(body, off)
            _, off = _r_float(body, off)
            _, off = _r_str(body, off)                         # string materialOverride
            _, off = _r_str(body, off)                         # string modelOverride
            # 8 bools: isAttacking, isSitting, isCorpse, isCorpseMine,
            #          isHostile, isStealth, isHardcore, isLfg
            for _ in range(8):
                _, off = _r_bool(body, off)
            if off + 1 <= len(body):                           # byte animationPresetID
                off += 1
            _, off = _r_bool(body, off)                        # bool showRangedWeapon
            event["level"], off = _r_i32(body, off)            # int level
        except Exception:
            pass  # Partial parse — classHID may still be available

    elif msg_id == 0x0024:  # UpdateExperience
        event["type"] = "UpdateExperience"
        event["entity_id"], off = _r_u32(body, off)
        event["experience"], off = _r_u32(body, off)

    elif msg_id == 0x0025:  # UpdateLevel
        event["type"] = "UpdateLevel"
        event["entity_id"], off = _r_u32(body, off)
        event["class_hid"], off = _r_str(body, off)
        event["level"], off = _r_i32(body, off)

    elif msg_id == 0x005F:  # UpdateClassHID
        event["type"] = "UpdateClassHID"
        event["entity_id"], off = _r_u32(body, off)
        event["class_hid"], off = _r_str(body, off)

    elif msg_id == 0x005C:  # ParticleHit
        event["type"] = "ParticleHit"
        event["target_id"], off = _r_u32(body, off)
        event["particle_name"], off = _r_str(body, off)

    elif msg_id == 0x0146:  # ChannelAbility
        event["type"] = "ChannelAbility"
        event["entity_id"], off = _r_u32(body, off)
        event["target_id"], off = _r_u32(body, off)
        event["ability_name"], off = _r_str(body, off)

    elif msg_id == 0x005D:  # CancelBuff
        event["type"] = "CancelBuff"
        event["entity_id"], off = _r_u32(body, off)

    elif msg_id == 0x0380:  # ClientPartyUpdate — has class/level for party members
        event["type"] = "ClientPartyUpdate"
        try:
            member_count, off = _r_u32(body, off)       # u32 member count
            members = []
            if _plog.isEnabledFor(logging.DEBUG):
                _plog.debug(f"PARTY_UPDATE member_count={member_count} body_len={len(body)} body_hex={body.hex(' ')}")
            if member_count is not None and member_count < 50:
                for mi in range(member_count):
                    m_start = off
                    m_id, off = _r_u32(body, off)       # u32 entity_id
                    m_cid, off = _r_u32(body, off)      # u32 unknown (secondary id)
                    m_name, off = _r_str(body, off)     # LNL string name
                    # After name: [u8 0x00] [3 raw class bytes] [u8 level] [LNL zone]
                    # Class is NOT a LNL string — it's 3 raw ASCII bytes preceded
                    # by a 0x00 separator byte, followed by a u8 level byte.
                    m_class = None
                    m_level = None
                    m_zone = None
                    if _plog.isEnabledFor(logging.DEBUG):
                        peek = body[off:off+30].hex(' ') if off + 30 <= len(body) else body[off:].hex(' ')
                        _plog.debug(f"PARTY_MEMBER_RAW [{mi}] eid=#{m_id} name=\"{m_name}\" "
                                    f"after_name_off={off} next_bytes={peek}")
                    if off + 5 <= len(body):
                        # off+0: separator (0x00), off+1..3: class, off+4: level
                        cls_bytes = body[off+1:off+4]
                        try:
                            cls_str = cls_bytes.decode('ascii')
                            if cls_str.isalpha() and cls_str.islower():
                                m_class = cls_str
                        except (UnicodeDecodeError, ValueError):
                            pass
                        lvl_byte = body[off+4]
                        if 1 <= lvl_byte <= 100:
                            m_level = lvl_byte
                        off += 5
                        # Offline members (eid=0, class=000, level=0) have NO zone string
                        if m_id == 0 and cls_bytes == b'\x00\x00\x00' and lvl_byte == 0:
                            if _plog.isEnabledFor(logging.DEBUG):
                                _plog.debug(f"PARTY_MEMBER_PARSED [{mi}] OFFLINE — no zone")
                        else:
                            # Read zone LNL string (only present for online members)
                            m_zone, off = _r_str(body, off)
                            if _plog.isEnabledFor(logging.DEBUG):
                                _plog.debug(f"PARTY_MEMBER_PARSED [{mi}] class={m_class} "
                                            f"level={m_level} zone={m_zone}")
                    members.append({
                        "id": m_id, "name": m_name,
                        "class_hid": m_class, "level": m_level,
                        "zone": m_zone,
                    })
            event["members"] = members
            event["leader"], off = _r_u32(body, off)
        except Exception:
            if "members" not in event:
                event["members"] = []

    else:
        return None

    return event


def _scan_class_hid(hid_region):
    """Extract class_hid from HID region via ASCII scanning.
    Looks for short printable ASCII runs (class codes like 'bbr', 'wlf', 'elf')."""
    runs = []
    current = []
    for b in hid_region:
        if 0x20 <= b < 0x7F:
            current.append(b)
        else:
            if current:
                runs.append(bytes(current).decode("ascii"))
                current = []
    if current:
        runs.append(bytes(current).decode("ascii"))
    # First multi-char run is likely classHID
    for r in runs:
        if len(r) >= 2:
            return r
    return None


def _find_stats(body, name_end):
    """Scan for health/maxHealth stats block after the HID region."""
    # Primary: NPC 19-byte offset
    off = name_end + 19
    if off + 16 <= len(body):
        h, mh, mn, mmn = struct.unpack_from("<iiii", body, off)
        if 0 < h <= 1_000_000 and 0 < mh <= 1_000_000 and h <= mh:
            if 0 <= mn <= 1_000_000 and 0 < mmn <= 1_000_000:
                return off
    # Secondary: scan
    for delta in range(8, min(50, len(body) - name_end - 15)):
        off = name_end + delta
        if off + 16 > len(body):
            break
        h, mh, mn, mmn = struct.unpack_from("<iiii", body, off)
        if 0 < h <= 1_000_000 and 0 < mh <= 1_000_000 and h <= mh:
            if 0 <= mn <= 1_000_000 and 0 < mmn <= 1_000_000:
                return off
    return None


def _find_position(body, start_off):
    """Scan for a plausible 3D position (3 consecutive floats) in spawn data."""
    for off in range(start_off, len(body) - 11):
        try:
            x, y, z = struct.unpack_from("<fff", body, off)
        except struct.error:
            continue
        if all(-50000 < v < 50000 and v == v for v in (x, y, z)):
            if abs(x) + abs(y) + abs(z) > 1.0:
                nontrivial = sum(1 for v in (x, y, z) if abs(v) > 0.1)
                if nontrivial >= 2:
                    return (x, y, z)
    return None


def _find_hostile(body, start_off):
    """Heuristic: scan for the is_hostile bool in the spawn flags region."""
    # After stats(16) + position sync (~37 bytes) + target + booleans
    # is_hostile is typically in a sequence of booleans
    # We can't know exactly, but we look for common patterns
    return False  # Conservative default


# ===================================================================
# Loot/item message parsing
# ===================================================================

def _read_item_record(data, off):
    """Parse an ItemRecord from the wire. Returns (item_dict, new_offset) or (None, off).

    ItemInformation (0x0080) wire format (all strings use _r_str_nn —
    length counts implicit null but null is NOT on wire):

    [str_nn hid] [str_nn name]
    [i32 item_type] [i32 class_mask] [i32 race_mask] [i32 slot_mask] [i32 req_level]
    [11 bools] [u16 stack_size] [u16 charges]
    [bool craft_flag] [str_nn craft_class]
    [6 x i32 unknown]
    [i32 damage] [i32 delay] [i32 ac]
    [7 x i32 primary stats: str sta dex agi int wis cha]
    [4 x i32 pools: hp hp_regen mana mana_regen]
    [3 x i32 haste: melee ranged spell]
    [7 x i32 resists: fire cold poison disease magic arcane nature]
    [str_nn material_hid] [float weight] [u16 unknown]
    [str_nn description]
    [u16 effect_count] [effect_count x str_nn]
    """
    item = {}
    # Phase 1: HID + Name (must succeed)
    try:
        item["hid"], off = _r_str_nn(data, off)
        if not item["hid"]:
            return None, off
        item["name"], off = _r_str_nn(data, off)
    except Exception:
        return None, off

    # Phase 2: structured fields (best-effort — item is kept even if this fails)
    try:
        item["item_type"], off = _r_i32(data, off)
        item["class_mask"], off = _r_i32(data, off)
        item["race_mask"], off = _r_i32(data, off)
        item["slot_mask"], off = _r_i32(data, off)
        item["required_level"], off = _r_i32(data, off)

        # 11 boolean flags (no_drop, is_unique, is_magic, + 8 unknown)
        item["no_drop"], off = _r_bool(data, off)
        item["is_unique"], off = _r_bool(data, off)
        item["is_magic"], off = _r_bool(data, off)
        for _ in range(8):  # 8 additional unknown bools
            _, off = _r_bool(data, off)

        item["stack_size"], off = _r_u16(data, off)
        item["charges"], off = _r_u16(data, off)

        # Craft flag + craft class string
        _, off = _r_bool(data, off)
        _, off = _r_str_nn(data, off)

        # Damage, delay, AC, then 6 unknown i32 fields
        item["damage"], off = _r_i32(data, off)
        item["delay"], off = _r_i32(data, off)
        item["ac"], off = _r_i32(data, off)
        for _ in range(6):
            _, off = _r_i32(data, off)

        for stat in ("strength", "stamina", "dexterity", "agility",
                     "intelligence", "wisdom", "charisma"):
            item[stat], off = _r_i32(data, off)

        item["health"], off = _r_i32(data, off)
        item["health_regen"], off = _r_i32(data, off)
        item["mana"], off = _r_i32(data, off)
        item["mana_regen"], off = _r_i32(data, off)

        item["melee_haste"], off = _r_i32(data, off)
        item["ranged_haste"], off = _r_i32(data, off)
        item["spell_haste"], off = _r_i32(data, off)

        for resist in ("resist_fire", "resist_cold", "resist_poison", "resist_disease",
                       "resist_magic", "resist_arcane", "resist_nature"):
            item[resist], off = _r_i32(data, off)

        # Material HID string, weight, unknown u16
        _, off = _r_str_nn(data, off)
        item["weight"], off = _r_float(data, off)
        _, off = _r_u16(data, off)

        item["description"], off = _r_str_nn(data, off)

        # Effects — read as array of strings (count + strings)
        effect_count, off = _r_u16(data, off)
        effects = []
        if effect_count is not None and 0 < effect_count <= 50:
            for _ in range(effect_count):
                eff, off = _r_str_nn(data, off)
                if eff is not None:
                    effects.append(eff)
        item["effects"] = effects

    except Exception:
        pass

    return item, off


def parse_loot_event(msg_id, body, direction):
    """Parse a loot/item message. Returns dict or None."""
    event = {"msg_id": msg_id, "msg_name": get_message_name(msg_id), "direction": direction}
    off = 0

    if msg_id == 0x0065:  # LootItemFromCorpse (outbound)
        event["type"] = "LootItemFromCorpse"
        event["entity_id"], off = _r_u32(body, off)
        event["slot_id"], off = _r_u16(body, off)
        event["item_id"], off = _r_u32(body, off)
        return event

    elif msg_id == 0x0063:  # AddItemToInventory
        event["type"] = "AddItemToInventory"
        try:
            # ClientItemRecord format:
            # [u32 item_uid] [u32 unknown] [LNL hid+type_byte]
            # [21 bytes fixed prefix] [i32 craft_count] [N x str_nn craft strings]
            # [embedded ItemRecord using _r_str_nn format]
            event["item_uid"], off = _r_u32(body, off)
            _skip, off = _r_u32(body, off)  # unknown u32
            event["item_hid"], off = _r_str(body, off)
            # Strip trailing type byte (0x03/0x05/etc) from HID
            hid = event.get("item_hid")
            if hid and len(hid) > 1 and not hid[-1].isalnum() and hid[-1] != '_':
                event["item_hid"] = hid[:-1]
            if _plog.isEnabledFor(logging.DEBUG):
                _plog.debug(f"LOOT_HEADER uid={event.get('item_uid')} "
                            f"hid=\"{event.get('item_hid')}\" off={off} "
                            f"remaining={len(body)-off}")
            # Parse embedded ItemRecord from the ClientItemRecord body
            hid_str = event.get("item_hid", "")
            if hid_str and off + 25 < len(body):
                try:
                    # Primary path: skip 21 fixed prefix bytes, read craft
                    # count, skip craft strings, then parse ItemRecord
                    rec_off = off + 21
                    craft_count, rec_off = _r_i32(body, rec_off)
                    if craft_count is not None and 0 <= craft_count <= 10:
                        for _ in range(craft_count):
                            _, rec_off = _r_str_nn(body, rec_off)
                        item, _ = _read_item_record(body, rec_off)
                        if item and item.get("hid"):
                            event["item_record"] = item
                    # Fallback: scan for embedded HID in _r_str_nn format
                    if not event.get("item_record"):
                        hid_bytes = hid_str.encode("utf-8")
                        nn_prefix = struct.pack("<H", len(hid_bytes) + 1)
                        idx = body.find(nn_prefix + hid_bytes, off)
                        if idx >= 0:
                            item, _ = _read_item_record(body, idx)
                            if item and item.get("hid"):
                                event["item_record"] = item
                    if _plog.isEnabledFor(logging.DEBUG):
                        ir = event.get("item_record")
                        if ir:
                            _plog.debug(
                                f"LOOT_ITEM_REC hid={ir.get('hid')} "
                                f"name={ir.get('name')} "
                                f"fields={list(ir.keys())}")
                        else:
                            _plog.debug("LOOT_ITEM_REC parse failed")
                except Exception as e:
                    if _plog.isEnabledFor(logging.DEBUG):
                        _plog.debug(f"LOOT_ITEM_REC_ERR {e}")
        except Exception:
            pass
        return event

    elif msg_id == 0x0080:  # ItemInformation
        event["type"] = "ItemInformation"
        if _plog.isEnabledFor(logging.DEBUG):
            _plog.debug(f"ITEM_INFO_RAW len={len(body)} hex={body.hex(' ')}")
        try:
            # Wire format: [u16 count] [u8 flag] [ItemRecord...]
            _count, off = _r_u16(body, off)
            _flag, off = _r_u8(body, off)
            if _plog.isEnabledFor(logging.DEBUG):
                _plog.debug(f"ITEM_INFO_PREFIX count={_count} flag={_flag}")
            item, off = _read_item_record(body, off)
            if item and item.get("hid"):
                event["item_record"] = item
                if _plog.isEnabledFor(logging.DEBUG):
                    _plog.debug(f"ITEM_INFO_PARSED off={off} remaining={len(body)-off} "
                                f"fields={list(item.keys())}")
                    if off < len(body):
                        _plog.debug(f"ITEM_INFO_TAIL hex={body[off:].hex(' ')}")
            elif _plog.isEnabledFor(logging.DEBUG):
                _plog.debug(f"ITEM_INFO_FAIL hid={item.get('hid') if item else None} "
                            f"name={item.get('name') if item else None} off={off}")
        except Exception as e:
            if _plog.isEnabledFor(logging.DEBUG):
                _plog.debug(f"ITEM_INFO_EXCEPTION {e}")
        return event

    return None


# ===================================================================
# Entity tracker — name resolution + damage/healing meter
# ===================================================================

class Encounter:
    """Tracks a single NPC encounter (one per NPC entity_id)."""
    __slots__ = ('npc_eid', 'npc_name', 'npc_class', 'npc_level', 'max_hp',
                 'start_time', 'end_time', 'is_dead', 'total_damage',
                 'text_damage', 'players')

    def __init__(self, npc_eid, npc_name, npc_class="", npc_level=None, max_hp=None):
        self.npc_eid = npc_eid
        self.npc_name = npc_name
        self.npc_class = npc_class
        self.npc_level = npc_level
        self.max_hp = max_hp
        self.start_time = None   # first damage timestamp
        self.end_time = None     # Die timestamp
        self.is_dead = False
        self.total_damage = 0    # from UpdateHealth deltas (may be percentage-based)
        self.text_damage = 0     # from EndCasting text (real damage numbers)
        # attacker_eid -> {name, cls, level, dealt, text_dealt, received, first, last}
        self.players = {}

    @property
    def best_damage(self):
        """Return whichever is higher: text or HP-based damage.
        Text damage has real numbers (for % HP mobs), HP damage has full coverage."""
        return max(self.text_damage, self.total_damage)

    def get_or_create_player(self, eid, name, cls="", level=None):
        if eid not in self.players:
            self.players[eid] = {
                'name': name, 'cls': cls, 'level': level,
                'dealt': 0, 'text_dealt': 0, 'received': 0,
                'first': None, 'last': None, 'abilities': {}, 'ability_counts': {},
            }
        else:
            # Update name/class/level if we have better info now
            p = self.players[eid]
            if name and not name.startswith("Entity#"):
                # Don't overwrite a good name with "YOU" placeholder
                cur = p['name']
                if name != "YOU" or not cur or cur.startswith("Entity#"):
                    p['name'] = name
            if cls:
                p['cls'] = cls
            if level is not None:
                p['level'] = level
        return self.players[eid]

    @property
    def duration(self):
        if self.start_time is None:
            return 0.0
        end = self.end_time if self.end_time is not None else time.time()
        return max(end - self.start_time, 0.1)

    @property
    def dps(self):
        d = self.duration
        return self.best_damage / d if d > 0 else 0.0


class EntityTracker:
    def __init__(self):
        self.names = {}        # eid -> name
        self.hp = {}           # eid -> (current_hp, max_hp)
        self.damage = {}       # eid -> total damage taken
        self.healing = {}      # eid -> total healing received
        self.first_dmg = {}    # eid -> timestamp of first damage event
        self.last_dmg = {}     # eid -> timestamp of last damage event
        self.classes = {}      # eid -> class_hid string (e.g. "elf", "wlf")
        self.levels = {}       # eid -> level int
        self.zones = {}        # eid -> zone_hid string (e.g. "keepersbight")
        self.entity_types = {} # eid -> entity_type uint16 from SpawnEntity
        self.pet_states = {}   # eid -> True if petState was set in SpawnEntity
        self._pet_owners = {}  # pet_eid -> owner_eid from UpdateState parent_id
        self._lock = threading.Lock()
        self.player_name = ""  # set from config, used to name local player entity
        self._local_player_eid = None  # detected from "Your ..." / "You ..." patterns
        self._party_eids = {}  # name -> eid, tracks current party member eids for zone change detection

        # Damage DEALT tracking (for the damage meter)
        self.damage_dealt = {}   # eid -> total damage dealt by this entity
        self.first_dealt = {}    # eid -> timestamp of first damage dealt
        self.last_dealt = {}     # eid -> timestamp of last damage dealt

        # Encounter tracking (per-NPC)
        self.encounters = []         # all encounters, newest first
        self._encounter_map = {}     # npc_eid -> Encounter

        # Attack attribution: who last attacked each target, and with what
        self.last_attacker = {}      # target_eid -> attacker_eid
        self.last_attack_type = {}   # target_eid -> "melee"/"spell"/"ability"
        self.last_ability_name = {}  # target_eid -> ability name string
        self._pending_attacker = {}  # target_eid -> (caster_eid, ability_name) from BeginCasting
        # Track autoattack state per entity for melee attribution
        self.autoattack_target = {}  # attacker_eid -> target_eid (from ChangeTarget + Autoattack ON)
        self._autoattack_on = set()  # set of eids with autoattack active
        # Most recent UpdateHealth entity — used to correlate ChatCombat with
        # the correct target when multiple entities share the same name.
        self._last_hp_eid = None     # eid from most recent UpdateHealth
        self._last_hp_time = 0.0     # timestamp of that UpdateHealth
        # Pending "You ..." ChatCombat damage waiting for local player eid
        self._pending_local_dmg = []  # [(tag, text_dmg, timestamp, target_name)]
        # ChatCombat damage waiting for UpdateHealth to confirm the target.
        # Prevents ghost encounters from name-lookup hitting the wrong entity.
        self._pending_chat_dmg = []  # [(target_name, text_dmg, timestamp, attacker_eid)]
        # CastAbility OUT → BeginCasting IN correlation for local player detection
        self._pending_cast_target = None  # target_id from most recent outbound CastAbility
        self._pending_cast_time = 0.0

        # Experience tracking
        self._xp_current = {}     # eid -> last known total XP
        self._xp_events = []      # list of {timestamp, eid, name, xp_total, xp_gained, pct}
        self._xp_level_start = {} # eid -> XP total when current level began
        self._xp_level_needed = {}# eid -> XP required for current level (learned from level-ups)
        self._xp_player_level = {}# eid -> last known level (to detect level-ups)

        # Reload gate: block all parsing until ClientPartyUpdate identifies local player
        self._reload_gate = True
        self._reload_gate_time = time.time()  # auto-clear after timeout (ungrouped solo)
        self._party_members_pending = None  # list of (eid, name, class_hid, level) for GUI player selection

    def _backfill_player_info(self, eid, cls=None, level=None):
        """Update class/level on existing encounter player records for this eid."""
        for enc in self.encounters:
            if eid in enc.players:
                p = enc.players[eid]
                if cls and not p['cls']:
                    p['cls'] = cls
                if level is not None and p['level'] is None:
                    p['level'] = level

    @staticmethod
    def _looks_like_npc_name(name):
        """Return True if the name looks like an NPC name (not a player)."""
        if not name:
            return False
        # NPC names typically start with "a ", "an ", "the " (lowercase article)
        # Player names start with an uppercase letter and have no spaces/articles
        if name[0].islower():
            return True
        if name.startswith("Entity#"):
            return True
        return False

    def _mark_local_player(self, eid):
        """Mark entity as the local player and assign player_name if available."""
        # If _local_player_eid is already set from a reliable source (outbound
        # packets), don't let a different eid overwrite it.  Only allow re-set
        # to the same eid (for name refresh) or first-time detection.
        if (self._local_player_eid is not None
                and eid != self._local_player_eid):
            _plog.debug(f"  LOCAL_PLAYER_REJECT eid=#{eid} "
                        f"(already set to #{self._local_player_eid})")
            return
        self.entity_types[eid] = 0
        first_time = self._local_player_eid is None
        self._local_player_eid = eid
        # Auto-detect player name — retry on every call since name may
        # arrive later via SpawnEntity after the eid is first discovered.
        # "YOU" is a fallback that can be overwritten by a real name.
        detected = self.names.get(eid)
        if (detected
                and detected.upper() not in ("YOU", "YOUR")
                and not self._looks_like_npc_name(detected)
                and detected != self.player_name):
            old_pn = self.player_name
            self.player_name = detected
            _plog.info(f"  LOCAL_PLAYER name=\"{self.player_name}\" (was \"{old_pn}\") from eid=#{eid}")
        # Fallback: use "YOU" if no real name found yet
        if not self.player_name:
            self.player_name = "YOU"
            _plog.debug(f"  LOCAL_PLAYER eid=#{eid} fallback name=\"YOU\"")
        if self.player_name:
            cur_name = self.names.get(eid)
            if not cur_name or cur_name == "YOU" or cur_name.startswith("Entity#"):
                self.names[eid] = self.player_name
                _plog.debug(f"  LOCAL_PLAYER eid=#{eid} name=\"{self.player_name}\"")
        # Update encounter player entries that still have placeholder names
        if self.player_name:
            for enc in self.encounters:
                if eid in enc.players:
                    cur = enc.players[eid]['name']
                    if cur.startswith("Entity#") or cur == "YOU" or self._looks_like_npc_name(cur):
                        if self.player_name != cur:
                            enc.players[eid]['name'] = self.player_name
        if first_time:
            # Flush pending "You ..." ChatCombat damage now that we know the player
            if self._pending_local_dmg:
                atk_name = self.names.get(eid, f"Entity#{eid}")
                atk_cls = self.classes.get(eid, "")
                atk_lvl = self.levels.get(eid)
                for tag, dmg, ts, tgt_name, *extra in self._pending_local_dmg:
                    tgt_eid = self._resolve_target_eid(None, tgt_name)
                    if tgt_eid is not None:
                        enc = self._encounter_map.get(tgt_eid)
                        if enc:
                            p = enc.get_or_create_player(eid, atk_name, atk_cls, atk_lvl)
                            p['text_dealt'] += dmg
                            ab = extra[0] if extra else "Melee"
                            p['abilities'][ab] = p['abilities'].get(ab, 0) + dmg
                            p['ability_counts'][ab] = p['ability_counts'].get(ab, 0) + 1
                            if p['first'] is None:
                                p['first'] = ts
                            p['last'] = ts
                            _plog.debug(f"  FLUSH_PENDING \"{enc.npc_name}\"(#{tgt_eid}) +{dmg}dmg by {atk_name}(#{eid})")
                self._pending_local_dmg.clear()
            # Merge "_local" sentinel from last_attacker, damage_dealt,
            # and encounter player entries into the real eid.
            for k, v in list(self.last_attacker.items()):
                if v == "_local":
                    self.last_attacker[k] = eid
            if "_local" in self.damage_dealt:
                self.damage_dealt[eid] = self.damage_dealt.get(eid, 0) + self.damage_dealt.pop("_local")
            if "_local" in self.first_dealt:
                old_first = self.first_dealt.pop("_local")
                if eid not in self.first_dealt or old_first < self.first_dealt[eid]:
                    self.first_dealt[eid] = old_first
            if "_local" in self.last_dealt:
                old_last = self.last_dealt.pop("_local")
                if eid not in self.last_dealt or old_last > self.last_dealt[eid]:
                    self.last_dealt[eid] = old_last
            for enc in self.encounters:
                if "_local" in enc.players:
                    old_p = enc.players.pop("_local")
                    name = self.player_name or self.names.get(eid, f"Entity#{eid}")
                    real_p = enc.get_or_create_player(eid, name, self.classes.get(eid, ""), self.levels.get(eid))
                    real_p['dealt'] += old_p['dealt']
                    real_p['text_dealt'] += old_p['text_dealt']
                    real_p['received'] += old_p['received']
                    for ab, dmg in old_p.get('abilities', {}).items():
                        real_p['abilities'][ab] = real_p['abilities'].get(ab, 0) + dmg
                    for ab, cnt in old_p.get('ability_counts', {}).items():
                        real_p['ability_counts'][ab] = real_p['ability_counts'].get(ab, 0) + cnt
                    if old_p['first'] is not None:
                        if real_p['first'] is None or old_p['first'] < real_p['first']:
                            real_p['first'] = old_p['first']
                    if old_p['last'] is not None:
                        if real_p['last'] is None or old_p['last'] > real_p['last']:
                            real_p['last'] = old_p['last']
            _plog.info(f"  LOCAL_MERGE merged '_local' sentinel entries into eid=#{eid}")

    def _resolve_target_eid(self, target_id, target_name):
        """Resolve the actual NPC entity_id for encounter tracking.
        If target_id points to a player (type 0) or is missing, fall back to
        reverse name lookup from self.names, preferring alive entities."""
        if target_id is not None:
            target_type = self.entity_types.get(target_id)
            if target_type != 0:  # NPC or unknown (None) — accept
                return target_id
            # Player target — allow if a PvP encounter already exists
            if target_type == 0 and self._encounter_map.get(target_id) is not None:
                return target_id
        # target_id is invalid (None, no encounter, or eid 0) — reverse lookup by name
        # When multiple entities share a name (e.g. "an ashira warrior"),
        # prefer one that is alive (encounter not dead) over stale/dead ones.
        if target_name:
            best_eid = None
            for eid_candidate, name in self.names.items():
                if name == target_name:
                    eid_type = self.entity_types.get(eid_candidate)
                    # Accept NPCs/unknown, or players with existing PvP encounter
                    if eid_type != 0 or self._encounter_map.get(eid_candidate) is not None:
                        enc = self._encounter_map.get(eid_candidate)
                        if enc is None or not enc.is_dead:
                            return eid_candidate  # alive or no encounter yet — best match
                        if best_eid is None:
                            best_eid = eid_candidate  # fallback to first dead match
            return best_eid
        return None

    def get_name(self, eid):
        if eid is None:
            return "???"
        with self._lock:
            name = self.names.get(eid)
        return name if name else f"Entity#{eid}"

    def get_name_short(self, eid):
        """Name without entity ID suffix — for cleaner display."""
        if eid is None:
            return "???"
        with self._lock:
            return self.names.get(eid, f"Entity#{eid}")

    @staticmethod
    def _extract_ability_name(text):
        """Extract ability or melee verb from combat text for ability breakdown."""
        # Spell: "X's AbilityName hits Y for N..." or "Your AbilityName hits Y for N..."
        m = re.match(r"^(?:.+?'s|Your) (.+?) hits .+? for \d+", text)
        if m:
            return m.group(1)
        # Local melee: "You verb ..."
        m = re.match(r"^You (\w+)", text)
        if m:
            return "Melee"
        # 3P melee: "Name verbs ..."
        m = re.match(r"^\S+ (\w+?)(?:e?s) ", text)
        if m:
            return "Melee"
        return "Auto-attack"

    def _process_chat_combat(self, text):
        """Process a ChatMessage combat text (channel 1 damage lines).
        No entity_id/target_id — resolve everything from text."""
        if not text:
            return
        text = _strip_msg_type_byte(text)
        _plog.debug(f"CHATCOMBAT text=\"{text[:80]}\"")

        # Every damage line contains "for N points of [Type ]damage" — use
        # that as the universal damage indicator instead of matching verbs.
        m_num = re.search(r'for (\d+) points? of ', text)
        if not m_num:
            return
        text_dmg = int(m_num.group(1))

        attacker_name = None
        target_name = None
        is_local = False

        # 1. Local player melee: "You slash [at] X for N ..."
        m = re.match(r"^You \w+ (?:at )?(.+?)(?:\s+with (?:your|their) offhand)? for \d+", text)
        if m:
            target_name = m.group(1)
            is_local = True
        # 2. Local ability: "Your Restorative Smite hits X for N ..."
        if not m:
            m = re.match(r"^Your .+? hits (.+?) for \d+", text)
            if m:
                target_name = m.group(1)
                is_local = True
        # 3. Third-person ability: "Name's Ability hits X for N ..."
        #    Ability name must start with a capital letter so possessive
        #    entity names like "a nefarious cultist's pet" aren't split.
        if not m:
            m = re.match(r"^(.+?)'s [A-Z].+? hits (.+?) for \d+", text)
            if m:
                attacker_name = m.group(1)
                target_name = m.group(2)
        # 4. Third-person melee: "Name verbs [at] X for N ..."
        #    Use verb whitelist (with trailing 's/es') + greedy attacker
        #    capture to prevent words like "nefarious" matching as verbs.
        if not m:
            m = re.match(r"^(.+) " + _MELEE_VERBS + r"(?:e?s) (?:at )?(.+?)(?:\s+with (?:your|their) offhand)? for \d+", text)
            if m:
                attacker_name = m.group(1)
                target_name = m.group(2)

        if not m:
            return

        # "Your crusader slashes X" — pet/mercenary uses a melee verb,
        # pattern 4 captures "Your crusader" as attacker.  Treat as local.
        if attacker_name and attacker_name.startswith("Your "):
            is_local = True
            attacker_name = None

        now = time.time()

        with self._lock:
            # "X slashes you for N..." or "X's Ability hits you for N..."
            # → the local player is the TARGET.  Use _local_player_eid if
            # already known (set by outbound packets); only fall back to
            # HP-correlation when the eid hasn't been discovered yet.
            if target_name and target_name.lower() == "you":
                if self._local_player_eid is None:
                    if self._last_hp_eid is not None and (now - self._last_hp_time) < 2.0:
                        hp_type = self.entity_types.get(self._last_hp_eid)
                        if hp_type is not None and hp_type != 0:
                            _plog.debug(f"  CHATCOMBAT_LOCAL_REJECT target=\"you\" hp_eid=#{self._last_hp_eid} is NPC (type={hp_type})")
                        else:
                            self._mark_local_player(self._last_hp_eid)
                            _plog.debug(f"  CHATCOMBAT_LOCAL_DETECT target=\"you\" hp_corr → local_eid=#{self._last_hp_eid}")
                # Target is the local player — not an NPC encounter, skip damage tracking
                return

            # Mark local player if detected
            if is_local and self._local_player_eid is not None:
                attacker_eid = self._local_player_eid
            elif is_local:
                # Don't know local player eid yet — queue for later
                # attribution when _mark_local_player fires
                attacker_eid = None
                self._pending_local_dmg.append(("_deferred_", text_dmg, now, target_name, self._extract_ability_name(text)))
            else:
                # Resolve attacker by name — prefer eid with entity_type==0
                # (after zone migration, old eids lose their entity_type)
                attacker_eid = None
                if attacker_name:
                    fallback_eid = None
                    for eid_c, name in self.names.items():
                        if name == attacker_name:
                            if self.entity_types.get(eid_c) == 0:
                                attacker_eid = eid_c
                                break
                            if fallback_eid is None:
                                fallback_eid = eid_c
                    if attacker_eid is None:
                        attacker_eid = fallback_eid

            # Resolve target NPC — prefer the entity from the most recent
            # UpdateHealth (arrives right before the ChatCombat message).
            # This avoids picking the wrong entity when multiple NPCs share
            # a name (e.g. six "an ashira lookout" in the zone).
            target_eid = None
            from_hp_corr = False
            if self._last_hp_eid is not None and (now - self._last_hp_time) < 2.0:
                hp_name = self.names.get(self._last_hp_eid)
                hp_type = self.entity_types.get(self._last_hp_eid)
                # Allow NPC targets (type!=0) or player targets with existing
                # PvP encounter (so text_damage reaches the encounter immediately)
                _hp_pvp_ok = hp_type == 0 and self._encounter_map.get(self._last_hp_eid) is not None
                if (hp_type != 0 or _hp_pvp_ok) and (hp_name == target_name or hp_name is None):
                    target_eid = self._last_hp_eid
                    from_hp_corr = True
                    # Set name if entity didn't have one yet
                    if hp_name is None and target_name:
                        self.names[self._last_hp_eid] = target_name
            if target_eid is None:
                target_eid = self._resolve_target_eid(None, target_name)
            # If resolved via name lookup to an entity with no HP data,
            # the entity likely isn't the real target (just a spawned NPC
            # sharing the name).  Queue damage for when UpdateHealth
            # confirms the actual target — prevents ghost encounters.
            _ability = self._extract_ability_name(text)
            if target_eid is not None and not from_hp_corr and target_eid not in self.hp:
                self._pending_chat_dmg.append((target_name, text_dmg, now, attacker_eid, _ability))
                _plog.debug(f"  CHATCOMBAT_QUEUED target=\"{target_name}\"(#{target_eid} no HP) +{text_dmg}dmg (waiting for UpdateHealth)")
                return
            if target_eid is None:
                self._pending_chat_dmg.append((target_name, text_dmg, now, attacker_eid, _ability))
                _plog.debug(f"  CHATCOMBAT_QUEUED target=\"{target_name}\"(unresolved) +{text_dmg}dmg (waiting for UpdateHealth)")
                return

            enc = self._get_or_create_encounter(target_eid, now)
            enc.text_damage += text_dmg
            if enc.start_time is None:
                enc.start_time = now

            if attacker_eid is not None:
                atk_name = self.names.get(attacker_eid, f"Entity#{attacker_eid}")
                atk_cls = self.classes.get(attacker_eid, "")
                atk_lvl = self.levels.get(attacker_eid)
                p = enc.get_or_create_player(attacker_eid, atk_name, atk_cls, atk_lvl)
                p['text_dealt'] += text_dmg
                ability = self._extract_ability_name(text)
                p['abilities'][ability] = p['abilities'].get(ability, 0) + text_dmg
                p['ability_counts'][ability] = p['ability_counts'].get(ability, 0) + 1
                if p['first'] is None:
                    p['first'] = now
                p['last'] = now
                _plog.debug(f"  CHATCOMBAT_DMG \"{enc.npc_name}\"(#{target_eid}) +{text_dmg}dmg by {atk_name}(#{attacker_eid}) text_total={enc.text_damage}")
            else:
                _plog.debug(f"  CHATCOMBAT_DMG \"{enc.npc_name}\"(#{target_eid}) +{text_dmg}dmg by \"{attacker_name}\"(unresolved) text_total={enc.text_damage}")

    def process(self, event):
        """Update tracker. Returns (dmg, heal) deltas or None."""
        etype = event.get("type", "")

        # Reload gate: discard everything except ClientPartyUpdate and SpawnEntity
        # SpawnEntity is allowed through to populate entity_types/pet_states/names
        # (it cannot cause local player misidentification)
        # Auto-clear after 15s — game sends nothing when solo ungrouped
        if self._reload_gate and etype not in ("ClientPartyUpdate", "SpawnEntity"):
            if time.time() - self._reload_gate_time > 15.0:
                self._reload_gate = False
                _plog.info("RELOAD_GATE auto-cleared — timeout (solo ungrouped)")
            else:
                return None

        # ChatCombat has no entity_id — handle separately
        if etype == "ChatCombat":
            self._process_chat_combat(event.get("text", ""))
            return None

        # CastAbility OUT has no entity_id — record for BeginCasting correlation
        if etype == "CastAbility":
            direction = event.get("direction", "IN")
            if direction == "OUT":
                with self._lock:
                    self._pending_cast_target = event.get("target_id")
                    self._pending_cast_time = time.time()
                    _plog.debug(f"CASTABILITY_OUT gem={event.get('gem_id')} target=#{self._pending_cast_target}")
            return None

        # ClientPartyUpdate has no single entity_id — process member list
        if etype == "ClientPartyUpdate":
            with self._lock:
                members = event.get("members", [])
                for m in members:
                    m_eid = m.get("id")
                    m_name = m.get("name")
                    m_class = m.get("class_hid")
                    m_level = m.get("level")
                    m_zone = m.get("zone")
                    if not m_eid:
                        continue
                    # Detect eid change (zone change) — migrate data from old eid
                    if m_name and m_name in self._party_eids:
                        old_eid = self._party_eids[m_name]
                        if old_eid != m_eid:
                            _plog.info(f"PARTY_EID_MIGRATE \"{m_name}\" old=#{old_eid} → new=#{m_eid}")
                            # Clear old eid's player type so it doesn't pollute
                            # if the eid gets reused by an NPC in the new zone
                            self.entity_types.pop(old_eid, None)
                            # Carry over class/level/zone to new eid
                            if old_eid in self.classes and m_eid not in self.classes:
                                self.classes[m_eid] = self.classes[old_eid]
                            if old_eid in self.levels and m_eid not in self.levels:
                                self.levels[m_eid] = self.levels[old_eid]
                            if old_eid in self.zones and m_eid not in self.zones:
                                self.zones[m_eid] = self.zones[old_eid]
                    if m_name:
                        self.names[m_eid] = m_name
                        self._party_eids[m_name] = m_eid
                    self.entity_types[m_eid] = 0  # party members are players
                    if m_class:
                        self.classes[m_eid] = m_class
                    if m_level is not None:
                        self.levels[m_eid] = m_level
                    if m_zone:
                        self.zones[m_eid] = m_zone
                    if m_class or m_level is not None:
                        self._backfill_player_info(m_eid, cls=m_class, level=m_level)
                    # Local player detection from party data
                    if m_eid == self._local_player_eid:
                        # Already know this is us — refresh name/class/level
                        self._mark_local_player(m_eid)
                    elif (m_name
                          and self.player_name
                          and self.player_name != "YOU"
                          and m_name == self.player_name
                          and m_eid != self._local_player_eid):
                        # Name matches — either first detection or eid changed (zone change)
                        if self._local_player_eid is not None:
                            _plog.info(f"PARTY_EID_CHANGE \"{m_name}\" old=#{self._local_player_eid} → new=#{m_eid}")
                            self._local_player_eid = None  # allow re-marking with new eid
                        _plog.info(f"PARTY_LOCAL_DETECT name match \"{m_name}\" → eid=#{m_eid}")
                        self._mark_local_player(m_eid)
                    _plog.debug(f"PARTY_MEMBER #{m_eid} \"{m_name}\" class={m_class} lvl={m_level}")
                # Solo: auto-detect and clear gate immediately
                # Group: store member list for GUI player selection (gate stays up)
                valid = [(m.get("id"), m.get("name"), m.get("class_hid"), m.get("level"))
                         for m in members if m.get("id") and m.get("name")
                         and not self._looks_like_npc_name(m.get("name", ""))]
                if self._reload_gate and self._local_player_eid is None:
                    if len(valid) == 1:
                        eid0, name0, _, _ = valid[0]
                        _plog.info(f"PARTY_SOLO_DETECT single member \"{name0}\" → eid=#{eid0}")
                        self._mark_local_player(eid0)
                        self._reload_gate = False
                        _plog.info("RELOAD_GATE cleared — solo player")
                    elif len(valid) > 1:
                        self._party_members_pending = valid
                        _plog.info(f"RELOAD_GATE waiting for player selection ({len(valid)} members)")
                    else:
                        # No valid members (solo, not in a party) — clear gate to prevent lockout
                        self._reload_gate = False
                        _plog.info("RELOAD_GATE cleared — no valid party members (solo ungrouped)")
                elif self._reload_gate:
                    # local player already known (shouldn't happen, but be safe)
                    self._reload_gate = False
                    _plog.info(f"RELOAD_GATE cleared — local player already known #{self._local_player_eid}")
            return None

        eid = event.get("entity_id")
        if eid is None:
            return None

        with self._lock:
            etype = event.get("type", "")

            if etype == "SpawnEntity":
                name = event.get("name")
                if name:
                    self.names[eid] = name
                    # If this is the local player and we just learned their
                    # real name, re-run _mark_local_player to replace all
                    # "Entity#XXXXX" entries in encounters with the real name.
                    if eid == self._local_player_eid and not self.player_name:
                        self._mark_local_player(eid)
                # Don't use spawn HP as damage baseline — _find_stats often
                # grabs misaligned bytes producing garbage values (e.g. 3072/49920).
                # Let the first UpdateHealth set the real baseline instead.
                # Clear any stale HP so re-spawns don't carry old baselines.
                self.hp.pop(eid, None)
                class_hid = event.get("class_hid")
                if class_hid:
                    self.classes[eid] = class_hid
                level = event.get("level")
                et = event.get("entity_type")
                if level is not None:
                    # SpawnEntity level uses fallback byte scanning that often
                    # misreads values.  Don't overwrite a level already set by
                    # a more reliable source (ClientPartyUpdate / UpdateLevel)
                    # for confirmed players.
                    existing_level = self.levels.get(eid)
                    if existing_level is not None and self.entity_types.get(eid) == 0:
                        _plog.debug(f"SPAWN_SKIP_LEVEL #{eid} spawn_lvl={level} "
                                    f"keeping existing={existing_level} (player)")
                        level = None  # don't use spawn level
                    else:
                        self.levels[eid] = level
                if class_hid or level is not None:
                    self._backfill_player_info(eid, cls=class_hid, level=level)
                if et is not None:
                    self.entity_types[eid] = et
                if event.get("pet_state"):
                    self.pet_states[eid] = True
                    parent_id = event.get("parent_id")
                    if not parent_id:
                        # Fallback 1: scan body for known party member eids
                        # Use step=1 (not 4) — parent eid may not be 4-byte aligned
                        # due to variable-length string fields preceding it
                        pet_body = event.get("_pet_body")
                        if pet_body:
                            party_eids = set(self._party_eids.values())
                            for scan_off in range(0, len(pet_body) - 3):
                                candidate, _ = _r_u32(pet_body, scan_off)
                                if candidate and candidate in party_eids:
                                    parent_id = candidate
                                    break
                        # Fallback 2: eid-1 is a confirmed player (zone entry)
                        if not parent_id and self.entity_types.get(eid - 1) == 0:
                            parent_id = eid - 1
                    if parent_id:
                        self._pet_owners[eid] = parent_id
                    owner_name = self.names.get(parent_id, "?") if parent_id else "?"
                    _plog.debug(f"SPAWN_PET #{eid} \"{name}\" owner=#{parent_id} \"{owner_name}\"")
                self.damage.setdefault(eid, 0)
                self.healing.setdefault(eid, 0)
                # Retire old encounter only if eid is reused by a DIFFERENT entity.
                # Pets and nearby mobs get repeated SpawnEntity messages for the
                # same entity — don't destroy the encounter mapping for those.
                old_enc = self._encounter_map.get(eid)
                if old_enc:
                    new_name = event.get("name")
                    if new_name and old_enc.npc_name != new_name:
                        self._encounter_map.pop(eid, None)
                        if not old_enc.is_dead and old_enc.best_damage > 0:
                            old_enc.end_time = time.time()
                            _plog.debug(f"ENC_RETIRE #{eid} \"{old_enc.npc_name}\" best_dmg={old_enc.best_damage} (eid reused by \"{new_name}\")")
                _safe_name = (name or "").encode('ascii', 'replace').decode('ascii')[:60]
                _plog.debug(f"SPAWN #{eid} type={et} \"{_safe_name}\" HP:{event.get('hp')}/{event.get('max_hp')} class={class_hid} lvl={level}")
                return None

            if etype == "UpdateClassHID":
                class_hid = event.get("class_hid")
                if class_hid:
                    self.classes[eid] = class_hid
                    self._backfill_player_info(eid, cls=class_hid)
                    _plog.debug(f"CLASS_UPDATE #{eid} class={class_hid}")
                return None

            if etype == "UpdateLevel":
                class_hid = event.get("class_hid")
                level = event.get("level")
                if class_hid:
                    self.classes[eid] = class_hid
                if level is not None:
                    old_level = self._xp_player_level.get(eid)
                    self.levels[eid] = level
                    self._xp_player_level[eid] = level
                    # Level-up detected: learn XP-per-level from the transition
                    cur_xp = self._xp_current.get(eid)
                    if old_level is not None and level > old_level and cur_xp is not None:
                        start = self._xp_level_start.get(eid)
                        if start is not None:
                            self._xp_level_needed[eid] = cur_xp - start
                            _plog.debug(f"XP_LEVEL_LEARNED #{eid} level {old_level}->{level} needed={cur_xp - start:,}")
                    # New level starts at current XP
                    if cur_xp is not None:
                        self._xp_level_start[eid] = cur_xp
                self._backfill_player_info(eid, cls=class_hid, level=level)
                _plog.debug(f"LEVEL_UPDATE #{eid} class={class_hid} level={level}")
                return None

            if etype == "UpdateExperience":
                xp_total = event.get("experience", 0)
                prev = self._xp_current.get(eid)
                self._xp_current[eid] = xp_total
                # Seed level start on first XP event if not set
                if eid not in self._xp_level_start:
                    self._xp_level_start[eid] = 0  # XP value IS progress into level
                # Resolve the NPC that just died for this kill.
                # The XP delta is off-by-one: the delta computed NOW
                # is from the PREVIOUS kill, so we save this kill's NPC
                # and attribute the current delta to the PREVIOUS kill's NPC.
                npc_name_now = None
                now = time.time()
                # Resolve the kill target via HP correlation.
                # Skip confirmed players (type==0) unless they died (PvP).
                # Skip unknown entities (type==None) with player-like names
                # (uppercase first char) — they're likely party members whose
                # SpawnEntity wasn't captured yet.
                if (self._last_hp_eid is not None
                        and (now - self._last_hp_time) < 3.0):
                    hp_enc = self._encounter_map.get(self._last_hp_eid)
                    if hp_enc and hp_enc.npc_name:
                        hp_type = self.entity_types.get(self._last_hp_eid)
                        if hp_type == 0 and not hp_enc.is_dead:
                            pass  # living player — skip
                        elif hp_type is None and not self._looks_like_npc_name(hp_enc.npc_name):
                            pass  # unknown entity with player name — skip
                        else:
                            npc_name_now = hp_enc.npc_name
                if not npc_name_now:
                    # Fallback: find the most recently dead encounter
                    # Same filtering: skip players and unknown player-names
                    last_kill = None
                    for enc in self.encounters:
                        if enc.end_time and enc.npc_name:
                            enc_type = self.entity_types.get(enc.npc_eid)
                            if enc_type == 0:
                                continue  # player encounter — skip for XP
                            if enc_type is None and not self._looks_like_npc_name(enc.npc_name):
                                continue  # unknown with player name — skip
                            if last_kill is None or enc.end_time > last_kill.end_time:
                                last_kill = enc
                    if last_kill and (now - last_kill.end_time) < 5.0:
                        npc_name_now = last_kill.npc_name
                # First event — record baseline (no delta to show yet)
                if prev is None:
                    _plog.debug(f"XP_BASELINE #{eid} total={xp_total:,} (first event, no delta)")
                    return None
                leveled_up = False
                if xp_total < prev:
                    # XP dropped — level-up detected (XP is per-level, resets)
                    self._xp_level_needed[eid] = prev
                    self._xp_level_start[eid] = 0
                    leveled_up = True
                    _plog.debug(f"XP_LEVELUP_DETECTED #{eid} old_cap={prev:,} new_xp={xp_total:,}")
                xp_gained = xp_total - prev if not leveled_up else xp_total
                # Compute percentage of level if we know XP-per-level
                level_needed = self._xp_level_needed.get(eid)
                pct = (xp_gained / level_needed * 100) if (level_needed and xp_gained > 0) else None
                name = self.names.get(eid, f"Entity#{eid}")
                npc_for_delta = npc_name_now
                zone = self.zones.get(eid)
                xp_ev = {
                    "timestamp": time.time(),
                    "eid": eid,
                    "name": name,
                    "xp_total": xp_total,
                    "xp_gained": xp_gained,
                    "pct": pct,
                    "leveled_up": leveled_up,
                }
                if npc_for_delta:
                    xp_ev["npc_name"] = npc_for_delta
                if zone:
                    xp_ev["zone"] = zone
                self._xp_events.append(xp_ev)
                _plog.debug(f"XP_UPDATE #{eid} \"{name}\" total={xp_total:,} gained=+{xp_gained:,} pct={pct} lvlup={leveled_up} npc=\"{npc_for_delta}\" next_npc=\"{npc_name_now}\"")
                return None

            if etype == "UpdateState":
                name = event.get("name")
                class_hid = event.get("class_hid")
                level = event.get("level")
                et = event.get("entity_type")
                if name:
                    self.names[eid] = name
                    if eid == self._local_player_eid and not self.player_name:
                        self._mark_local_player(eid)
                if et is not None:
                    self.entity_types[eid] = et
                if class_hid:
                    self.classes[eid] = class_hid
                if level is not None:
                    self.levels[eid] = level
                if class_hid or level is not None:
                    self._backfill_player_info(eid, cls=class_hid, level=level)
                parent_id = event.get("parent_id")
                pet_st = event.get("pet_state")
                if pet_st:
                    self.pet_states[eid] = True
                if parent_id and parent_id != 0:
                    self._pet_owners[eid] = parent_id
                _safe_name = (name or "").encode('ascii', 'replace').decode('ascii')[:60]
                _plog.debug(f"UPDATE_STATE #{eid} type={et} \"{_safe_name}\" class={class_hid} lvl={level} parent={parent_id} pet={pet_st}")
                return None

            if etype == "DespawnEntity":
                _plog.debug(f"DESPAWN #{eid}")
                return None

            if etype == "Die":
                dead_name = self.names.get(eid, f"#{eid}")
                etype_val = self.entity_types.get(eid)
                # Skip player deaths (feign death, PvP, etc.) — they pollute
                # the dead-encounter list used for XP NPC attribution.
                if etype_val == 0:
                    _plog.debug(f"DIE_PLAYER #{eid} \"{dead_name}\" skipped (player)")
                    return None
                if etype_val is None and not self._looks_like_npc_name(dead_name):
                    _plog.debug(f"DIE_PLAYER #{eid} \"{dead_name}\" skipped (unknown, player-like name)")
                    return None
                enc = self._encounter_map.get(eid)
                if enc and not enc.is_dead:
                    enc.is_dead = True
                    enc.end_time = time.time()
                    _plog.debug(f"DIE #{eid} \"{dead_name}\" hp_dmg={enc.total_damage} text_dmg={enc.text_damage} best={enc.best_damage} players={list(enc.players.keys())}")
                else:
                    _plog.debug(f"DIE #{eid} \"{dead_name}\" no_encounter")
                return None

            # Track name from any event that has it
            if event.get("name") and eid not in self.names:
                self.names[eid] = event["name"]

            # Attack attribution tracking
            if etype == "BeginCasting":
                target_id = event.get("target_id")
                ability = event.get("ability_name", "")
                if target_id is not None:
                    self.last_attacker[target_id] = eid
                    self.last_attack_type[target_id] = "spell"
                    self.last_ability_name[target_id] = ability
                # CastAbility OUT → BeginCasting IN correlation:
                # If we recently sent a CastAbility with the same target_id,
                # the BeginCasting entity_id (eid) is the local player.
                if (self._pending_cast_target is not None
                        and target_id == self._pending_cast_target
                        and (time.time() - self._pending_cast_time) < 2.0):
                    self._mark_local_player(eid)
                    self._pending_cast_target = None
                    _plog.info(f"  CAST_CORRELATE BeginCasting eid=#{eid} matched CastAbility target=#{target_id} → local player")
                caster_name = self.names.get(eid, f"#{eid}")
                target_name = self.names.get(target_id, f"#{target_id}") if target_id else "?"
                _plog.debug(f"ATTRIB BeginCasting caster={caster_name}(#{eid}) -> target={target_name}(#{target_id}) ability=\"{ability}\"")
                # Pet owner fallback: if a confirmed player casts on an
                # unowned pet, assume they are the owner (first writer wins).
                # The owner typically buffs their pet before the healer does.
                if (target_id and target_id in self.pet_states
                        and target_id not in self._pet_owners
                        and self.entity_types.get(eid) == 0):
                    self._pet_owners[target_id] = eid
                    if _plog.isEnabledFor(logging.DEBUG):
                        _plog.debug(f"PET_OWNER_CAST #{target_id} \"{target_name}\" "
                                    f"owner=#{eid} \"{caster_name}\" via BeginCasting")

            elif etype == "ChannelAbility":
                target_id = event.get("target_id")
                ability = event.get("ability_name", "")
                if target_id is not None:
                    self.last_attacker[target_id] = eid
                    self.last_attack_type[target_id] = "spell"
                    self.last_ability_name[target_id] = ability
                _plog.debug(f"ATTRIB ChannelAbility caster=#{eid} -> target=#{target_id} ability=\"{ability}\"")

            elif etype == "EndCasting":
                # Extract caster/target names and set attacker attribution
                text = _strip_msg_type_byte(event.get("text", ""))
                target_id = event.get("target_id")
                _plog.debug(f"ENDCAST caster=#{eid} target=#{target_id} text=\"{text[:80]}\"")
                if text:
                    is_dmg = False
                    is_heal = False
                    _text_target_name = None  # target name extracted from text

                    # === DAMAGE PATTERNS (order matters) ===

                    # 1. Third-person spell: "X's Ability hits Y for N ..."
                    m = re.match(r"^(.+?)'s .+? hits (.+?) for \d+", text)
                    if m:
                        _text_target_name = m.group(2)
                        if eid not in self.names:
                            self.names[eid] = m.group(1)
                        # Don't set name to "YOU"/"you" — that's a pronoun, not a name
                        if (target_id is not None and target_id not in self.names
                                and _text_target_name.upper() not in ("YOU", "YOUR")):
                            self.names[target_id] = _text_target_name
                        is_dmg = True
                        _plog.debug(f"  -> DMG_HIT attacker={m.group(1)}(#{eid}) -> victim={_text_target_name}(#{target_id})")

                    # 2. Local player spell: "Your Ability hits Y for N ..."
                    if not is_dmg:
                        m_local = re.match(r"^Your .+? hits (.+?) for \d+", text)
                        if m_local:
                            _text_target_name = m_local.group(1)
                            self._mark_local_player(eid)
                            if target_id is not None and target_id not in self.names:
                                self.names[target_id] = _text_target_name
                            is_dmg = True
                            _plog.debug(f"  -> DMG_LOCAL_SPELL caster=#{eid} -> victim={_text_target_name}(#{target_id})")

                    # 3. Local player melee WITH damage: "You slash Y for N points of ..."
                    #    Must check BEFORE the no-damage melee pattern to avoid capturing damage text as target
                    if not is_dmg:
                        m_melee_dmg = re.match(rf"^You {_MELEE_VERBS} (.+?) for \d+ point", text)
                        if m_melee_dmg:
                            _text_target_name = m_melee_dmg.group(1)
                            self._mark_local_player(eid)
                            if target_id is not None and target_id not in self.names:
                                self.names[target_id] = _text_target_name
                            is_dmg = True
                            _plog.debug(f"  -> DMG_LOCAL_MELEE_D caster=#{eid} -> victim={_text_target_name}(#{target_id})")

                    # 4. Third-person melee WITH damage: "Bannin slashes Y for N points of ..."
                    if not is_dmg:
                        m_3p_melee_dmg = re.match(rf"^(\S+) {_MELEE_VERBS}(?:e?s) (.+?) for \d+ point", text)
                        if m_3p_melee_dmg:
                            _text_target_name = m_3p_melee_dmg.group(2)
                            if eid not in self.names:
                                self.names[eid] = m_3p_melee_dmg.group(1)
                            if target_id is not None and target_id not in self.names:
                                self.names[target_id] = _text_target_name
                            is_dmg = True
                            _plog.debug(f"  -> DMG_3P_MELEE_D attacker={m_3p_melee_dmg.group(1)}(#{eid}) -> victim={_text_target_name}(#{target_id})")

                    # 5. Local player melee NO damage: "You kick Y."
                    if not is_dmg:
                        m_melee = re.match(rf"^You {_MELEE_VERBS} (.+?)\.?$", text)
                        if m_melee:
                            _text_target_name = m_melee.group(1)
                            self._mark_local_player(eid)
                            if target_id is not None and target_id not in self.names:
                                self.names[target_id] = _text_target_name
                            is_dmg = True
                            _plog.debug(f"  -> DMG_LOCAL_MELEE caster=#{eid} -> victim={_text_target_name}(#{target_id})")

                    # 6. Third-person melee NO damage: "Lilyth kicks Y."
                    if not is_dmg:
                        m_3p_melee = re.match(rf"^(\S+) {_MELEE_VERBS}(?:e?s) (.+?)\.?$", text)
                        if m_3p_melee:
                            _text_target_name = m_3p_melee.group(2)
                            if eid not in self.names:
                                self.names[eid] = m_3p_melee.group(1)
                            if target_id is not None and target_id not in self.names:
                                self.names[target_id] = _text_target_name
                            is_dmg = True
                            _plog.debug(f"  -> DMG_3P_MELEE attacker={m_3p_melee.group(1)}(#{eid}) -> victim={_text_target_name}(#{target_id})")

                    # "hits you" / "slashes you" → target_id is the local player
                    if is_dmg and _text_target_name and _text_target_name.lower() == "you" and target_id is not None:
                        self._mark_local_player(target_id)

                    if is_dmg:
                        if target_id is not None:
                            self.last_attacker[target_id] = eid
                        event["_is_heal"] = False
                        # Extract damage number from text and credit to encounter
                        m_num = re.search(r'for (\d+)', text)
                        if m_num:
                            text_dmg = int(m_num.group(1))
                            now = time.time()
                            # Resolve actual NPC eid — target_id may point to
                            # the player (type 0) for melee EndCasting messages
                            resolved_eid = self._resolve_target_eid(target_id, _text_target_name)
                            if resolved_eid is not None:
                                enc = self._get_or_create_encounter(resolved_eid, now)
                                enc.text_damage += text_dmg
                                if enc.start_time is None:
                                    enc.start_time = now
                                atk_name = self.names.get(eid, f"Entity#{eid}")
                                atk_cls = self.classes.get(eid, "")
                                atk_lvl = self.levels.get(eid)
                                p = enc.get_or_create_player(eid, atk_name, atk_cls, atk_lvl)
                                p['text_dealt'] += text_dmg
                                ability = self._extract_ability_name(text)
                                p['abilities'][ability] = p['abilities'].get(ability, 0) + text_dmg
                                p['ability_counts'][ability] = p['ability_counts'].get(ability, 0) + 1
                                if p['first'] is None:
                                    p['first'] = now
                                p['last'] = now
                                _plog.debug(f"  TEXT_DMG \"{enc.npc_name}\"(#{resolved_eid}) +{text_dmg}dmg by {atk_name}(#{eid}) text_total={enc.text_damage}")
                            else:
                                _plog.debug(f"  TEXT_DMG_UNRESOLVED target_id=#{target_id} name=\"{_text_target_name}\" +{text_dmg}dmg (no NPC match)")
                    else:
                        # Third-person heal: "X's Y heals Z for N Health."
                        m2 = re.match(r"^(.+?)'s .+? heals (.+?) for \d+", text)
                        if m2:
                            if eid not in self.names:
                                self.names[eid] = m2.group(1)
                            heal_target = m2.group(2)
                            if (target_id is not None and target_id not in self.names
                                    and heal_target.lower() not in ("you", "your")):
                                self.names[target_id] = heal_target
                            # "heals you" means target is local player
                            if heal_target.lower() == "you" and target_id is not None:
                                self._mark_local_player(target_id)
                            is_heal = True
                            _plog.debug(f"  -> HEAL healer={m2.group(1)}(#{eid}) -> target={heal_target}(#{target_id})")

                        # Local player heal: "Your X heals Y for N Health."
                        if not is_heal:
                            m2_local = re.match(r"^Your .+? heals (.+?) for \d+", text)
                            if m2_local:
                                self._mark_local_player(eid)
                                heal_target = m2_local.group(1)
                                if (target_id is not None and target_id not in self.names
                                        and heal_target.lower() not in ("you", "your")):
                                    self.names[target_id] = heal_target
                                is_heal = True
                                _plog.debug(f"  -> HEAL_LOCAL caster=#{eid} -> target={heal_target}(#{target_id})")

                        if is_heal:
                            # Clear attacker so heal HP delta isn't misattributed
                            if target_id is not None:
                                atk = self.last_attacker.get(target_id)
                                if atk == eid:
                                    self.last_attacker.pop(target_id, None)
                                    _plog.debug(f"  -> HEAL_CLEAR cleared attacker for #{target_id} (was healer #{eid})")
                            event["_is_heal"] = True
                        else:
                            _plog.debug(f"  -> NO_MATCH (not dmg or heal pattern)")

            elif etype == "ParticleHit":
                # ParticleHit: target_id takes the hit
                target_id = event.get("target_id")
                if target_id is not None:
                    # Keep existing attacker if set, just mark as spell
                    if target_id not in self.last_attacker:
                        self.last_attacker[target_id] = None
                    self.last_attack_type[target_id] = "spell"
                    self.last_ability_name[target_id] = event.get("particle_name", "")

            elif etype == "Autoattack":
                active = event.get("active", False)
                direction = event.get("direction", "IN")
                _plog.debug(f"AUTOATTACK active={active} dir={direction} eid=#{eid}")
                if direction == "OUT":
                    # Note: Autoattack only has "active" field, no entity_id
                    # (eid is always None for outbound). Local player detection
                    # relies on CastAbility/EndCasting/ChatCombat correlation.
                    if active:
                        self._autoattack_on.add("_local")
                    else:
                        self._autoattack_on.discard("_local")

            elif etype == "ChangeTarget":
                target_id = event.get("target_id")
                direction = event.get("direction", "IN")
                tgt_name = self.names.get(target_id, f"#{target_id}") if target_id else "None"
                _plog.debug(f"CHANGETARGET target={tgt_name}(#{target_id}) dir={direction} eid=#{eid} autoattack_on={'_local' in self._autoattack_on}")
                if direction == "OUT" and target_id is not None:
                    # Note: ChangeTarget only has target_id, no entity_id
                    # (eid is always None for outbound). Local player detection
                    # relies on CastAbility/EndCasting/ChatCombat correlation.
                    self.autoattack_target["_local"] = target_id
                    # If autoattack is on, set melee attribution with real eid
                    if "_local" in self._autoattack_on:
                        atk = self._local_player_eid if self._local_player_eid is not None else "_local"
                        self.last_attacker[target_id] = atk
                        self.last_attack_type[target_id] = "melee"
                        self.last_ability_name.pop(target_id, None)

            # HP delta tracking
            if etype in ("UpdateHealth", "UpdateHealthMana"):
                new_hp = event.get("hp")
                if new_hp is None:
                    return None
                max_hp = event.get("max_hp", new_hp)
                self.damage.setdefault(eid, 0)
                self.healing.setdefault(eid, 0)
                old = self.hp.get(eid)
                self.hp[eid] = (new_hp, max_hp)
                # Track for ChatCombat correlation
                self._last_hp_eid = eid
                self._last_hp_time = time.time()
                # Flush pending ChatCombat damage queued for this entity's name.
                # Allow NPCs (type!=0) and also player targets if a PvP encounter
                # already exists for them (so text_damage gets attributed).
                _eid_type = self.entity_types.get(eid)
                _flush_ok = _eid_type != 0 or self._encounter_map.get(eid) is not None
                if self._pending_chat_dmg and _flush_ok:
                    eid_name = self.names.get(eid)
                    if eid_name:
                        flush_now = time.time()
                        remaining = []
                        for tgt_name, txt_dmg, ts, atk_eid, *extra in self._pending_chat_dmg:
                            if tgt_name == eid_name:
                                enc = self._get_or_create_encounter(eid, ts)
                                enc.text_damage += txt_dmg
                                if enc.start_time is None:
                                    enc.start_time = ts
                                if enc.max_hp is None or max_hp > 0:
                                    enc.max_hp = max_hp
                                if atk_eid is not None:
                                    atk_name = self.names.get(atk_eid, f"Entity#{atk_eid}")
                                    atk_cls = self.classes.get(atk_eid, "")
                                    atk_lvl = self.levels.get(atk_eid)
                                    p = enc.get_or_create_player(atk_eid, atk_name, atk_cls, atk_lvl)
                                    p['text_dealt'] += txt_dmg
                                    ab = extra[0] if extra else "Melee"
                                    p['abilities'][ab] = p['abilities'].get(ab, 0) + txt_dmg
                                    p['ability_counts'][ab] = p['ability_counts'].get(ab, 0) + 1
                                    if p['first'] is None:
                                        p['first'] = ts
                                    p['last'] = ts
                                _plog.debug(f"  CHATCOMBAT_FLUSH \"{eid_name}\"(#{eid}) +{txt_dmg}txt_dmg atk={atk_eid} (queued {flush_now - ts:.1f}s ago)")
                            elif flush_now - ts < 10.0:
                                remaining.append((tgt_name, txt_dmg, ts, atk_eid, *(extra if extra else [])))
                            else:
                                _plog.debug(f"  CHATCOMBAT_EXPIRED \"{tgt_name}\" +{txt_dmg}txt_dmg (stale {flush_now - ts:.1f}s)")
                        self._pending_chat_dmg = remaining
                name = self.names.get(eid, f"#{eid}")
                if old is not None:
                    delta = new_hp - old[0]
                    if delta < 0:
                        now = time.time()
                        amt = -delta
                        self.damage[eid] += amt
                        if eid not in self.first_dmg:
                            self.first_dmg[eid] = now
                        self.last_dmg[eid] = now
                        # Credit damage dealt to the attacker
                        atk_eid = self.last_attacker.get(eid)
                        if atk_eid == "_local":
                            atk_eid = self._local_player_eid
                        atk_name_str = self.names.get(atk_eid, f"#{atk_eid}") if atk_eid is not None else "None"
                        if atk_eid is not None:
                            self.damage_dealt[atk_eid] = self.damage_dealt.get(atk_eid, 0) + amt
                            if atk_eid not in self.first_dealt:
                                self.first_dealt[atk_eid] = now
                            self.last_dealt[atk_eid] = now
                        # --- Encounter tracking ---
                        target_type = self.entity_types.get(eid)
                        _plog.debug(f"DMG  {name}(#{eid}) type={target_type} {old[0]}->{new_hp}/{max_hp} amt={amt} attacker={atk_name_str}({atk_eid})")
                        if target_type is not None and target_type != 0:
                            # Known NPC — always create encounter
                            enc = self._get_or_create_encounter(eid, now)
                            enc.total_damage += amt
                            if enc.start_time is None:
                                enc.start_time = now
                            if enc.max_hp is None or max_hp > 0:
                                enc.max_hp = max_hp
                            # Credit to attacker player entry
                            if atk_eid is not None:
                                atk_name = self.names.get(atk_eid, f"Entity#{atk_eid}")
                                atk_cls = self.classes.get(atk_eid, "")
                                atk_lvl = self.levels.get(atk_eid)
                                p = enc.get_or_create_player(atk_eid, atk_name, atk_cls, atk_lvl)
                                p['dealt'] += amt
                                if p['first'] is None:
                                    p['first'] = now
                                p['last'] = now
                                _plog.debug(f"  ENC+ \"{enc.npc_name}\"(#{eid}) +{amt}dmg by {atk_name}({atk_eid}) total={enc.total_damage}")
                            else:
                                _plog.debug(f"  ENC+ \"{enc.npc_name}\"(#{eid}) +{amt}dmg NO_ATTACKER total={enc.total_damage}")
                        elif target_type is None:
                            # Unknown entity (no SpawnEntity received).  Only add
                            # HP damage to an encounter that already exists (created
                            # by ChatCombat text).  Don't create new encounters from
                            # HP deltas alone — prevents false encounters for players
                            # whose SpawnEntity wasn't captured (e.g. Pitborn heals).
                            enc = self._encounter_map.get(eid)
                            if enc is not None and atk_eid is not None:
                                enc.total_damage += amt
                                if enc.max_hp is None or max_hp > 0:
                                    enc.max_hp = max_hp
                                atk_name = self.names.get(atk_eid, f"Entity#{atk_eid}")
                                atk_cls = self.classes.get(atk_eid, "")
                                atk_lvl = self.levels.get(atk_eid)
                                p = enc.get_or_create_player(atk_eid, atk_name, atk_cls, atk_lvl)
                                p['dealt'] += amt
                                if p['first'] is None:
                                    p['first'] = now
                                p['last'] = now
                                _plog.debug(f"  ENC+ \"{enc.npc_name}\"(#{eid}) type=None +{amt}dmg by {atk_name}({atk_eid}) total={enc.total_damage}")
                            else:
                                _plog.debug(f"  ENC_SKIP type=None no_enc={'no_enc' if enc is None else 'no_atk'} #{eid} amt={amt}")
                        elif target_type == 0 and atk_eid is not None:
                            atk_type = self.entity_types.get(atk_eid)
                            if atk_type == 0:
                                # PvP: player attacking player — create encounter for target
                                enc = self._get_or_create_encounter(eid, now)
                                enc.total_damage += amt
                                if enc.start_time is None:
                                    enc.start_time = now
                                if enc.max_hp is None or max_hp > 0:
                                    enc.max_hp = max_hp
                                atk_name = self.names.get(atk_eid, f"Entity#{atk_eid}")
                                atk_cls = self.classes.get(atk_eid, "")
                                atk_lvl = self.levels.get(atk_eid)
                                p = enc.get_or_create_player(atk_eid, atk_name, atk_cls, atk_lvl)
                                p['dealt'] += amt
                                if p['first'] is None:
                                    p['first'] = now
                                p['last'] = now
                                _plog.debug(f"  ENC_PVP \"{enc.npc_name}\"(#{eid}) +{amt}dmg by {atk_name}({atk_eid}) total={enc.total_damage}")
                            elif atk_type is not None and atk_type != 0:
                                # NPC attacking player — credit received on NPC's encounter
                                enc = self._encounter_map.get(atk_eid)
                                if enc:
                                    p_name = self.names.get(eid, f"Entity#{eid}")
                                    p_cls = self.classes.get(eid, "")
                                    p_lvl = self.levels.get(eid)
                                    p = enc.get_or_create_player(eid, p_name, p_cls, p_lvl)
                                    p['received'] += amt
                                    _plog.debug(f"  ENC_RECV player={p_name}(#{eid}) +{amt}recv from NPC \"{enc.npc_name}\"(#{atk_eid})")
                                else:
                                    _plog.debug(f"  ENC_RECV_SKIP player #{eid} hit by #{atk_eid} atk_type={atk_type} has_enc=False")
                            else:
                                _plog.debug(f"  ENC_SKIP target_type={target_type} atk_type={atk_type}")
                        else:
                            _plog.debug(f"  ENC_SKIP target_type={target_type} (no attacker)")
                        return (-delta, 0)
                    elif delta > 0:
                        self.healing[eid] += delta
                        atk_eid_heal = self.last_attacker.get(eid)
                        atk_heal_str = self.names.get(atk_eid_heal, f"#{atk_eid_heal}") if atk_eid_heal is not None else "None"
                        _plog.debug(f"HEAL {name}(#{eid}) {old[0]}->{new_hp}/{max_hp} delta=+{delta} last_attacker={atk_heal_str}({atk_eid_heal})")
                        return (0, delta)
                else:
                    _plog.debug(f"HP_INIT {name}(#{eid}) HP:{new_hp}/{max_hp} (no previous HP, no delta)")
                return None

            return None

    def get_attacker_info(self, target_eid):
        """Return (attacker_name, attack_type, ability_name) for a target entity."""
        with self._lock:
            atk_id = self.last_attacker.get(target_eid)
            atk_type = self.last_attack_type.get(target_eid, "")
            ability = self.last_ability_name.get(target_eid, "")
            if atk_id == "_local":
                return ("_local", atk_type, ability)
            if atk_id is not None:
                name = self.names.get(atk_id, f"Entity#{atk_id}")
                return (name, atk_type, ability)
            # Check if autoattack is on and this is the current target
            local_target = self.autoattack_target.get("_local")
            if local_target == target_eid and "_local" in self._autoattack_on:
                return ("_local", "melee", "")
        return (None, "", "")

    def get_damage_board(self, top_n=20):
        """Return list of (name, total_dmg, dps, class_hid, level) sorted by DPS desc."""
        with self._lock:
            board = []
            for eid in self.damage_dealt:
                d = self.damage_dealt[eid]
                if d <= 0:
                    continue
                name = self.names.get(eid, f"Entity#{eid}")
                first = self.first_dealt.get(eid)
                last = self.last_dealt.get(eid)
                if first is not None and last is not None:
                    elapsed = max(last - first, 1.0)
                    dps = d / elapsed
                else:
                    dps = float(d)
                cls = self.classes.get(eid, "")
                lvl = self.levels.get(eid)
                board.append((name, d, dps, cls, lvl))
            board.sort(key=lambda x: x[2], reverse=True)
            return board[:top_n]

    def _get_or_create_encounter(self, npc_eid, now=None):
        """Get or create an Encounter for the given NPC entity ID.
        Must be called while self._lock is held."""
        enc = self._encounter_map.get(npc_eid)
        if enc is None:
            name = self.names.get(npc_eid, f"Entity#{npc_eid}")
            cls = self.classes.get(npc_eid, "")
            lvl = self.levels.get(npc_eid)
            enc = Encounter(npc_eid, name, cls, lvl)
            self._encounter_map[npc_eid] = enc
            self.encounters.insert(0, enc)
        else:
            # Update name/class/level if better info is now available
            name = self.names.get(npc_eid)
            if name and enc.npc_name.startswith("Entity#"):
                enc.npc_name = name
            cls = self.classes.get(npc_eid, "")
            if cls and not enc.npc_class:
                enc.npc_class = cls
            lvl = self.levels.get(npc_eid)
            if lvl is not None and enc.npc_level is None:
                enc.npc_level = lvl
        return enc

    def get_encounters(self, top_n=30):
        """Return encounters sorted by start_time asc (oldest first, numbered chronologically)."""
        with self._lock:
            active = [e for e in self.encounters
                      if e.best_damage > 0 and not e.npc_name.startswith("Entity#")
                      and e.players]
            active.sort(key=lambda e: e.start_time or 0)
            return active[:top_n]

    def get_encounter_detail(self, npc_eid):
        """Return a single Encounter or None."""
        with self._lock:
            return self._encounter_map.get(npc_eid)

    def reset(self):
        with self._lock:
            self.damage.clear()
            self.healing.clear()
            self.first_dmg.clear()
            self.last_dmg.clear()
            self.damage_dealt.clear()
            self.first_dealt.clear()
            self.last_dealt.clear()
            self.encounters.clear()
            self._encounter_map.clear()
            # Keep names and HP for continuity


# ===================================================================
# Capture + processing pipeline (background threads)
# ===================================================================

class CaptureBackend:
    """Manages all background threads: capture, connections, keys, processing."""

    def __init__(self, event_queue, status_callback=None):
        self._event_queue = event_queue      # parsed combat events -> GUI
        self._status_cb = status_callback    # status string updates -> GUI
        self._stop = threading.Event()
        self._threads = []
        self._pid = None
        self._aes_key = None
        self._hmac_key = None
        self._xor_key = None
        self._local_eps = set()
        self._remote_eps = set()
        self._local_ports = set()
        self._conn_lock = threading.Lock()
        self._key_lock = threading.Lock()
        self._packet_queue = queue.Queue(maxsize=10000)
        self._sock = None
        self._tracker = EntityTracker()

        # API client (initialized in start() if configured)
        self._api = None

        # Player/server identity (loaded from config.json)
        self.player_name = ""
        self.server_name = ""

        # Loot context: track last looted corpse for NPC name association
        self._last_loot_target = {}  # entity_id -> name from tracker

        # Item tracking
        self._items = {}           # hid -> item_record dict
        self._item_drops = []      # list of {hid, name, quantity, timestamp, npc_name}
        self._item_lock = threading.Lock()

        # Trigger tracking
        self._triggers = []              # list of {"pattern": str, "sound": path|None, "sound_label": str}
        self._trigger_counts = {}        # pattern (lower) -> int
        self._trigger_lock = threading.Lock()
        self._trigger_sound_queue = queue.Queue(maxsize=100)
        self._init_triggers()

        # Chat logging
        self._chat_queue = queue.Queue(maxsize=10000)  # chat msgs -> GUI
        self.chat_log_enabled = False  # toggled by GUI button

        # Stats
        self.stats = {
            "packets_captured": 0, "packets_matched": 0,
            "packets_decrypted": 0, "combat_events": 0,
        }

    @property
    def tracker(self):
        return self._tracker

    def _status(self, msg):
        if self._status_cb:
            self._status_cb(msg)

    def start(self):
        self._stop.clear()
        self._init_api_client()
        t = threading.Thread(target=self._lifecycle_loop, daemon=True, name="Lifecycle")
        t.start()
        self._threads.append(t)

    def _load_config(self):
        """Load config.json for player identity and API settings."""
        try:
            config_path = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "config.json")
            import json as _json
            with open(config_path, 'r') as f:
                return _json.load(f)
        except Exception as e:
            _plog.debug(f"Config load failed: {e}")
            return {}

    def _init_api_client(self):
        """Load config and start ApiClient if enabled."""
        cfg = self._load_config()

        # Load player/server identity
        self.player_name = cfg.get("player_name", "")
        self.server_name = cfg.get("server_name", "")
        self._tracker.player_name = self.player_name

        # Start API client if configured
        if cfg.get("api_enabled") and cfg.get("api_url") and cfg.get("api_key"):
            try:
                from parser.api_client import ApiClient
                self._api = ApiClient(
                    api_url=cfg["api_url"],
                    api_key=cfg["api_key"],
                    batch_interval=cfg.get("api_batch_interval", 15),
                )
                self._api.start()
                self._status("API client enabled")
            except ImportError:
                try:
                    import importlib.util
                    spec = importlib.util.spec_from_file_location(
                        "api_client",
                        os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_client.py"))
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    self._api = mod.ApiClient(
                        api_url=cfg["api_url"],
                        api_key=cfg["api_key"],
                        batch_interval=cfg.get("api_batch_interval", 15),
                    )
                    self._api.start()
                    self._status("API client enabled")
                except Exception as e:
                    _plog.debug(f"API client init failed: {e}")
            except Exception as e:
                _plog.debug(f"API client init failed: {e}")

    def stop(self):
        self._stop.set()
        if self._api:
            self._api.stop()
        if self._sock:
            try:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        for t in self._threads:
            t.join(timeout=3)
        self._threads.clear()

    def _lifecycle_loop(self):
        """Main lifecycle: find process -> start capture -> monitor."""
        # Phase 1: Find mnm.exe
        self._status("Waiting...")
        while not self._stop.is_set():
            pid = find_game_pid()
            if pid:
                self._pid = pid
                self._status("Connecting...")
                break
            self._stop.wait(2)

        if self._stop.is_set():
            return

        # Phase 2: Start background threads
        threads = [
            threading.Thread(target=self._conn_loop, daemon=True, name="ConnMon"),
            threading.Thread(target=self._key_loop, daemon=True, name="KeyWatch"),
            threading.Thread(target=self._capture_loop, daemon=True, name="Capture"),
            threading.Thread(target=self._process_loop, daemon=True, name="Process"),
        ]
        for t in threads:
            t.start()
            self._threads.append(t)

        # Phase 3: Monitor process health
        while not self._stop.is_set():
            if not is_process_alive(self._pid):
                self._status("Game exited")
                # Keep running, wait for new process
                while not self._stop.is_set():
                    pid = find_game_pid()
                    if pid:
                        self._pid = pid
                        self._status("Reconnected")
                        break
                    self._stop.wait(2)
            self._stop.wait(3)

    def _conn_loop(self):
        """Poll game connections every 5 seconds."""
        while not self._stop.is_set():
            if self._pid:
                try:
                    local_eps, remote_eps, local_ports = get_game_connections(self._pid)
                    with self._conn_lock:
                        self._local_eps = local_eps
                        self._remote_eps = remote_eps
                        self._local_ports = local_ports
                except Exception:
                    pass
            self._stop.wait(5)

    def _key_loop(self):
        """Poll encryption keys every 5 seconds."""
        first_attempt = True
        while not self._stop.is_set():
            if self._pid:
                try:
                    if first_attempt and not _cached_class_ptr:
                        self._status("Scanning keys...")
                    keys = read_encryption_keys(self._pid)
                    first_attempt = False
                    if keys and keys.get("aes_key"):
                        with self._key_lock:
                            old = self._aes_key
                            self._aes_key = keys["aes_key"]
                            self._hmac_key = keys.get("hmac_key")
                            self._xor_key = keys.get("xor_key")
                        if old != keys["aes_key"]:
                            self._status("")
                except Exception:
                    pass
            self._stop.wait(5)

    def _capture_loop(self):
        """Raw socket capture."""
        try:
            # Auto-detect local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "0.0.0.0"

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._sock.bind((local_ip, 0))
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except (PermissionError, OSError) as e:
            self._status("Capture failed (run as Admin)")
            return

        while not self._stop.is_set():
            try:
                self._sock.settimeout(1.0)
                data = self._sock.recvfrom(65535)[0]
                self.stats["packets_captured"] += 1
                try:
                    self._packet_queue.put_nowait(data)
                except queue.Full:
                    try:
                        self._packet_queue.get_nowait()
                    except queue.Empty:
                        pass
                    self._packet_queue.put_nowait(data)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue

    def _matches_game(self, src_ip, src_port, dst_ip, dst_port):
        with self._conn_lock:
            if (src_ip, src_port) in self._local_eps:
                return True
            if (dst_ip, dst_port) in self._local_eps:
                return True
            if src_port in self._local_ports:
                return True
            if dst_port in self._local_ports:
                return True
            if (src_ip, src_port) in self._remote_eps:
                return True
            if (dst_ip, dst_port) in self._remote_eps:
                return True
        return False

    def _get_direction(self, src_ip, src_port, dst_ip, dst_port):
        with self._conn_lock:
            if (src_ip, src_port) in self._local_eps or src_port in self._local_ports:
                return "OUT"
            return "IN"

    def _process_loop(self):
        """Pull raw packets, parse, decrypt, extract combat + loot events."""
        ALL_MSG_IDS = COMBAT_MSG_IDS | LOOT_MSG_IDS | ITEM_MSG_IDS
        _seen_unknown = set()  # Track first-seen unknown msg IDs
        while not self._stop.is_set():
            try:
                raw = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            # Parse IP header
            ip = parse_ip_header(raw)
            if not ip:
                continue
            proto_num, src_ip, dst_ip, ihl = ip
            transport = raw[ihl:]

            if proto_num == 17:  # UDP
                result = parse_udp_header(transport)
            elif proto_num == 6:  # TCP
                result = parse_tcp_header(transport)
            else:
                continue
            if not result:
                continue
            src_port, dst_port, payload = result

            if not payload or not self._matches_game(src_ip, src_port, dst_ip, dst_port):
                continue

            self.stats["packets_matched"] += 1
            direction = self._get_direction(src_ip, src_port, dst_ip, dst_port)

            # Decrypt
            with self._key_lock:
                aes_key = self._aes_key
                hmac_key = self._hmac_key
                xor_key = self._xor_key

            if not aes_key or len(payload) < 36:
                continue

            plaintext = decrypt_packet(payload, aes_key, hmac_key, xor_key)
            if not plaintext:
                continue

            self.stats["packets_decrypted"] += 1

            # Extract game messages
            messages = extract_game_messages(plaintext)
            for msg_id, body in messages:
                msg_name = get_message_name(msg_id)

                # Log item-related messages with body hex for discovery
                if msg_id in ITEM_MSG_IDS:
                    body_hex = body.hex(' ') if body else ''
                    _plog.debug(f"MSG_ITEM 0x{msg_id:04X} {msg_name} dir={direction} len={len(body)} body={body_hex}")
                elif msg_id in ALL_MSG_IDS:
                    _plog.debug(f"MSG_IN 0x{msg_id:04X} {msg_name} dir={direction} body_len={len(body)}")
                else:
                    # Log first occurrence of any unknown message ID
                    if msg_id not in _seen_unknown:
                        _seen_unknown.add(msg_id)
                        body_hex = body[:32].hex(' ') if body else ''
                        _plog.debug(f"MSG_UNKNOWN_NEW 0x{msg_id:04X} dir={direction} len={len(body)} body={body_hex}")

                if msg_id not in ALL_MSG_IDS:
                    continue

                # Loot/item messages — process known loot opcodes
                if msg_id in LOOT_MSG_IDS:
                    loot_event = parse_loot_event(msg_id, body, direction)
                    if loot_event:
                        self._handle_loot_event(loot_event)
                    continue
                if msg_id in ITEM_MSG_IDS:
                    continue  # logged above, not yet parsed

                # Combat messages
                event = parse_combat_event(msg_id, body, direction)
                if not event:
                    _plog.debug(f"  PARSE_FAIL 0x{msg_id:04X} {msg_name} body={body[:32].hex()}")
                    continue

                # Chat messages (non-combat channels) — queue for chat log
                if event.get("type") == "ChatMessage":
                    self._check_triggers(event.get("text", ""))
                    if self.chat_log_enabled:
                        try:
                            self._chat_queue.put_nowait(event)
                        except queue.Full:
                            pass
                    continue

                self.stats["combat_events"] += 1
                _plog.debug(f"  PARSED type={event.get('type')} eid={event.get('entity_id')} target={event.get('target_id')}")

                # Track entity state (all events, for damage meter + attribution)
                deltas = self._tracker.process(event)

                # Queue to API: Die events, SpawnEntity (hostile NPCs)
                if self._api:
                    etype = event.get("type", "")
                    if etype == "Die":
                        self._api_queue_kill(event)
                    elif etype == "SpawnEntity":
                        self._api_queue_npc(event)

                # Feed display — EndCasting combat text, kills, heals, HP changes
                etype = event.get("type", "")

                if etype == "Die":
                    event["_display"] = self._format_event(event)
                    self._check_triggers(event.get("_display", ""))
                    try:
                        self._event_queue.put_nowait(event)
                    except queue.Full:
                        pass

                elif etype == "EndCasting":
                    text = event.get("text", "")
                    if text:
                        self._check_triggers(text)
                        display = self._format_event(event)
                        if display:
                            event["_display"] = display
                            if event.get("_is_heal"):
                                event["type"] = "EndCasting_heal"
                            try:
                                self._event_queue.put_nowait(event)
                            except queue.Full:
                                pass

                elif etype == "ChatCombat":
                    text = event.get("text", "")
                    if text:
                        self._check_triggers(text)
                        self._check_chat_loot(text)
                        event["_display"] = _strip_msg_type_byte(text)
                        event["type"] = "EndCasting"  # reuse same feed tag color
                        try:
                            self._event_queue.put_nowait(event)
                        except queue.Full:
                            pass

                elif etype in ("UpdateHealth", "UpdateHealthMana") and deltas:
                    dmg, heal = deltas
                    eid = event.get("entity_id")
                    # Only show HP changes for entities in encounters or the local player
                    t = self._tracker
                    relevant = (eid is not None and
                                (eid in t._encounter_map or
                                 eid == t._local_player_eid))
                    if relevant and (dmg > 0 or heal > 0):
                        name = t.get_name_short(eid)
                        hp = event.get("hp", 0)
                        max_hp = event.get("max_hp", 0)
                        if dmg > 0:
                            hp_event = {
                                "type": "hp_damage",
                                "_display": f"  {name} -{dmg} ({hp}/{max_hp})",
                            }
                        else:
                            hp_event = {
                                "type": "hp_heal",
                                "_display": f"  {name} +{heal} ({hp}/{max_hp})",
                            }
                        try:
                            self._event_queue.put_nowait(hp_event)
                        except queue.Full:
                            pass

    def _handle_loot_event(self, event):
        """Process a loot/item message — queue to API and show in feed with full stats."""
        if not event:
            return
        etype = event.get("type", "")

        if etype == "LootItemFromCorpse":
            # Outbound: player is looting. Record the target entity for NPC name lookup.
            eid = event.get("entity_id")
            if eid is not None:
                name = self._tracker.get_name(eid)
                self._last_loot_target[eid] = name

        elif etype == "AddItemToInventory":
            item_rec = event.get("item_record")
            item_hid = event.get("item_hid") or (item_rec or {}).get("hid")
            # Try to get item name: from record, from existing data, or from HID
            item_name = event.get("item_name") or (item_rec or {}).get("name")
            if not item_name and item_hid:
                # Check if we already have this item from a prior ItemInformation (0x0080)
                with self._item_lock:
                    existing = self._items.get(item_hid)
                if existing:
                    item_name = existing.get("name")
                    if not item_rec:
                        item_rec = existing  # use cached stats for display
            if not item_name and item_hid:
                # Derive display name from HID: "beetle_meat" → "Beetle Meat"
                item_name = item_hid.replace('_', ' ').title()

            # Queue item data to API
            if self._api and item_rec and item_rec.get("hid"):
                self._api.queue_item(item_rec)

            # Queue loot event to API
            npc_name = None
            if self._last_loot_target:
                for _, n in self._last_loot_target.items():
                    npc_name = n
            if self._api and item_name:
                self._api.queue_loot_event({
                    "item_hid": item_hid,
                    "item_name": item_name,
                    "npc_name": npc_name,
                    "quantity": event.get("quantity", 1),
                })

            # Store in item tracker
            with self._item_lock:
                if item_rec and item_hid:
                    self._items[item_hid] = item_rec
                # Only add drop if we have a real name — ChatCombat loot
                # text (via _check_chat_loot) already captures drops with
                # proper names, so skip unknown items to avoid "?" duplicates.
                if item_name:
                    self._item_drops.append({
                        "hid": item_hid,
                        "name": item_name,
                        "quantity": event.get("quantity", 1),
                        "timestamp": time.time(),
                        "npc_name": npc_name,
                    })

            # Build loot display with full item stats
            player = self.player_name or "You"
            lines = [f"{player} looted: {item_name or '?'}"]
            if event.get("quantity", 1) > 1:
                lines[0] += f" x{event['quantity']}"

            # Append item stats if we have the ItemRecord
            if item_rec:
                stats_line = self._format_item_stats(item_rec)
                if stats_line:
                    lines.append(stats_line)
                desc = item_rec.get("description")
                if desc:
                    lines.append(f"  \"{desc}\"")
                effects = item_rec.get("effects")
                if effects and isinstance(effects, list):
                    for eff in effects:
                        lines.append(f"  Effect: {eff}")

            event["_display"] = "\n".join(lines)
            event["type"] = "AddItemToInventory"
            try:
                self._event_queue.put_nowait(event)
            except queue.Full:
                pass

        elif etype == "ItemInformation":
            item_rec = event.get("item_record")
            if item_rec and item_rec.get("hid"):
                with self._item_lock:
                    self._items[item_rec["hid"]] = item_rec
                if self._api:
                    self._api.queue_item(item_rec)
                if _plog.isEnabledFor(logging.DEBUG):
                    _plog.debug(
                        f"ITEM_INFO hid={item_rec.get('hid')} "
                        f"name={item_rec.get('name')} "
                        f"type={item_rec.get('item_type')} "
                        f"slot={item_rec.get('slot_mask')} "
                        f"lvl={item_rec.get('required_level')} "
                        f"dmg={item_rec.get('damage')} "
                        f"delay={item_rec.get('delay')} "
                        f"ac={item_rec.get('ac')} "
                        f"str={item_rec.get('strength')} sta={item_rec.get('stamina')} "
                        f"dex={item_rec.get('dexterity')} agi={item_rec.get('agility')} "
                        f"int={item_rec.get('intelligence')} wis={item_rec.get('wisdom')} "
                        f"cha={item_rec.get('charisma')} "
                        f"hp={item_rec.get('health')} mana={item_rec.get('mana')} "
                        f"hp_regen={item_rec.get('health_regen')} mana_regen={item_rec.get('mana_regen')} "
                        f"m_haste={item_rec.get('melee_haste')} r_haste={item_rec.get('ranged_haste')} "
                        f"s_haste={item_rec.get('spell_haste')} "
                        f"weight={item_rec.get('weight')} "
                        f"nodrop={item_rec.get('no_drop')} unique={item_rec.get('is_unique')} "
                        f"magic={item_rec.get('is_magic')} "
                        f"stack={item_rec.get('stack_size')} charges={item_rec.get('charges')} "
                        f"effects={item_rec.get('effects')} "
                        f"desc={item_rec.get('description')!r}"
                    )

    # Regex for loot text: "[item|hid|Name]" and "from NPC's corpse"
    _LOOT_ITEM_RE = re.compile(
        r'\[item\|([^|]+)\|([^\]]+)\]')
    _LOOT_FROM_RE = re.compile(
        r"from (.+?)(?:'s)? corpse", re.IGNORECASE)
    _LOOT_WHO_RE = re.compile(
        r"^--(?:You|([\w]+)) loots? ")

    def _check_chat_loot(self, text):
        """Parse [item|hid|Name] from ChatCombat loot text and store as item drop."""
        m = self._LOOT_ITEM_RE.search(text)
        if not m:
            return
        item_hid = m.group(1)
        item_name = m.group(2)

        # Extract NPC name from "from X's corpse"
        npc_name = None
        fm = self._LOOT_FROM_RE.search(text)
        if fm:
            npc_name = fm.group(1)

        # Extract looter name: "--You loot" or "--PlayerName loots"
        looter = None
        lm = self._LOOT_WHO_RE.match(text)
        if lm:
            looter = lm.group(1)  # None means "You" matched -> local player
            if looter is None:
                looter = self.player_name or "You"

        with self._item_lock:
            self._item_drops.append({
                "hid": item_hid,
                "name": item_name,
                "quantity": 1,
                "timestamp": time.time(),
                "npc_name": npc_name,
                "looter": looter,
            })

        _plog.debug(f"LOOT_CHAT item={item_name} hid={item_hid} npc={npc_name} looter={looter}")

    def _format_item_stats(self, item):
        """Format an ItemRecord dict into a compact stats summary string."""
        parts = []
        # Core combat stats
        if item.get("damage"):
            delay = item.get("delay")
            if delay:
                parts.append(f"DMG:{item['damage']}/{delay}")
            else:
                parts.append(f"DMG:{item['damage']}")
        if item.get("ac"):
            parts.append(f"AC:{item['ac']}")
        # Primary stats (only show non-zero)
        stat_map = [
            ("strength", "STR"), ("stamina", "STA"), ("dexterity", "DEX"),
            ("agility", "AGI"), ("intelligence", "INT"), ("wisdom", "WIS"),
            ("charisma", "CHA"),
        ]
        for key, label in stat_map:
            v = item.get(key)
            if v and v != 0:
                parts.append(f"{label}:{v:+d}")
        # HP/Mana
        if item.get("health"):
            parts.append(f"HP:{item['health']:+d}")
        if item.get("mana"):
            parts.append(f"Mana:{item['mana']:+d}")
        if item.get("health_regen"):
            parts.append(f"HPR:{item['health_regen']:+d}")
        if item.get("mana_regen"):
            parts.append(f"MR:{item['mana_regen']:+d}")
        # Haste
        if item.get("melee_haste"):
            parts.append(f"MHaste:{item['melee_haste']:+d}")
        if item.get("ranged_haste"):
            parts.append(f"RHaste:{item['ranged_haste']:+d}")
        if item.get("spell_haste"):
            parts.append(f"SHaste:{item['spell_haste']:+d}")
        # Resists
        resist_map = [
            ("resist_fire", "FR"), ("resist_cold", "CR"), ("resist_poison", "PR"),
            ("resist_disease", "DR"), ("resist_magic", "MR"), ("resist_arcane", "AR"),
            ("resist_nature", "NR"), ("resist_holy", "HR"),
        ]
        for key, label in resist_map:
            v = item.get(key)
            if v and v != 0:
                parts.append(f"{label}:{v:+d}")
        # Weight
        if item.get("weight"):
            parts.append(f"WT:{item['weight']:.1f}")
        # Flags
        flags = []
        if item.get("no_drop"):
            flags.append("NO DROP")
        if item.get("is_unique"):
            flags.append("UNIQUE")
        if item.get("is_magic"):
            flags.append("MAGIC")
        if flags:
            parts.append(" ".join(flags))

        if parts:
            return "  " + " | ".join(parts)
        return ""

    def get_item_summary(self):
        """Aggregate item drops by name -> [{hid, name, count}] sorted by count desc."""
        with self._item_lock:
            counts = {}  # name -> {hid, name, count}
            for drop in self._item_drops:
                name = drop["name"]
                if name not in counts:
                    counts[name] = {"hid": drop["hid"], "name": name, "count": 0}
                counts[name]["count"] += drop.get("quantity", 1)
            return sorted(counts.values(), key=lambda x: x["count"], reverse=True)

    def get_item_record(self, hid):
        """Return full ItemRecord dict for a given HID."""
        with self._item_lock:
            return self._items.get(hid)

    def get_item_drops_for(self, name):
        """Return drop events for an item name (for drop history)."""
        with self._item_lock:
            return [d for d in self._item_drops if d["name"] == name]

    def reset_items(self):
        """Clear all tracked items and drops."""
        with self._item_lock:
            self._items.clear()
            self._item_drops.clear()

    # --- Triggers ---

    def _init_triggers(self):
        """Load triggers from disk on startup."""
        saved = _load_triggers()
        for t in saved:
            pat = t.get("pattern", "")
            if pat:
                self._triggers.append({
                    "pattern": pat,
                    "sound": t.get("sound"),
                    "sound_label": t.get("sound_label", "(none)"),
                })
                self._trigger_counts[pat.lower()] = 0

    def add_trigger(self, pattern, sound_path, sound_label):
        """Thread-safe add trigger, dedup by pattern (case-insensitive). Saves to disk."""
        key = pattern.lower()
        with self._trigger_lock:
            for t in self._triggers:
                if t["pattern"].lower() == key:
                    return  # duplicate
            self._triggers.append({
                "pattern": pattern,
                "sound": sound_path,
                "sound_label": sound_label,
            })
            self._trigger_counts[key] = 0
            _save_triggers(self._triggers)

    def remove_trigger(self, pattern):
        """Thread-safe remove trigger by pattern. Saves to disk."""
        key = pattern.lower()
        with self._trigger_lock:
            self._triggers = [t for t in self._triggers if t["pattern"].lower() != key]
            self._trigger_counts.pop(key, None)
            _save_triggers(self._triggers)

    def get_trigger_snapshot(self):
        """Return [(pattern, sound_label, count), ...] copy."""
        with self._trigger_lock:
            return [(t["pattern"], t["sound_label"], self._trigger_counts.get(t["pattern"].lower(), 0))
                    for t in self._triggers]

    def _check_triggers(self, text):
        """Check text against all triggers. Increment counts and queue sounds."""
        if not text:
            return
        text_lower = text.lower()
        with self._trigger_lock:
            for t in self._triggers:
                if t["pattern"].lower() in text_lower:
                    self._trigger_counts[t["pattern"].lower()] = \
                        self._trigger_counts.get(t["pattern"].lower(), 0) + 1
                    if t["sound"]:
                        try:
                            self._trigger_sound_queue.put_nowait(t["sound"])
                        except queue.Full:
                            pass

    def _api_queue_kill(self, event):
        """Queue a kill event to the API from a Die message."""
        if not self._api:
            return
        eid = event.get("entity_id")
        killer_id = event.get("killer_id")
        t = self._tracker

        target_name = t.get_name(eid) if eid else None
        killer_name = t.get_name(killer_id) if killer_id else None

        # Get damage board snapshot for this kill
        with t._lock:
            target_class = t.classes.get(eid, "")
            target_level = t.levels.get(eid)
            total_dmg = t.damage.get(eid, 0)
            first = t.first_dmg.get(eid)
            last = t.last_dmg.get(eid)
            killer_class = t.classes.get(killer_id, "")
            killer_level = t.levels.get(killer_id)

        duration = max(last - first, 1.0) if first and last else 0
        dps = total_dmg / duration if duration > 0 else 0

        self._api.queue_combat_event({
            "event_type": "kill",
            "source_name": killer_name,
            "source_class": killer_class,
            "source_level": killer_level,
            "target_name": target_name,
            "target_class": target_class,
            "target_level": target_level,
            "damage_total": total_dmg,
            "dps": round(dps, 1),
            "duration_secs": round(duration, 1),
            "killer_name": killer_name,
        })

    def _api_queue_npc(self, event):
        """Queue an NPC from a SpawnEntity event to the API."""
        if not self._api:
            return
        name = event.get("name")
        if not name:
            return
        self._api.queue_npc({
            "entity_name": name,
            "entity_type": event.get("entity_type"),
            "class_hid": event.get("class_hid", ""),
            "level": event.get("level"),
            "max_health": event.get("max_hp"),
            "is_hostile": event.get("is_hostile", False),
        })

    def _format_event(self, event):
        """Format event for the combat feed.
        Uses EndCasting text (the game's own combat log) for damage/heal messages.
        Shows: combat text (damage, heals, abilities), kills, loot.
        """
        t = self._tracker
        etype = event.get("type", "")
        eid = event.get("entity_id")

        if etype == "Die":
            target_name = t.get_name_short(eid) if eid is not None else "???"
            killer_id = event.get("killer_id")
            killer_name = t.get_name_short(killer_id) if killer_id is not None else "???"
            feign = " (feign death)" if event.get("feign") else ""
            return f"{killer_name} killed {target_name}{feign}"

        elif etype == "EndCasting":
            text = event.get("text", "")
            if not text:
                return None
            # Strip trailing message-type byte the game appends after the period
            text = _strip_msg_type_byte(text)
            # Skip non-combat messages (aggro, interrupts) unless they
            # contain damage/heal info — keep those for context
            if not text:
                return None
            return text

        return None


# ===================================================================
# GUI
# ===================================================================

COLORS = {
    'bg':        '#000000',  'bg_darker': '#0a0a0a',
    'fg':        '#cdd6f4',  'fg_dim':    '#6c7086',
    'red':       '#f38ba8',  'green':     '#a6e3a1',
    'blue':      '#89b4fa',  'yellow':    '#f9e2af',
    'peach':     '#fab387',  'mauve':     '#cba6f7',
    'teal':      '#94e2d5',  'surface':   '#313244',
    'border':    '#45475a',
}

EVENT_TAG_COLORS = {
    'EndCasting':        'fg',
    'EndCasting_heal':   'green',
    'Die':               'red',
    'hp_damage':         'peach',
    'hp_heal':           'green',
    'AddItemToInventory':'yellow',  'LootItemFromCorpse':'yellow',
    'ItemInformation':   'fg_dim',
}

# Class HID → readable name mapping (from ClassIconMapping tooltip in game DLL)
CLASS_HID_NAMES = {
    "arc": "Arcanist", "brd": "Bard", "bst": "Beastlord", "clr": "Cleric",
    "dru": "Druid", "ele": "Elementalist", "enc": "Enchanter", "ftr": "Fighter",
    "mnk": "Monk", "nec": "Necromancer", "pal": "Paladin", "ran": "Ranger",
    "rng": "Ranger", "rog": "Rogue", "shd": "Shadow Knight", "shm": "Shaman",
    "war": "Warrior", "wiz": "Wizard", "alc": "Alchemist", "smn": "Summoner",
}

def _class_label(hid):
    """Return uppercase short class code (e.g. 'pal' → 'PAL')."""
    if not hid:
        return ""
    return hid.upper()

TRIGGERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "triggers.json")

TRIGGER_SOUNDS = [
    ("(none)", None),
    ("Ding", r"C:\Windows\Media\Windows Ding.wav"),
    ("Notify", r"C:\Windows\Media\Windows Notify System Generic.wav"),
    ("Chimes", r"C:\Windows\Media\chimes.wav"),
    ("Chord", r"C:\Windows\Media\chord.wav"),
    ("Tada", r"C:\Windows\Media\tada.wav"),
    ("Notify Email", r"C:\Windows\Media\Windows Notify Email.wav"),
    ("Exclamation", r"C:\Windows\Media\Windows Exclamation.wav"),
    ("Critical Stop", r"C:\Windows\Media\Windows Critical Stop.wav"),
    ("Alarm", r"C:\Windows\Media\Alarm01.wav"),
    ("Ring", r"C:\Windows\Media\Ring05.wav"),
]


def _load_triggers():
    """Read triggers from triggers.json. Returns list of dicts."""
    try:
        with open(TRIGGERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return []


def _save_triggers(triggers):
    """Write triggers list to triggers.json."""
    try:
        with open(TRIGGERS_FILE, "w", encoding="utf-8") as f:
            json.dump(triggers, f, indent=2)
    except OSError:
        pass


class CombatApp(tk.Tk):
    MAX_FEED_LINES = 2000

    def __init__(self):
        super().__init__()
        self.title(f"ZekParser {APP_VERSION}")
        self.geometry("425x300")
        self.configure(bg='black')
        self.minsize(350, 220)
        self.attributes('-topmost', True)
        self.attributes('-alpha', 0.85)

        self._event_queue = queue.Queue(maxsize=50000)
        self._status_queue = queue.Queue(maxsize=100)
        self._feed_line_count = 0
        self._paused = False
        self._pending_events = []
        self._combat_log = []  # [(timestamp, type, text), ...] for CSV export

        # Chat log
        self._chat_log_file = None   # open file handle when logging
        self._chat_log_path = None   # path for status display

        self._build_ui()

        # Start backend
        self._backend = CaptureBackend(
            self._event_queue,
            status_callback=lambda msg: self._status_queue.put(msg),
        )
        self._backend.start()

        # Update title and header with player/server info
        pn = self._backend.player_name
        sn = self._backend.server_name
        if pn or sn:
            title = f"ZekParser {APP_VERSION}"
            if pn:
                title += f" \u2014 {pn}"
            if sn:
                title += f" [{sn}]"
            self.title(title)
            # Show in header bar
            tag = ""
            if pn:
                tag += pn
            if sn:
                tag += f" | {sn}"
            self._player_label.configure(text=tag)

        self._poll_id = self.after(80, self._poll_queue)
        self._meter_id = self.after(1000, self._refresh_meter)
        self._item_id = self.after(1000, self._refresh_items)
        self._trigger_id = self.after(500, self._refresh_triggers)
        self._xp_id = self.after(1000, self._refresh_experience)
        self._stats_id = self.after(3000, self._refresh_stats)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('Dark.TFrame', background=COLORS['bg'])
        style.configure('Dark.TButton', background=COLORS['surface'], foreground=COLORS['fg'])
        style.map('Dark.TButton', background=[('active', COLORS['border'])])
        style.configure('ActiveTab.TButton', background=COLORS['border'], foreground=COLORS['fg'])
        style.map('ActiveTab.TButton', background=[('active', COLORS['border'])])
        style.configure('Dark.TCombobox',
                        fieldbackground=COLORS['surface'],
                        background=COLORS['surface'],
                        foreground=COLORS['fg'],
                        arrowcolor=COLORS['fg'],
                        selectbackground=COLORS['surface'],
                        selectforeground=COLORS['fg'])
        style.map('Dark.TCombobox',
                   fieldbackground=[('readonly', COLORS['surface'])],
                   selectbackground=[('readonly', COLORS['surface'])],
                   selectforeground=[('readonly', COLORS['fg'])],
                   foreground=[('readonly', COLORS['fg'])])
        self.option_add('*TCombobox*Listbox.background', COLORS['surface'])
        self.option_add('*TCombobox*Listbox.foreground', COLORS['fg'])
        self.option_add('*TCombobox*Listbox.selectBackground', COLORS['border'])
        self.option_add('*TCombobox*Listbox.selectForeground', COLORS['fg'])

        # Top status bar
        top = tk.Frame(self, bg=COLORS['bg_darker'], height=28)
        top.pack(fill=tk.X)
        top.pack_propagate(False)

        self._status_dot = tk.Label(top, text="\u25CF", bg=COLORS['bg_darker'],
                                     fg=COLORS['yellow'], font=('Segoe UI', 12))
        self._status_dot.pack(side=tk.LEFT, padx=(8, 4))

        self._status_label = tk.Label(top, text="Initializing...",
                                       bg=COLORS['bg_darker'], fg=COLORS['fg'],
                                       font=('Consolas', 9), anchor=tk.W)
        self._status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._player_label = tk.Label(top, text="", bg=COLORS['bg_darker'],
                                       fg=COLORS['teal'], font=('Consolas', 9))
        self._player_label.pack(side=tk.RIGHT, padx=(0, 8))

        self._left_visible = False
        self._toggle_left_btn = tk.Button(
            top, text="\u25B6", bg=COLORS['surface'], fg=COLORS['fg'],
            activebackground=COLORS['border'], activeforeground=COLORS['fg'],
            font=('Consolas', 9, 'bold'), relief=tk.RAISED, bd=1, padx=5, pady=1,
            command=self._toggle_left_panel)
        self._toggle_left_btn.pack(side=tk.RIGHT, padx=(0, 4))

        # Main area — start with left hidden, right takes full width
        main = tk.Frame(self, bg=COLORS['bg'])
        main.pack(fill=tk.BOTH, expand=True, padx=6, pady=(3, 0))
        self._main_frame = main
        main.columnconfigure(0, weight=0, uniform='')
        main.columnconfigure(1, weight=0)  # divider
        main.columnconfigure(2, weight=1, uniform='')
        main.rowconfigure(0, weight=1)

        # Divider (hidden by default)
        self._divider = tk.Frame(main, bg=COLORS['border'], width=4)
        self._divider.grid(row=0, column=1, sticky='ns')
        self._divider.grid_remove()

        # Left: combat feed / item tracker (hidden by default)
        left = tk.Frame(main, bg=COLORS['bg'])
        left.grid(row=0, column=0, sticky='nsew')
        left.grid_remove()
        self._left_frame = left

        header_left = tk.Frame(left, bg=COLORS['bg'])
        header_left.pack(fill=tk.X)
        self._header_left = header_left

        # Tab dropdown (left side)
        self._left_view_var = tk.StringVar(value="Feed")
        self._left_combo = ttk.Combobox(
            header_left, textvariable=self._left_view_var,
            values=["Feed", "Items", "Triggers", "Experience"],
            state='readonly', style='Dark.TCombobox', width=10,
            font=('Segoe UI', 9))
        self._left_combo.pack(side=tk.LEFT, padx=4, pady=2)
        self._left_combo.bind('<<ComboboxSelected>>', self._on_left_view_change)

        self._pause_var = tk.BooleanVar(value=False)
        self._chatlog_var = tk.BooleanVar(value=False)

        self._export_left_btn = ttk.Button(
            header_left, text="Export", style='Dark.TButton',
            command=self._export_left)
        self._export_left_btn.pack(side=tk.RIGHT, padx=4)

        self._copy_left_btn = ttk.Button(
            header_left, text="Copy", style='Dark.TButton',
            command=self._copy_left)
        self._copy_left_btn.pack(side=tk.RIGHT, padx=4)

        self._item_back_btn = ttk.Button(
            header_left, text="< Back", style='Dark.TButton',
            command=self._on_detail_back)
        # Hidden by default — shown in item detail view

        # Feed text widget + scrollbars (stored for pack/forget toggling)
        self._feed = tk.Text(left, bg=COLORS['bg_darker'], fg=COLORS['fg'],
                             font=('Consolas', 9), wrap=tk.NONE, state=tk.DISABLED,
                             borderwidth=0, highlightthickness=0, padx=4, pady=4)
        self._feed_sy = tk.Scrollbar(left, orient=tk.VERTICAL, command=self._feed.yview)
        self._feed_sx = tk.Scrollbar(left, orient=tk.HORIZONTAL, command=self._feed.xview)
        self._feed.configure(yscrollcommand=self._feed_sy.set,
                             xscrollcommand=self._feed_sx.set)
        self._feed_sy.pack(side=tk.RIGHT, fill=tk.Y)
        self._feed_sx.pack(side=tk.BOTTOM, fill=tk.X)
        self._feed.pack(fill=tk.BOTH, expand=True)

        # Tags for color coding
        for tag, color_key in EVENT_TAG_COLORS.items():
            self._feed.tag_configure(tag, foreground=COLORS[color_key])
        self._feed.tag_configure('damage_delta', foreground=COLORS['red'])
        self._feed.tag_configure('heal_delta', foreground=COLORS['green'])

        # Item tracker view (created but not packed)
        self._item_view = tk.Text(left, bg=COLORS['bg_darker'], fg=COLORS['fg'],
                                  font=('Consolas', 9), wrap=tk.NONE, state=tk.DISABLED,
                                  borderwidth=0, highlightthickness=0, padx=4, pady=4,
                                  cursor="arrow")
        self._item_scroll_y = tk.Scrollbar(left, orient=tk.VERTICAL,
                                           command=self._item_view.yview)
        self._item_scroll_x = tk.Scrollbar(left, orient=tk.HORIZONTAL,
                                           command=self._item_view.xview)
        self._item_view.configure(yscrollcommand=self._item_scroll_y.set,
                                  xscrollcommand=self._item_scroll_x.set)

        # Item view tags
        self._item_view.tag_configure('item_name', foreground=COLORS['yellow'])
        self._item_view.tag_configure('item_count', foreground=COLORS['fg_dim'])
        self._item_view.tag_configure('stat_label', foreground=COLORS['teal'])
        self._item_view.tag_configure('stat_value', foreground=COLORS['fg'])
        self._item_view.tag_configure('stat_positive', foreground=COLORS['green'])
        self._item_view.tag_configure('stat_negative', foreground=COLORS['red'])
        self._item_view.tag_configure('flag', foreground=COLORS['mauve'])
        self._item_view.tag_configure('effect', foreground=COLORS['peach'])
        self._item_view.tag_configure('description', foreground=COLORS['fg_dim'])
        self._item_view.tag_configure('header_line', foreground=COLORS['fg_dim'])
        self._item_view.tag_configure('npc_name', foreground=COLORS['blue'])
        self._item_view.tag_configure('compact_stats', foreground=COLORS['fg_dim'])

        # Triggers view (created but not packed)
        self._trigger_add_frame = tk.Frame(left, bg=COLORS['bg_darker'])

        tk.Label(self._trigger_add_frame, text="Pattern:",
                 bg=COLORS['bg_darker'], fg=COLORS['fg'],
                 font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(4, 2))
        self._trigger_pattern_entry = tk.Entry(
            self._trigger_add_frame, bg=COLORS['surface'], fg=COLORS['fg'],
            insertbackground=COLORS['fg'], font=('Consolas', 9),
            relief=tk.FLAT, width=20)
        self._trigger_pattern_entry.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

        tk.Label(self._trigger_add_frame, text="Sound:",
                 bg=COLORS['bg_darker'], fg=COLORS['fg'],
                 font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(6, 2))
        self._trigger_sound_var = tk.StringVar(value="(none)")
        sound_names = [s[0] for s in TRIGGER_SOUNDS]
        self._trigger_sound_menu = ttk.Combobox(
            self._trigger_add_frame, textvariable=self._trigger_sound_var,
            values=sound_names, state="readonly", width=14,
            font=('Segoe UI', 8))
        self._trigger_sound_menu.pack(side=tk.LEFT, padx=2)

        self._trigger_preview_btn = ttk.Button(
            self._trigger_add_frame, text="\u25B6", style='Dark.TButton',
            command=self._preview_trigger_sound, width=2)
        self._trigger_preview_btn.pack(side=tk.LEFT, padx=2)

        self._trigger_add_btn = ttk.Button(
            self._trigger_add_frame, text="Add", style='Dark.TButton',
            command=self._add_trigger)
        self._trigger_add_btn.pack(side=tk.LEFT, padx=(2, 4))

        self._trigger_view = tk.Text(left, bg=COLORS['bg_darker'], fg=COLORS['fg'],
                                     font=('Consolas', 9), wrap=tk.NONE, state=tk.DISABLED,
                                     borderwidth=0, highlightthickness=0, padx=4, pady=4,
                                     cursor="arrow")
        self._trigger_scroll_y = tk.Scrollbar(left, orient=tk.VERTICAL,
                                              command=self._trigger_view.yview)
        self._trigger_view.configure(yscrollcommand=self._trigger_scroll_y.set)

        # Trigger view tags
        self._trigger_view.tag_configure('pattern', foreground=COLORS['yellow'])
        self._trigger_view.tag_configure('count', foreground=COLORS['green'],
                                         font=('Consolas', 9, 'bold'))
        self._trigger_view.tag_configure('sound', foreground=COLORS['fg_dim'])
        self._trigger_view.tag_configure('header_line', foreground=COLORS['fg_dim'])
        self._trigger_view.tag_configure('help_text', foreground=COLORS['fg_dim'])

        # Experience view
        self._xp_view = tk.Text(left, bg=COLORS['bg_darker'], fg=COLORS['fg'],
                                font=('Consolas', 9), wrap=tk.NONE, state=tk.DISABLED,
                                borderwidth=0, highlightthickness=0, padx=4, pady=4,
                                cursor="arrow")
        self._xp_scroll_y = tk.Scrollbar(left, orient=tk.VERTICAL,
                                         command=self._xp_view.yview)
        self._xp_view.configure(yscrollcommand=self._xp_scroll_y.set)

        # XP view tags
        self._xp_view.tag_configure('header', foreground=COLORS['mauve'],
                                    font=('Consolas', 9, 'bold'))
        self._xp_view.tag_configure('xp_gain', foreground=COLORS['green'],
                                    font=('Consolas', 9, 'bold'))
        self._xp_view.tag_configure('xp_total', foreground=COLORS['fg_dim'])
        self._xp_view.tag_configure('npc_name', foreground=COLORS['peach'])
        self._xp_view.tag_configure('player_name', foreground=COLORS['blue'])
        self._xp_view.tag_configure('sep', foreground=COLORS['fg_dim'])
        self._xp_view.tag_configure('summary_label', foreground=COLORS['fg_dim'])
        self._xp_view.tag_configure('summary_value', foreground=COLORS['yellow'],
                                    font=('Consolas', 9, 'bold'))
        self._xp_view.tag_configure('help_text', foreground=COLORS['fg_dim'])

        # Left view state
        self._left_view = "feed"          # "feed", "items", "item_detail", "triggers", "experience"
        self._item_selected_name = None   # selected item name for detail
        self._item_fingerprint = None     # skip-redraw optimization
        self._item_buttons = []           # embedded widgets in item list
        self._trigger_buttons = []        # embedded widgets in trigger list
        self._trigger_fingerprint = None  # skip-redraw optimization
        self._xp_fingerprint = None       # skip-redraw optimization

        # Right: encounter meter
        right = tk.Frame(main, bg=COLORS['bg'])
        right.grid(row=0, column=2, sticky='nsew')

        header_right = tk.Frame(right, bg=COLORS['bg'])
        header_right.pack(fill=tk.X)

        self._meter_back_btn = ttk.Button(
            header_right, text="< Back", style='Dark.TButton',
            command=self._on_meter_back)
        # Hidden by default — shown in detail view
        self._meter_view_var = tk.StringVar(value="Overview")
        self._meter_combo = ttk.Combobox(
            header_right, textvariable=self._meter_view_var,
            values=["Overview", "Encounters", "Grand Overview"],
            state='readonly', style='Dark.TCombobox', width=14,
            font=('Segoe UI', 9))
        self._meter_combo.pack(side=tk.LEFT, padx=4, pady=2)
        self._meter_combo.bind('<<ComboboxSelected>>', self._on_meter_view_change)
        ttk.Button(header_right, text="Reset", style='Dark.TButton',
                   command=self._reset_meter).pack(side=tk.RIGHT, padx=4)
        self._export_meter_btn = ttk.Button(
            header_right, text="Export", style='Dark.TButton',
            command=self._export_meter)
        self._export_meter_btn.pack(side=tk.RIGHT, padx=4)
        self._copy_meter_btn = ttk.Button(
            header_right, text="Copy", style='Dark.TButton',
            command=self._copy_overview)
        self._copy_meter_btn.pack(side=tk.RIGHT, padx=4)

        # Meter view state
        self._meter_view = "overview"  # "overview", "encounters", "encounter_detail", "grand_overview"
        self._meter_selected_eid = None
        self._encounter_buttons = []  # widgets embedded in meter
        self._encounter_button_eids = []  # eid order for in-place updates
        self._hidden_encounters = set()  # npc_eids dismissed by user
        self._meter_fingerprint = None  # skip redraw when unchanged
        self._overview_expanded = set()  # player names expanded in overview
        self._overview_lines = []        # tag names for in-place text updates

        self._meter = tk.Text(right, bg=COLORS['bg_darker'], fg=COLORS['fg'],
                              font=('Consolas', 9), wrap=tk.NONE, state=tk.DISABLED,
                              borderwidth=0, highlightthickness=0, padx=4, pady=4,
                              cursor="arrow",
                              selectbackground=COLORS['border'],
                              selectforeground=COLORS['fg'])
        meter_scroll = tk.Scrollbar(right, orient=tk.VERTICAL, command=self._meter.yview)
        self._meter.configure(yscrollcommand=meter_scroll.set)
        meter_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._meter.pack(fill=tk.BOTH, expand=True)
        # Block all keyboard input except Ctrl+C (copy) and Ctrl+A (select all)
        self._meter.bind("<Key>", lambda e: "break"
                         if e.keysym not in ("c", "a", "C", "A")
                            or not (e.state & 0x4)  # Ctrl
                         else None)

        self._meter.tag_configure('rank', foreground=COLORS['fg_dim'])
        self._meter.tag_configure('name', foreground=COLORS['fg'])
        self._meter.tag_configure('class_tag', foreground=COLORS['teal'])
        self._meter.tag_configure('dmg', foreground=COLORS['red'])
        self._meter.tag_configure('heal', foreground=COLORS['green'])
        self._meter.tag_configure('bar', foreground=COLORS['mauve'])
        self._meter.tag_configure('header_line', foreground=COLORS['fg_dim'])
        self._meter.tag_configure('dead_tag', foreground=COLORS['red'])
        self._meter.tag_configure('alive_tag', foreground=COLORS['green'])
        self._meter.tag_configure('duration', foreground=COLORS['peach'])

        # Bottom status
        self._bottom_status = tk.Label(self, text="Requires Administrator privileges",
                                        bg=COLORS['bg_darker'], fg=COLORS['fg_dim'],
                                        font=('Consolas', 8), anchor=tk.W, padx=6)
        self._bottom_status.pack(fill=tk.X, side=tk.BOTTOM)

        # Reload gate overlay — covers entire window until /reload is received
        self._reload_overlay_buttons_shown = False
        self._reload_overlay = tk.Frame(self, bg=COLORS['bg'])
        self._reload_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        tk.Label(self._reload_overlay, text="Type /reload in-game to start",
                 font=("Segoe UI", 14), fg=COLORS['fg'], bg=COLORS['bg']
                 ).place(relx=0.5, rely=0.45, anchor='center')
        tk.Label(self._reload_overlay, text="This identifies your character",
                 font=("Segoe UI", 9), fg=COLORS['fg_dim'], bg=COLORS['bg']
                 ).place(relx=0.5, rely=0.55, anchor='center')

    def _select_local_player(self, eid):
        """User clicked a player button on the reload overlay — assign as local player."""
        tracker = self._backend._tracker
        with tracker._lock:
            tracker._mark_local_player(eid)
            tracker._party_members_pending = None
            tracker._reload_gate = False
            _plog.info(f"RELOAD_GATE cleared — user selected player #{eid} \"{tracker.names.get(eid, '?')}\"")

    # --- Event polling ---

    def _on_pause_toggle(self):
        self._paused = self._pause_var.get()
        if not self._paused and self._pending_events:
            for text, tag, extra in self._pending_events:
                self._append_feed_line(text, tag, extra)
            self._pending_events.clear()

    # ------------------------------------------------------------------
    # Unified export — left panel
    # ------------------------------------------------------------------

    def _copy_left(self):
        """Copy text from the current left view's text widget to clipboard."""
        v = self._left_view
        if v == "feed":
            widget = self._feed
        elif v in ("items", "item_detail"):
            widget = self._item_view
        elif v == "triggers":
            widget = self._trigger_view
        elif v == "experience":
            widget = self._xp_view
        else:
            return
        text = widget.get("1.0", tk.END).rstrip()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._copy_left_btn.configure(text="Copied!")
        self.after(1500, lambda: self._copy_left_btn.configure(text="Copy"))

    def _export_left(self):
        """Route export to the correct method for the current left view."""
        v = self._left_view
        if v == "feed":
            self._export_feed_csv()
        elif v in ("items", "item_detail"):
            self._export_items_csv()
        elif v == "triggers":
            self._export_triggers_csv()

    def _export_feed_csv(self):
        if not self._combat_log:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"combat_log_{ts}.csv",
            title="Export Combat Log",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["timestamp", "type", "text"])
                w.writerows(self._combat_log)
            self._status_label.configure(text=f"Exported {len(self._combat_log)} lines to {os.path.basename(path)}")
        except Exception as e:
            self._status_label.configure(text=f"Export failed: {e}")

    def _export_items_csv(self):
        summary = self._backend.get_item_summary()
        if not summary:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"items_{ts}.csv",
            title="Export Items",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["item_name", "hid", "count", "looter", "looter_count",
                            "npc_source", "npc_count"])
                for item in summary:
                    name = item["name"]
                    hid = item["hid"]
                    count = item["count"]
                    drops = self._backend.get_item_drops_for(name)
                    # Aggregate looters
                    looters = {}
                    npcs = {}
                    for d in drops:
                        who = d.get("looter")
                        if who:
                            looters[who] = looters.get(who, 0) + d.get("quantity", 1)
                        npc = d.get("npc_name")
                        if npc:
                            npcs[npc] = npcs.get(npc, 0) + d.get("quantity", 1)
                    # First row: item summary
                    first_looter = max(looters, key=looters.get) if looters else ""
                    first_looter_cnt = looters.get(first_looter, 0) if first_looter else 0
                    first_npc = max(npcs, key=npcs.get) if npcs else ""
                    first_npc_cnt = npcs.get(first_npc, 0) if first_npc else 0
                    w.writerow([name, hid, count, first_looter, first_looter_cnt,
                                first_npc, first_npc_cnt])
                    # Sub-rows for remaining looters
                    for who in sorted(looters, key=looters.get, reverse=True):
                        if who == first_looter:
                            continue
                        w.writerow(["", "", "", who, looters[who], "", ""])
                    # Sub-rows for remaining NPCs
                    for npc in sorted(npcs, key=npcs.get, reverse=True):
                        if npc == first_npc:
                            continue
                        w.writerow(["", "", "", "", "", npc, npcs[npc]])
            self._status_label.configure(text=f"Exported {len(summary)} items to {os.path.basename(path)}")
        except Exception as e:
            self._status_label.configure(text=f"Export failed: {e}")

    def _export_triggers_csv(self):
        snapshot = self._backend.get_trigger_snapshot()
        if not snapshot:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"triggers_{ts}.csv",
            title="Export Triggers",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["pattern", "sound", "match_count"])
                for pattern, sound_label, count in snapshot:
                    w.writerow([pattern, sound_label, count])
            self._status_label.configure(text=f"Exported {len(snapshot)} triggers to {os.path.basename(path)}")
        except Exception as e:
            self._status_label.configure(text=f"Export failed: {e}")

    def _poll_queue(self):
        try:
            # Update status
            try:
                while True:
                    msg = self._status_queue.get_nowait()
                    self._status_label.configure(text=msg)
                    if msg in ("", "Reconnected"):
                        self._status_dot.configure(fg=COLORS['green'])
                    elif "Waiting" in msg or "exited" in msg or "Connecting" in msg:
                        self._status_dot.configure(fg=COLORS['yellow'])
                    elif "failed" in msg:
                        self._status_dot.configure(fg=COLORS['red'])
            except queue.Empty:
                pass

            # Reload overlay: show player selection or remove when gate clears
            if self._reload_overlay is not None and hasattr(self._backend, '_tracker'):
                tracker = self._backend._tracker
                if not tracker._reload_gate:
                    # Gate cleared (solo auto-detect or player selected) — remove overlay
                    self._reload_overlay.destroy()
                    self._reload_overlay = None
                elif (tracker._party_members_pending is not None
                      and not self._reload_overlay_buttons_shown):
                    # Group detected — replace overlay with player selection buttons
                    self._reload_overlay_buttons_shown = True
                    for w in self._reload_overlay.winfo_children():
                        w.destroy()
                    tk.Label(self._reload_overlay, text="Which character is yours?",
                             font=("Segoe UI", 14), fg=COLORS['fg'], bg=COLORS['bg']
                             ).pack(pady=(10, 8))
                    # Scrollable container for player buttons (fits 6+ members)
                    canvas = tk.Canvas(self._reload_overlay, bg=COLORS['bg'],
                                       highlightthickness=0, bd=0)
                    scrollbar = tk.Scrollbar(self._reload_overlay, orient=tk.VERTICAL,
                                             command=canvas.yview)
                    btn_frame = tk.Frame(canvas, bg=COLORS['bg'])
                    btn_frame.bind('<Configure>',
                                   lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
                    canvas.create_window((0, 0), window=btn_frame, anchor='n')
                    canvas.configure(yscrollcommand=scrollbar.set)
                    # Only show scrollbar if needed (many members)
                    if len(tracker._party_members_pending) > 5:
                        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                    canvas.pack(fill=tk.BOTH, expand=True, padx=20)
                    # Center the button frame in the canvas
                    canvas.bind('<Configure>',
                                lambda e: canvas.itemconfigure(
                                    canvas.find_withtag('all')[0],
                                    width=e.width) if canvas.find_withtag('all') else None)
                    for m_eid, m_name, m_cls, m_lvl in tracker._party_members_pending:
                        label = m_name
                        if m_cls:
                            label += f"  -  {_class_label(m_cls)}"
                        if m_lvl is not None:
                            label += f"  Lv{m_lvl}"
                        btn = tk.Button(
                            btn_frame, text=label,
                            font=("Segoe UI", 11), fg=COLORS['fg'], bg=COLORS['surface'],
                            activeforeground=COLORS['fg'], activebackground=COLORS['border'],
                            bd=0, padx=20, pady=6, cursor="hand2",
                            command=lambda eid=m_eid: self._select_local_player(eid))
                        btn.pack(pady=3, fill=tk.X)

            # Process combat events
            batch = 0
            try:
                while batch < 200:
                    event = self._event_queue.get_nowait()
                    batch += 1

                    text = event.get("_display", "???")
                    tag = event.get("type", "")
                    self._combat_log.append((
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        tag,
                        text,
                    ))

                    if self._paused:
                        self._pending_events.append((text, tag, None))
                        if len(self._pending_events) > 5000:
                            self._pending_events = self._pending_events[-3000:]
                    else:
                        self._append_feed_line(text, tag, None)
            except queue.Empty:
                pass

            # Drain chat log queue → file
            if self._chat_log_file:
                try:
                    while True:
                        cev = self._backend._chat_queue.get_nowait()
                        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        ch = cev.get("channel", "?")
                        txt = cev.get("text", "")
                        self._chat_log_file.write(f"[{ts}] [ch:{ch}] {txt}\n")
                        self._chat_log_file.flush()
                except queue.Empty:
                    pass
        finally:
            self._poll_id = self.after(80, self._poll_queue)

    def _append_feed_line(self, text, tag, extra):
        self._feed.configure(state=tk.NORMAL)
        at_bottom = self._feed.yview()[1] >= 0.98

        self._feed.insert(tk.END, text, tag)
        if extra:
            self._feed.insert(tk.END, extra[1], extra[0])
        self._feed.insert(tk.END, '\n')
        self._feed_line_count += 1

        if self._feed_line_count > self.MAX_FEED_LINES:
            trim = self._feed_line_count - self.MAX_FEED_LINES
            self._feed.delete('1.0', f'{trim + 1}.0')
            self._feed_line_count = self.MAX_FEED_LINES

        if at_bottom:
            self._feed.see(tk.END)
        self._feed.configure(state=tk.DISABLED)

    # --- Encounter meter ---

    def _meter_build_fingerprint(self):
        """Build a hashable snapshot of current meter data to detect changes."""
        t = self._backend.tracker
        encounters = t.get_encounters(top_n=999)
        view = self._meter_view
        sel = self._meter_selected_eid
        hidden = frozenset(self._hidden_encounters)

        if view == "encounter_detail" and sel is not None:
            enc = t.get_encounter_detail(sel)
            if enc is None:
                return (view, sel, hidden, None)
            players = tuple(
                (eid, max(p['text_dealt'], p['dealt']), p['received'])
                for eid, p in sorted(enc.players.items())
            )
            return (view, sel, hidden, enc.best_damage, enc.is_dead,
                    round(enc.duration, 1), players)
        elif view == "grand_overview":
            items = tuple(
                (e.npc_eid, e.npc_name, e.best_damage, e.is_dead, round(e.duration, 1))
                for e in encounters
            )
            return (view, hidden, items)
        elif view == "overview":
            items = tuple(
                (e.npc_eid, e.npc_name, e.best_damage, e.is_dead, round(e.duration, 1))
                for e in encounters
            )
            return (view, hidden, frozenset(self._overview_expanded), items)
        else:
            items = tuple(
                (e.npc_eid, e.best_damage, e.is_dead, round(e.duration, 1))
                for e in encounters if e.npc_eid not in self._hidden_encounters
            )
            return (view, hidden, items)

    def _refresh_meter(self):
        # Periodic GUI state snapshot (every 10 refreshes = ~10s, dev-only)
        self._meter_refresh_count = getattr(self, '_meter_refresh_count', 0) + 1
        if self._meter_refresh_count % 10 == 0 and _plog.isEnabledFor(logging.DEBUG):
            tracker = self._backend.tracker
            enc_count = len(tracker.encounters)
            etype_counts = {}
            for eid, et in tracker.entity_types.items():
                key = f"type{et}" if et is not None else "unknown"
                etype_counts[key] = etype_counts.get(key, 0) + 1
            _plog.debug(f"GUI_STATE view={self._meter_view} encounters={enc_count} "
                        f"entity_types={etype_counts} names={len(tracker.names)} "
                        f"local_eid={tracker._local_player_eid} "
                        f"player_name=\"{tracker.player_name}\" "
                        f"classes={dict(tracker.classes)} levels={dict(tracker.levels)}")

        scroll_pos = self._meter.yview()[0]
        if self._meter_view == "encounter_detail":
            fp = self._meter_build_fingerprint()
            if fp != self._meter_fingerprint:
                self._meter_fingerprint = fp
                did_redraw = self._render_encounter_detail()
                if did_redraw:
                    self._meter.after_idle(lambda sp=scroll_pos: self._meter.yview_moveto(sp))
        elif self._meter_view == "grand_overview":
            fp = self._meter_build_fingerprint()
            if fp != self._meter_fingerprint:
                self._meter_fingerprint = fp
                self._render_encounter_totals()
                self._meter.after_idle(lambda sp=scroll_pos: self._meter.yview_moveto(sp))
        elif self._meter_view == "overview":
            fp = self._meter_build_fingerprint()
            if fp != self._meter_fingerprint:
                self._meter_fingerprint = fp
                did_redraw = self._render_overview()
                if did_redraw:
                    self._meter.after_idle(lambda sp=scroll_pos: self._meter.yview_moveto(sp))
        else:
            # Encounters list view: always update (in-place when structure unchanged)
            self._render_encounter_list()
        self._meter_id = self.after(1000, self._refresh_meter)

    def _build_encounter_label(self, idx, enc):
        tag_parts = []
        if enc.npc_class:
            tag_parts.append(_class_label(enc.npc_class))
        if enc.npc_level is not None and enc.npc_level > 0:
            tag_parts.append(f"L{enc.npc_level}")
        tag_str = f" [{' '.join(tag_parts)}]" if tag_parts else ""
        dur = enc.duration
        return f"#{idx}  {enc.npc_name[:18]}{tag_str}  {enc.best_damage:,}dmg  {dur:.1f}s"

    def _render_encounter_list(self):
        all_encounters = self._backend.tracker.get_encounters()
        encounters = [e for e in all_encounters if e.npc_eid not in self._hidden_encounters]

        live = [e for e in encounters if not e.is_dead]
        dead = [e for e in encounters if e.is_dead]

        # Build ordered list: live section then dead section
        ordered = live + dead
        new_eids = [(e.npc_eid, e.is_dead) for e in ordered]

        # In-place update: same encounters in same order with same sections
        if (new_eids == self._encounter_button_eids
                and len(self._encounter_buttons) == len(ordered)):
            # Number within each section: live 1..N, dead 1..M
            li = 0
            for i, enc in enumerate(ordered):
                if enc.is_dead and li == 0:
                    li = 0  # reset for dead section
                li_idx = (i - len(live) + 1) if enc.is_dead else (i + 1)
                label = self._build_encounter_label(li_idx, enc)
                row = self._encounter_buttons[i]
                children = row.winfo_children()
                if children:
                    children[0].configure(text=label)
            return

        # Structural change — full redraw
        self._encounter_button_eids = new_eids

        for w in self._encounter_buttons:
            w.destroy()
        self._encounter_buttons.clear()

        self._meter.configure(state=tk.NORMAL)
        self._meter.delete('1.0', tk.END)

        def _insert_section(section_encounters, header):
            if not section_encounters:
                return
            self._meter.insert(tk.END, f" {header}\n", 'header_line')
            for i, enc in enumerate(section_encounters, 1):
                label = self._build_encounter_label(i, enc)

                row = tk.Frame(self._meter, bg=COLORS['bg_darker'])
                btn = tk.Button(
                    row, text=label, anchor=tk.W,
                    bg=COLORS['surface'], fg=COLORS['fg'],
                    activebackground=COLORS['border'], activeforeground=COLORS['fg'],
                    font=('Consolas', 9), relief=tk.FLAT, padx=4, pady=2,
                    cursor="hand2",
                    command=lambda eid=enc.npc_eid: self._on_encounter_click(eid),
                )
                btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
                x_btn = tk.Button(
                    row, text="X", width=2,
                    bg=COLORS['surface'], fg=COLORS['red'],
                    activebackground=COLORS['border'], activeforeground=COLORS['red'],
                    font=('Consolas', 9, 'bold'), relief=tk.FLAT, pady=2,
                    cursor="hand2",
                    command=lambda eid=enc.npc_eid: self._on_encounter_hide(eid),
                )
                x_btn.pack(side=tk.RIGHT)

                self._meter.window_create(tk.END, window=row, stretch=True)
                self._meter.insert(tk.END, '\n')
                self._encounter_buttons.append(row)

        _insert_section(live, "\u2501 Active")
        if live and dead:
            self._meter.insert(tk.END, '\n')
        _insert_section(dead, "\u2501 Dead")

        if not encounters:
            self._meter.insert(tk.END, "  No encounters recorded yet\n", 'rank')

        self._meter.configure(state=tk.DISABLED)

    def _build_detail_segments(self, enc):
        """Build encounter detail as a list of (text, tag) segments."""
        segs = []
        tag_parts = []
        if enc.npc_class:
            tag_parts.append(_class_label(enc.npc_class))
        if enc.npc_level is not None and enc.npc_level > 0:
            tag_parts.append(f"L{enc.npc_level}")
        tag_str = f" [{' '.join(tag_parts)}]" if tag_parts else ""

        segs.append((enc.npc_name, 'name'))
        if tag_str:
            segs.append((tag_str, 'class_tag'))
        if enc.is_dead:
            segs.append((" \u2014 DEAD", 'dead_tag'))
        else:
            segs.append((" \u2014 LIVE", 'alive_tag'))
        dur = enc.duration
        segs.append((f" \u2014 {dur:.1f}s", 'duration'))
        segs.append((f" \u2014 {enc.best_damage:,} total dmg", 'dmg'))
        segs.append(('\n', None))
        segs.append(('\u2500' * 40 + '\n', 'header_line'))

        def _best_dealt(p):
            return max(p['text_dealt'], p['dealt'])

        enc_dur = enc.duration
        tracker = self._backend.tracker
        players = sorted(enc.players.items(), key=lambda x: _best_dealt(x[1]), reverse=True)
        for i, (p_eid, p) in enumerate(players, 1):
            dealt = _best_dealt(p)
            p_dps = dealt / enc_dur if enc_dur > 0 else 0.0

            # Resolve "YOU" placeholder to real name
            pname = p['name']
            if pname == "YOU" or pname.startswith("Entity#"):
                real_name = tracker.names.get(p_eid)
                if real_name and real_name != "YOU" and not real_name.startswith("Entity#"):
                    pname = real_name
                    p['name'] = real_name
            if p_eid == tracker._local_player_eid and pname == "YOU":
                real = tracker.player_name
                if real and real != "YOU":
                    pname = real
                    p['name'] = real

            p_cls = tracker.classes.get(p_eid) or p['cls']
            p_lvl = tracker.levels.get(p_eid) if tracker.levels.get(p_eid) is not None else p['level']
            p_tags = []
            if p_cls:
                p_tags.append(_class_label(p_cls))
            if p_lvl is not None and p_lvl > 0:
                p_tags.append(f"L{p_lvl}")
            p_tag = f" [{' '.join(p_tags)}]" if p_tags else ""

            segs.append((f"#{i:<3}", 'rank'))
            name_display = pname[:14].ljust(14)
            segs.append((f" {name_display}", 'name'))
            if p_tag:
                segs.append((p_tag, 'class_tag'))
            segs.append(('\n', None))
            segs.append(("    ", 'rank'))
            segs.append((f"Dealt: {dealt:,}", 'dmg'))
            segs.append((f" ({p_dps:,.1f} dps)", 'heal'))
            if p['received'] > 0:
                segs.append((f"  Recv: {p['received']:,}", 'duration'))
            segs.append(('\n', None))

        if not players:
            segs.append(("  No player damage recorded\n", 'rank'))
        return segs

    def _render_encounter_detail(self):
        """Returns True if a full redraw was performed, False if skipped."""
        eid = self._meter_selected_eid
        enc = self._backend.tracker.get_encounter_detail(eid) if eid else None
        if enc is None:
            self._meter_view = "encounters"
            self._on_meter_back()
            return False

        segs = self._build_detail_segments(enc)

        # Skip redraw if content identical to last render
        seg_key = tuple((t, tag) for t, tag in segs)
        if hasattr(self, '_detail_seg_cache') and self._detail_seg_cache == seg_key:
            return False
        self._detail_seg_cache = seg_key

        self._meter.configure(state=tk.NORMAL)
        self._meter.delete('1.0', tk.END)
        for text, tag in segs:
            if tag:
                self._meter.insert(tk.END, text, tag)
            else:
                self._meter.insert(tk.END, text)
        self._meter.configure(state=tk.DISABLED)
        return True

    def _on_encounter_hide(self, npc_eid):
        self._hidden_encounters.add(npc_eid)
        self._meter_fingerprint = None  # force redraw
        self._encounter_button_eids = []  # force full list rebuild

    def _on_encounter_click(self, npc_eid):
        self._meter_view = "encounter_detail"
        self._meter_selected_eid = npc_eid
        self._meter_fingerprint = None  # force redraw
        self._detail_seg_cache = None
        self._encounter_button_eids = []  # invalidate list cache
        # Show back button, hide dropdown and copy
        self._meter_back_btn.pack(side=tk.LEFT, padx=(4, 0))
        self._copy_meter_btn.pack_forget()
        # Force immediate refresh
        self._render_encounter_detail()

    def _on_meter_back(self):
        self._meter_view = "encounters"
        self._meter_view_var.set("Encounters")
        self._meter_selected_eid = None
        self._meter_fingerprint = None  # force redraw
        self._detail_seg_cache = None
        self._encounter_button_eids = []  # force full list rebuild
        self._meter_back_btn.pack_forget()
        self._render_encounter_list()

    def _on_meter_view_change(self, event=None):
        """Handle dropdown view selection."""
        label = self._meter_view_var.get()
        view_map = {
            "Overview": "overview",
            "Encounters": "encounters",
            "Grand Overview": "grand_overview",
        }
        new_view = view_map.get(label, "overview")
        self._meter_view = new_view
        self._meter_selected_eid = None
        self._meter_fingerprint = None
        self._detail_seg_cache = None
        self._encounter_button_eids = []
        self._overview_structure = None
        self._overview_lines = []
        self._meter_back_btn.pack_forget()
        # Force immediate render
        for w in self._encounter_buttons:
            w.destroy()
        self._encounter_buttons.clear()
        if new_view == "overview":
            self._copy_meter_btn.pack(side=tk.RIGHT, padx=4)
            self._render_overview()
        else:
            self._copy_meter_btn.pack_forget()
            if new_view == "encounters":
                self._render_encounter_list()
            elif new_view == "grand_overview":
                self._render_encounter_totals()
        # Unfocus the combobox
        self._meter.focus_set()

    def _toggle_overview_expand(self, player_name):
        """Toggle expand/collapse of a player in the overview."""
        if player_name in self._overview_expanded:
            self._overview_expanded.discard(player_name)
        else:
            self._overview_expanded.add(player_name)
        self._meter_fingerprint = None
        self._render_overview()

    def _build_overview_data(self):
        """Aggregate player totals across all encounters for the overview.
        Shows players and charmed pets only — filters out regular NPCs."""
        tracker = self._backend.tracker
        encounters = tracker.get_encounters(top_n=999)

        player_totals = {}
        grand_total_dmg = 0
        grand_total_dur = 0.0
        grand_enc_count = 0

        for enc in encounters:
            grand_total_dmg += enc.best_damage
            grand_total_dur += enc.duration
            grand_enc_count += 1
            for p_eid, p in enc.players.items():
                pname = p['name']
                # Resolve bad/placeholder names from tracker state
                if (pname.startswith("Entity#")
                        or pname == "YOU"
                        or EntityTracker._looks_like_npc_name(pname)):
                    real_name = tracker.names.get(p_eid)
                    if (real_name
                            and real_name != "YOU"
                            and not real_name.startswith("Entity#")):
                        pname = real_name
                        p['name'] = real_name
                # Local player fallback: use player_name if name is still bad
                if p_eid == tracker._local_player_eid:
                    if (pname.startswith("Entity#")
                            or pname == "YOU"
                            or EntityTracker._looks_like_npc_name(pname)):
                        real = tracker.player_name
                        if real and real != "YOU":
                            pname = real
                            p['name'] = real
                p_dealt = max(p['text_dealt'], p['dealt'])
                p_cls = tracker.classes.get(p_eid) or p['cls']
                p_lvl = tracker.levels.get(p_eid) if tracker.levels.get(p_eid) is not None else p['level']
                p_etype = tracker.entity_types.get(p_eid)  # 0=player, None=unknown, >0=NPC/pet
                # Filter: only confirmed players (entity_type==0) and charmed pets
                # The /reload gate ensures all party members are registered as type 0
                is_pet = False
                if p_etype == 0:
                    pass  # confirmed player — always show
                elif p_eid == tracker._local_player_eid:
                    pass  # local player — always show
                elif p_etype is not None and p_etype != 0:
                    is_pet = tracker.pet_states.get(p_eid, False)
                    if not is_pet:
                        continue  # skip regular NPCs
                    # Only include pet if owner is a confirmed player
                    pet_owner_eid = tracker._pet_owners.get(p_eid)
                    if pet_owner_eid is None or tracker.entity_types.get(pet_owner_eid) != 0:
                        continue  # skip NPC-owned pets
                else:
                    # Unknown entity_type — allow if name matches a known party member
                    # (old eids after zone migration lose entity_type but still carry text_dealt)
                    if pname not in tracker._party_eids:
                        continue
                if pname not in player_totals:
                    player_totals[pname] = {
                        'cls': p_cls, 'level': p_lvl,
                        'dealt': 0, 'active_dur': 0.0,
                        'abilities': {}, 'ability_counts': {},
                        'entity_type': p_etype,
                        'is_pet': is_pet,
                    }
                pt = player_totals[pname]
                pt['dealt'] += p_dealt
                pt['active_dur'] += enc.duration
                if p_cls and not pt['cls']:
                    pt['cls'] = p_cls
                if p_lvl is not None and pt['level'] is None:
                    pt['level'] = p_lvl
                # Promote entity_type: if any eid for this name is a player (0),
                # treat the whole entry as player. Otherwise keep the first non-None.
                if p_etype == 0:
                    pt['entity_type'] = 0
                elif pt['entity_type'] is None and p_etype is not None:
                    pt['entity_type'] = p_etype
                if is_pet:
                    pt['is_pet'] = True
                for ab_name, ab_dmg in p.get('abilities', {}).items():
                    pt['abilities'][ab_name] = pt['abilities'].get(ab_name, 0) + ab_dmg
                for ab_name, ab_cnt in p.get('ability_counts', {}).items():
                    pt['ability_counts'][ab_name] = pt['ability_counts'].get(ab_name, 0) + ab_cnt

        # Merge pet damage into owner's row as "[PET] PetName" ability entry
        pet_names = [pname for pname, pt in player_totals.items() if pt.get('is_pet')]
        for pet_name in pet_names:
            pet_pt = player_totals[pet_name]
            # Find owner name via _pet_owners
            owner_name = None
            for pet_eid, owner_eid in tracker._pet_owners.items():
                if tracker.names.get(pet_eid) == pet_name:
                    owner_name = tracker.names.get(owner_eid)
                    break
            if owner_name and owner_name in player_totals:
                owner_pt = player_totals[owner_name]
                owner_pt['dealt'] += pet_pt['dealt']
                ab_key = f"[PET] {pet_name}"
                owner_pt['abilities'][ab_key] = owner_pt['abilities'].get(ab_key, 0) + pet_pt['dealt']
                owner_pt['ability_counts'][ab_key] = owner_pt['ability_counts'].get(ab_key, 0) + sum(pet_pt.get('ability_counts', {}).values())
                del player_totals[pet_name]

        sorted_pt = sorted(player_totals.items(), key=lambda x: x[1]['dealt'], reverse=True)[:20]
        return grand_enc_count, grand_total_dmg, grand_total_dur, sorted_pt

    def _build_overview_label(self, rank, pname, pt, grand_total_dmg):
        """Build fixed-width label for one overview player row (paste-friendly)."""
        pct = (pt['dealt'] / grand_total_dmg * 100) if grand_total_dmg > 0 else 0
        avg_dps = pt['dealt'] / pt['active_dur'] if pt['active_dur'] > 0 else 0
        is_expanded = pname in self._overview_expanded
        arrow = "\u25BC" if is_expanded else "\u25B6"
        # Fixed columns: arrow+rank(5) name(14) damage(9) pct(8) dps(10)
        col_name = pname[:16].ljust(16)
        col_dmg = f"{pt['dealt']:,}".rjust(9)
        col_pct = f"({pct:.1f}%)".rjust(8)
        col_dps = f"{avg_dps:,.1f}".rjust(8)
        return f"{arrow} #{rank:<2} {col_name} {col_dmg} {col_pct} {col_dps} dps"

    @staticmethod
    def _build_overview_ability_line(ab_name, ab_dmg, ab_pct, ab_count=0):
        """Build fixed-width ability breakdown line (paste-friendly)."""
        col_name = ab_name[:16].ljust(16)
        col_cnt = f"x{ab_count}".rjust(5)
        col_dmg = f"{ab_dmg:,}".rjust(9)
        col_pct = f"({ab_pct:.0f}%)".rjust(5)
        return f"       {col_name}{col_cnt} {col_dmg} {col_pct}"

    def _render_overview(self):
        """Render session leaderboard. Returns True if full redraw, False if in-place."""
        grand_enc_count, grand_total_dmg, grand_total_dur, sorted_pt = self._build_overview_data()

        # Debug: log overview snapshot (dev-only, _plog is NullHandler in frozen exe)
        if _plog.isEnabledFor(logging.DEBUG):
            tracker = self._backend.tracker
            _plog.debug(f"OVERVIEW_RENDER enc={grand_enc_count} total_dmg={grand_total_dmg} "
                        f"dur={grand_total_dur:.1f}s entries={len(sorted_pt)} "
                        f"local_eid={tracker._local_player_eid} "
                        f"player_name=\"{tracker.player_name}\" "
                        f"pet_states={dict(tracker.pet_states)} "
                        f"entity_types_sample={dict(list(tracker.entity_types.items())[:20])}")
            for rank, (pname, pt) in enumerate(sorted_pt, 1):
                etype = pt.get('entity_type')
                is_pet = pt.get('is_pet', False)
                etype_s = f"player" if etype == 0 else (f"pet({etype})" if is_pet else (f"npc({etype})" if etype is not None else "unknown"))
                avg_dps = pt['dealt'] / pt['active_dur'] if pt['active_dur'] > 0 else 0
                top_abs = sorted(pt['abilities'].items(), key=lambda x: x[1], reverse=True)[:3]
                abs_str = ", ".join(f"{n}={d}" for n, d in top_abs) if top_abs else "none"
                _plog.debug(f"  OVERVIEW_ROW #{rank} \"{pname}\" type={etype_s} cls={pt['cls']} "
                            f"lvl={pt['level']} dealt={pt['dealt']} dps={avg_dps:.1f} "
                            f"abilities=[{abs_str}]")

        # Build a structural key: ordered player names + expanded set
        # If structure matches, do in-place text updates only (no flicker)
        new_structure = tuple(
            (pname, pname in self._overview_expanded,
             tuple(sorted(pt['abilities'].items())) if pname in self._overview_expanded else ())
            for pname, pt in sorted_pt
        )
        old_structure = getattr(self, '_overview_structure', None)

        if grand_enc_count > 0 and new_structure == old_structure and self._overview_lines:
            # In-place update: replace text content of player lines only
            self._meter.configure(state=tk.NORMAL)
            for idx, (pname, pt) in enumerate(sorted_pt):
                tag = f"_ovp_{idx}"
                click_tag = f"_ovc_{idx}"
                label = self._build_overview_label(idx + 1, pname, pt, grand_total_dmg)
                ranges = self._meter.tag_ranges(tag)
                if len(ranges) >= 2:
                    self._meter.delete(ranges[0], ranges[1])
                    self._meter.insert(ranges[0], label, (tag, click_tag))
            # Leave NORMAL so text is selectable/copyable
            return False

        # Structural change — full redraw
        self._overview_structure = new_structure
        self._overview_lines = []

        for w in self._encounter_buttons:
            w.destroy()
        self._encounter_buttons.clear()

        self._meter.configure(state=tk.NORMAL)
        self._meter.delete('1.0', tk.END)

        # Remove old per-player click tags
        for tag in self._meter.tag_names():
            if tag.startswith("_ovp_") or tag.startswith("_ovc_"):
                self._meter.tag_delete(tag)

        _box_w = 58

        if grand_enc_count == 0:
            self._meter.insert(tk.END, "  No encounters recorded yet\n", 'rank')
            self._meter.configure(state=tk.DISABLED)
            return True

        grand_dps = grand_total_dmg / grand_total_dur if grand_total_dur > 0 else 0
        dur_m = int(grand_total_dur) // 60
        dur_s = int(grand_total_dur) % 60

        # Session header
        self._meter.insert(tk.END, "\u2500" * _box_w + "\n", 'header_line')
        self._meter.insert(tk.END, f" Session  {dur_m}m {dur_s}s", 'name')
        self._meter.insert(tk.END, f"  |  Total: ", 'rank')
        self._meter.insert(tk.END, f"{grand_total_dmg:,}", 'dmg')
        self._meter.insert(tk.END, f"  DPS: ", 'rank')
        self._meter.insert(tk.END, f"{grand_dps:,.1f}\n", 'dmg')
        self._meter.insert(tk.END, "\u2500" * _box_w + "\n", 'header_line')
        # Column header
        self._meter.insert(tk.END,
            f"  {'#':<3} {'Name':<16} {'Damage':>9} {'Pct':>8} {'DPS':>8}\n", 'rank')

        # Top players sorted by damage — plain text with click tags
        for rank, (pname, pt) in enumerate(sorted_pt, 1):
            label = self._build_overview_label(rank, pname, pt, grand_total_dmg)
            tag = f"_ovp_{rank - 1}"        # text content tag for in-place updates
            click_tag = f"_ovc_{rank - 1}"  # clickable region tag

            self._meter.insert(tk.END, label, (tag, click_tag))
            self._meter.insert(tk.END, "\n")
            self._overview_lines.append(tag)

            # Make player line clickable with hand cursor
            self._meter.tag_configure(click_tag, foreground=COLORS['fg'])
            self._meter.tag_bind(click_tag, "<Button-1>",
                                 lambda e, name=pname: self._toggle_overview_expand(name))
            self._meter.tag_bind(click_tag, "<Enter>",
                                 lambda e: self._meter.configure(cursor="hand2"))
            self._meter.tag_bind(click_tag, "<Leave>",
                                 lambda e: self._meter.configure(cursor="arrow"))

            # Expanded ability breakdown
            if pname in self._overview_expanded and pt['abilities']:
                sorted_abs = sorted(pt['abilities'].items(), key=lambda x: x[1], reverse=True)
                ab_counts = pt.get('ability_counts', {})
                for ab_name, ab_dmg in sorted_abs:
                    ab_pct = (ab_dmg / pt['dealt'] * 100) if pt['dealt'] > 0 else 0
                    ab_cnt = ab_counts.get(ab_name, 0)
                    ab_line = self._build_overview_ability_line(ab_name, ab_dmg, ab_pct, ab_cnt)
                    self._meter.insert(tk.END, ab_line + "\n", 'bar')

        # Leave NORMAL so text is selectable/copyable (keyboard input blocked by binding)
        return True

    def _copy_overview(self):
        """Copy the overview table to clipboard (only expanded abilities included)."""
        if self._meter_view != "overview":
            return
        grand_enc_count, grand_total_dmg, grand_total_dur, sorted_pt = self._build_overview_data()
        if grand_enc_count == 0:
            return

        lines = []
        grand_dps = grand_total_dmg / grand_total_dur if grand_total_dur > 0 else 0
        dur_m = int(grand_total_dur) // 60
        dur_s = int(grand_total_dur) % 60
        _box_w = 58

        lines.append("\u2500" * _box_w)
        lines.append(f" Session  {dur_m}m {dur_s}s"
                     f"  |  Total: {grand_total_dmg:,}  DPS: {grand_dps:,.1f}")
        lines.append("\u2500" * _box_w)
        lines.append(f"  {'#':<3} {'Name':<16} {'Damage':>9} {'Pct':>8} {'DPS':>8}")

        for rank, (pname, pt) in enumerate(sorted_pt, 1):
            label = self._build_overview_label(rank, pname, pt, grand_total_dmg)
            lines.append(label)

            if pname in self._overview_expanded and pt['abilities']:
                sorted_abs = sorted(pt['abilities'].items(), key=lambda x: x[1], reverse=True)
                ab_counts = pt.get('ability_counts', {})
                for ab_name, ab_dmg in sorted_abs:
                    ab_pct = (ab_dmg / pt['dealt'] * 100) if pt['dealt'] > 0 else 0
                    ab_cnt = ab_counts.get(ab_name, 0)
                    lines.append(self._build_overview_ability_line(ab_name, ab_dmg, ab_pct, ab_cnt))

        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        # Brief visual feedback on the button
        self._copy_meter_btn.configure(text="Copied!")
        self.after(1500, lambda: self._copy_meter_btn.configure(text="Copy"))

    def _export_overview_csv(self):
        """Export overview session leaderboard."""
        tracker = self._backend.tracker
        encounters = tracker.get_encounters(top_n=999)
        if not encounters:
            return

        player_totals = {}
        # Same NPC target filter as _build_overview_data
        npc_target_eids = set()
        npc_target_names = set()
        for enc in encounters:
            et = tracker.entity_types.get(enc.npc_eid)
            if et is not None and et != 0:
                npc_target_eids.add(enc.npc_eid)
                if enc.npc_name:
                    npc_target_names.add(enc.npc_name)
            elif et is None and enc.npc_name:
                if EntityTracker._looks_like_npc_name(enc.npc_name):
                    npc_target_eids.add(enc.npc_eid)
                    npc_target_names.add(enc.npc_name)
        for enc in encounters:
            for p_eid, p in enc.players.items():
                pname = p['name']
                p_dealt = max(p['text_dealt'], p['dealt'])
                p_cls = tracker.classes.get(p_eid) or p['cls']
                p_lvl = tracker.levels.get(p_eid) if tracker.levels.get(p_eid) is not None else p['level']
                p_etype = tracker.entity_types.get(p_eid)
                # Same filter as _build_overview_data: skip regular NPCs and NPC-owned pets
                if p_etype is not None and p_etype != 0:
                    if not tracker.pet_states.get(p_eid, False):
                        continue
                    pet_owner_eid = tracker._pet_owners.get(p_eid)
                    if pet_owner_eid is None or tracker.entity_types.get(pet_owner_eid) != 0:
                        continue
                elif p_etype is None:
                    # Allow known party members (old eids after zone migration)
                    if pname not in tracker._party_eids:
                        if EntityTracker._looks_like_npc_name(pname):
                            continue
                        if (p_eid in npc_target_eids
                                and p_eid != tracker._local_player_eid):
                            continue
                        if (pname in npc_target_names
                                and p_eid != tracker._local_player_eid):
                            continue
                if pname not in player_totals:
                    player_totals[pname] = {
                        'cls': p_cls, 'level': p_lvl,
                        'dealt': 0, 'active_dur': 0.0,
                        'abilities': {},
                        'entity_type': p_etype,
                    }
                pt = player_totals[pname]
                pt['dealt'] += p_dealt
                pt['active_dur'] += enc.duration
                if p_cls and not pt['cls']:
                    pt['cls'] = p_cls
                if p_lvl is not None and pt['level'] is None:
                    pt['level'] = p_lvl
                if p_etype == 0:
                    pt['entity_type'] = 0
                elif pt['entity_type'] is None and p_etype is not None:
                    pt['entity_type'] = p_etype
                for ab_name, ab_dmg in p.get('abilities', {}).items():
                    pt['abilities'][ab_name] = pt['abilities'].get(ab_name, 0) + ab_dmg

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"overview_{ts}.csv",
            title="Export Overview",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["rank", "player", "entity_type", "class", "level",
                            "total_damage", "avg_dps", "active_duration_s",
                            "ability", "ability_damage"])
                sorted_pt = sorted(player_totals.items(), key=lambda x: x[1]['dealt'], reverse=True)
                for rank, (pname, pt) in enumerate(sorted_pt, 1):
                    avg_dps = round(pt['dealt'] / pt['active_dur'], 1) if pt['active_dur'] > 0 else 0
                    dur = round(pt['active_dur'], 1)
                    etype = pt.get('entity_type')
                    etype_str = "player" if etype == 0 else ("pet/npc" if etype is not None else "unknown")
                    abilities = sorted(pt['abilities'].items(), key=lambda x: x[1], reverse=True)
                    if abilities:
                        for ab_name, ab_dmg in abilities:
                            w.writerow([rank, pname, etype_str, pt['cls'] or "", pt['level'] or "",
                                        pt['dealt'], avg_dps, dur, ab_name, ab_dmg])
                    else:
                        w.writerow([rank, pname, etype_str, pt['cls'] or "", pt['level'] or "",
                                    pt['dealt'], avg_dps, dur, "", ""])
            self._status_label.configure(
                text=f"Exported overview to {os.path.basename(path)}")
        except Exception as e:
            self._status_label.configure(text=f"Export failed: {e}")

    def _render_encounter_totals(self):
        tracker = self._backend.tracker
        encounters = tracker.get_encounters(top_n=999)

        # Clear old buttons
        for w in self._encounter_buttons:
            w.destroy()
        self._encounter_buttons.clear()

        # Aggregate by NPC name + grand totals + per-player abilities
        npc_agg = {}  # npc_name -> {count, total_dmg, total_dur, players: {name -> {dealt, received, count}}}
        grand_total_dmg = 0
        grand_total_dur = 0.0
        grand_enc_count = 0
        # player_name -> {cls, level, dealt, received, abilities: {name: dmg}}
        player_totals = {}

        for enc in encounters:
            key = enc.npc_name
            if key not in npc_agg:
                npc_agg[key] = {
                    'count': 0, 'total_dmg': 0, 'total_dur': 0.0,
                    'npc_class': enc.npc_class, 'npc_level': enc.npc_level,
                    'players': {},
                }
            agg = npc_agg[key]
            agg['count'] += 1
            agg['total_dmg'] += enc.best_damage
            agg['total_dur'] += enc.duration
            grand_total_dmg += enc.best_damage
            grand_total_dur += enc.duration
            grand_enc_count += 1
            if enc.npc_class and not agg['npc_class']:
                agg['npc_class'] = enc.npc_class
            if enc.npc_level is not None and agg['npc_level'] is None:
                agg['npc_level'] = enc.npc_level
            for p_eid, p in enc.players.items():
                pname = p['name']
                # Resolve "YOU" and other placeholder names
                if (pname == "YOU" or pname.startswith("Entity#")):
                    real_name = tracker.names.get(p_eid)
                    if real_name and real_name != "YOU" and not real_name.startswith("Entity#"):
                        pname = real_name
                        p['name'] = real_name
                if p_eid == tracker._local_player_eid and pname == "YOU":
                    real = tracker.player_name
                    if real and real != "YOU":
                        pname = real
                        p['name'] = real
                p_dealt = max(p['text_dealt'], p['dealt'])
                # Use live tracker data for class/level (encounter records may be stale)
                p_cls = tracker.classes.get(p_eid) or p['cls']
                p_lvl = tracker.levels.get(p_eid) if tracker.levels.get(p_eid) is not None else p['level']
                if pname not in agg['players']:
                    agg['players'][pname] = {
                        'cls': p_cls, 'level': p_lvl,
                        'dealt': 0, 'received': 0, 'count': 0,
                    }
                pa = agg['players'][pname]
                pa['dealt'] += p_dealt
                pa['received'] += p['received']
                pa['count'] += 1
                if p_cls and not pa['cls']:
                    pa['cls'] = p_cls
                if p_lvl is not None and pa['level'] is None:
                    pa['level'] = p_lvl
                # Grand player totals + abilities
                if pname not in player_totals:
                    player_totals[pname] = {
                        'cls': p_cls, 'level': p_lvl,
                        'dealt': 0, 'received': 0, 'active_dur': 0.0,
                        'abilities': {},
                    }
                pt = player_totals[pname]
                pt['dealt'] += p_dealt
                pt['received'] += p['received']
                pt['active_dur'] += enc.duration
                if p_cls and not pt['cls']:
                    pt['cls'] = p_cls
                if p_lvl is not None and pt['level'] is None:
                    pt['level'] = p_lvl
                for ab_name, ab_dmg in p.get('abilities', {}).items():
                    pt['abilities'][ab_name] = pt['abilities'].get(ab_name, 0) + ab_dmg

        # Sort by total damage desc
        sorted_npcs = sorted(npc_agg.items(), key=lambda x: x[1]['total_dmg'], reverse=True)

        self._meter.configure(state=tk.NORMAL)
        self._meter.delete('1.0', tk.END)

        # === GRAND TOTAL SECTION ===
        _box_w = 38
        if grand_enc_count > 0:
            grand_dps = grand_total_dmg / grand_total_dur if grand_total_dur > 0 else 0
            dur_m = int(grand_total_dur) // 60
            dur_s = int(grand_total_dur) % 60

            self._meter.insert(tk.END, "\u2500" * _box_w + "\n", 'header_line')
            self._meter.insert(tk.END, " Grand Total", 'name')
            self._meter.insert(tk.END, f"  x{grand_enc_count}", 'rank')
            self._meter.insert(tk.END, f"  {dur_m}m {dur_s}s\n", 'duration')
            self._meter.insert(tk.END, " Damage: ", 'rank')
            self._meter.insert(tk.END, f"{grand_total_dmg:,}", 'dmg')
            self._meter.insert(tk.END, "  DPS: ", 'rank')
            self._meter.insert(tk.END, f"{grand_dps:,.1f}\n", 'dmg')
            self._meter.insert(tk.END, "\u2500" * _box_w + "\n", 'header_line')

            # Per-player breakdown with abilities in boxes
            sorted_pt = sorted(player_totals.items(), key=lambda x: x[1]['dealt'], reverse=True)
            for pname, pt in sorted_pt:
                p_tags = []
                if pt['cls']:
                    p_tags.append(_class_label(pt['cls']))
                if pt['level'] is not None and pt['level'] > 0:
                    p_tags.append(f"L{pt['level']}")
                p_tag = f" [{' '.join(p_tags)}]" if p_tags else ""
                pct = (pt['dealt'] / grand_total_dmg * 100) if grand_total_dmg > 0 else 0
                avg_dps = pt['dealt'] / pt['active_dur'] if pt['active_dur'] > 0 else 0

                # Box top
                self._meter.insert(tk.END, " \u250C" + "\u2500" * (_box_w - 2) + "\u2510\n", 'header_line')
                # Player name line
                self._meter.insert(tk.END, " \u2502 ", 'header_line')
                self._meter.insert(tk.END, f"{pname[:16]}", 'name')
                if p_tag:
                    self._meter.insert(tk.END, p_tag, 'class_tag')
                self._meter.insert(tk.END, '\n')
                # Damage + DPS line
                self._meter.insert(tk.END, " \u2502 ", 'header_line')
                self._meter.insert(tk.END, f"{pt['dealt']:,}", 'dmg')
                self._meter.insert(tk.END, f" ({pct:.1f}%)", 'rank')
                self._meter.insert(tk.END, "  DPS: ", 'rank')
                self._meter.insert(tk.END, f"{avg_dps:,.1f}", 'heal')
                if pt['received'] > 0:
                    self._meter.insert(tk.END, f"  recv {pt['received']:,}", 'duration')
                self._meter.insert(tk.END, '\n')

                # Ability breakdown
                if pt['abilities']:
                    sorted_abs = sorted(pt['abilities'].items(), key=lambda x: x[1], reverse=True)
                    for ab_name, ab_dmg in sorted_abs:
                        ab_pct = (ab_dmg / pt['dealt'] * 100) if pt['dealt'] > 0 else 0
                        self._meter.insert(tk.END, " \u2502   ", 'header_line')
                        self._meter.insert(tk.END, f"{ab_name[:16]}", 'bar')
                        self._meter.insert(tk.END, f"  {ab_dmg:,}", 'dmg')
                        self._meter.insert(tk.END, f" ({ab_pct:.0f}%)\n", 'rank')

                # Box bottom
                self._meter.insert(tk.END, " \u2514" + "\u2500" * (_box_w - 2) + "\u2518\n", 'header_line')

            self._meter.insert(tk.END, '\n')
            self._meter.insert(tk.END, "\u2500" * _box_w + "\n", 'header_line')
            self._meter.insert(tk.END, " Tanking\n", 'name')
            self._meter.insert(tk.END, "\u2500" * _box_w + "\n", 'header_line')

        # === PER-NPC SECTION ===
        for npc_name, agg in sorted_npcs:
            tag_parts = []
            if agg['npc_class']:
                tag_parts.append(_class_label(agg['npc_class']))
            if agg['npc_level'] is not None and agg['npc_level'] > 0:
                tag_parts.append(f"L{agg['npc_level']}")
            tag_str = f" [{' '.join(tag_parts)}]" if tag_parts else ""

            avg_dmg = agg['total_dmg'] / agg['count'] if agg['count'] > 0 else 0

            # NPC header
            self._meter.insert(tk.END, npc_name[:20], 'name')
            if tag_str:
                self._meter.insert(tk.END, tag_str, 'class_tag')
            self._meter.insert(tk.END, f"  x{agg['count']}", 'rank')
            self._meter.insert(tk.END, '\n')

            # Stats line
            self._meter.insert(tk.END, "  Total: ", 'rank')
            self._meter.insert(tk.END, f"{agg['total_dmg']:,} dmg", 'dmg')
            self._meter.insert(tk.END, "  Avg: ", 'rank')
            self._meter.insert(tk.END, f"{avg_dmg:,.0f} dmg", 'dmg')
            self._meter.insert(tk.END, '\n')

            # Player breakdown
            sorted_players = sorted(agg['players'].items(), key=lambda x: x[1]['dealt'], reverse=True)
            for pname, pa in sorted_players:
                p_tags = []
                if pa['cls']:
                    p_tags.append(_class_label(pa['cls']))
                if pa['level'] is not None and pa['level'] > 0:
                    p_tags.append(f"L{pa['level']}")
                p_tag = f" [{' '.join(p_tags)}]" if p_tags else ""

                avg_dealt = pa['dealt'] / pa['count'] if pa['count'] > 0 else 0
                self._meter.insert(tk.END, f"    {pname[:14]}", 'name')
                if p_tag:
                    self._meter.insert(tk.END, p_tag, 'class_tag')
                self._meter.insert(tk.END, f"  {pa['dealt']:,}", 'dmg')
                self._meter.insert(tk.END, f" (avg {avg_dealt:,.0f})", 'rank')
                if pa['received'] > 0:
                    self._meter.insert(tk.END, f"  recv {pa['received']:,}", 'duration')
                self._meter.insert(tk.END, '\n')

            self._meter.insert(tk.END, '\n')

        if not sorted_npcs:
            self._meter.insert(tk.END, "  No encounters recorded yet\n", 'rank')

        self._meter.configure(state=tk.DISABLED)

    def _reset_meter(self):
        self._backend.tracker.reset()
        self._meter_view = "overview"
        self._meter_view_var.set("Overview")
        self._meter_selected_eid = None
        self._meter_fingerprint = None  # force redraw
        self._hidden_encounters.clear()
        self._overview_expanded.clear()
        self._overview_structure = None
        self._overview_lines = []
        self._meter_back_btn.pack_forget()
        self._copy_meter_btn.pack(side=tk.RIGHT, padx=4)
        for w in self._encounter_buttons:
            w.destroy()
        self._encounter_buttons.clear()

    # ------------------------------------------------------------------
    # Unified export — right panel (encounters)
    # ------------------------------------------------------------------

    def _export_meter(self):
        """Route export to the correct method for the current meter view."""
        v = self._meter_view
        if v == "encounters":
            self._export_encounters_csv()
        elif v == "encounter_detail":
            self._export_encounter_detail_csv()
        elif v == "grand_overview":
            self._export_totals_csv()
        elif v == "overview":
            self._export_overview_csv()

    def _export_encounters_csv(self):
        """Export encounter list with per-player sub-rows."""
        encounters = self._backend.tracker.get_encounters(top_n=999)
        if not encounters:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"encounters_{ts}.csv",
            title="Export Encounters",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["npc_name", "npc_class", "npc_level", "status",
                            "total_damage", "duration_s", "dps",
                            "player_name", "player_class", "player_level",
                            "player_dealt", "player_dps", "player_received",
                            "ability", "ability_damage"])
                for enc in encounters:
                    if enc.npc_eid in self._hidden_encounters:
                        continue
                    status = "DEAD" if enc.is_dead else "LIVE"
                    dur = round(enc.duration, 1)
                    dps = round(enc.dps, 1)
                    players = sorted(enc.players.values(),
                                     key=lambda p: max(p['text_dealt'], p['dealt']),
                                     reverse=True)
                    if players:
                        for p in players:
                            dealt = max(p['text_dealt'], p['dealt'])
                            p_dps = round(dealt / enc.duration, 1) if enc.duration > 0 else 0
                            abilities = sorted(p.get('abilities', {}).items(),
                                               key=lambda x: x[1], reverse=True)
                            if abilities:
                                for ab_name, ab_dmg in abilities:
                                    w.writerow([
                                        enc.npc_name, enc.npc_class or "",
                                        enc.npc_level or "", status,
                                        enc.best_damage, dur, dps,
                                        p['name'], p['cls'] or "",
                                        p['level'] or "", dealt, p_dps,
                                        p['received'], ab_name, ab_dmg,
                                    ])
                            else:
                                w.writerow([
                                    enc.npc_name, enc.npc_class or "",
                                    enc.npc_level or "", status,
                                    enc.best_damage, dur, dps,
                                    p['name'], p['cls'] or "",
                                    p['level'] or "", dealt, p_dps,
                                    p['received'], "", "",
                                ])
                    else:
                        w.writerow([
                            enc.npc_name, enc.npc_class or "",
                            enc.npc_level or "", status,
                            enc.best_damage, dur, dps,
                            "", "", "", 0, 0, 0, "", "",
                        ])
            self._status_label.configure(
                text=f"Exported {len(encounters)} encounters to {os.path.basename(path)}")
        except Exception as e:
            self._status_label.configure(text=f"Export failed: {e}")

    def _export_encounter_detail_csv(self):
        """Export the currently selected encounter detail with player + ability rows."""
        eid = self._meter_selected_eid
        enc = self._backend.tracker.get_encounter_detail(eid) if eid else None
        if enc is None:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r'[^\w]', '_', enc.npc_name)[:20]
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"encounter_{safe_name}_{ts}.csv",
            title="Export Encounter Detail",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["npc_name", "npc_class", "npc_level", "status",
                            "total_damage", "duration_s", "dps",
                            "player_name", "player_class", "player_level",
                            "player_dealt", "player_dps", "player_received",
                            "ability", "ability_damage"])
                status = "DEAD" if enc.is_dead else "LIVE"
                dur = round(enc.duration, 1)
                dps = round(enc.dps, 1)
                players = sorted(enc.players.values(),
                                 key=lambda p: max(p['text_dealt'], p['dealt']),
                                 reverse=True)
                if players:
                    for p in players:
                        dealt = max(p['text_dealt'], p['dealt'])
                        p_dps = round(dealt / enc.duration, 1) if enc.duration > 0 else 0
                        abilities = sorted(p.get('abilities', {}).items(),
                                           key=lambda x: x[1], reverse=True)
                        if abilities:
                            for ab_name, ab_dmg in abilities:
                                w.writerow([
                                    enc.npc_name, enc.npc_class or "",
                                    enc.npc_level or "", status,
                                    enc.best_damage, dur, dps,
                                    p['name'], p['cls'] or "",
                                    p['level'] or "", dealt, p_dps,
                                    p['received'], ab_name, ab_dmg,
                                ])
                        else:
                            w.writerow([
                                enc.npc_name, enc.npc_class or "",
                                enc.npc_level or "", status,
                                enc.best_damage, dur, dps,
                                p['name'], p['cls'] or "",
                                p['level'] or "", dealt, p_dps,
                                p['received'], "", "",
                            ])
                else:
                    w.writerow([
                        enc.npc_name, enc.npc_class or "",
                        enc.npc_level or "", status,
                        enc.best_damage, dur, dps,
                        "", "", "", 0, 0, 0, "", "",
                    ])
            self._status_label.configure(
                text=f"Exported {enc.npc_name} detail to {os.path.basename(path)}")
        except Exception as e:
            self._status_label.configure(text=f"Export failed: {e}")

    def _export_totals_csv(self):
        """Export encounter totals with NPC aggregation, player breakdown, and abilities."""
        tracker = self._backend.tracker
        encounters = tracker.get_encounters(top_n=999)
        if not encounters:
            return

        # Aggregate by NPC name + grand player abilities
        npc_agg = {}
        player_totals = {}
        for enc in encounters:
            key = enc.npc_name
            if key not in npc_agg:
                npc_agg[key] = {
                    'count': 0, 'total_dmg': 0, 'total_dur': 0.0,
                    'npc_class': enc.npc_class, 'npc_level': enc.npc_level,
                    'players': {},
                }
            agg = npc_agg[key]
            agg['count'] += 1
            agg['total_dmg'] += enc.best_damage
            agg['total_dur'] += enc.duration
            if enc.npc_class and not agg['npc_class']:
                agg['npc_class'] = enc.npc_class
            if enc.npc_level is not None and agg['npc_level'] is None:
                agg['npc_level'] = enc.npc_level
            for p_eid, p in enc.players.items():
                pname = p['name']
                p_dealt = max(p['text_dealt'], p['dealt'])
                p_cls = tracker.classes.get(p_eid) or p['cls']
                p_lvl = tracker.levels.get(p_eid) if tracker.levels.get(p_eid) is not None else p['level']
                if pname not in agg['players']:
                    agg['players'][pname] = {
                        'cls': p_cls, 'level': p_lvl,
                        'dealt': 0, 'received': 0, 'count': 0,
                    }
                pa = agg['players'][pname]
                pa['dealt'] += p_dealt
                pa['received'] += p['received']
                pa['count'] += 1
                if p_cls and not pa['cls']:
                    pa['cls'] = p_cls
                if p_lvl is not None and pa['level'] is None:
                    pa['level'] = p_lvl
                # Grand player totals + abilities
                if pname not in player_totals:
                    player_totals[pname] = {
                        'cls': p_cls, 'level': p_lvl,
                        'dealt': 0, 'abilities': {},
                    }
                pt = player_totals[pname]
                pt['dealt'] += p_dealt
                if p_cls and not pt['cls']:
                    pt['cls'] = p_cls
                if p_lvl is not None and pt['level'] is None:
                    pt['level'] = p_lvl
                for ab_name, ab_dmg in p.get('abilities', {}).items():
                    pt['abilities'][ab_name] = pt['abilities'].get(ab_name, 0) + ab_dmg

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"encounter_totals_{ts}.csv",
            title="Export Encounter Totals",
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                # Grand totals section
                w.writerow(["section", "name", "class", "level",
                            "encounters", "total_damage", "avg_damage",
                            "total_duration", "ability", "ability_damage"])
                grand_dmg = sum(a['total_dmg'] for a in npc_agg.values())
                grand_dur = sum(a['total_dur'] for a in npc_agg.values())
                grand_cnt = sum(a['count'] for a in npc_agg.values())
                w.writerow(["GRAND_TOTAL", "", "", "", grand_cnt,
                            grand_dmg, round(grand_dmg / grand_cnt) if grand_cnt else 0,
                            round(grand_dur, 1), "", ""])
                # Grand player breakdown with abilities
                for pname in sorted(player_totals, key=lambda n: player_totals[n]['dealt'], reverse=True):
                    pt = player_totals[pname]
                    abilities = sorted(pt['abilities'].items(), key=lambda x: x[1], reverse=True)
                    if abilities:
                        for ab_name, ab_dmg in abilities:
                            w.writerow(["PLAYER_TOTAL", pname, pt['cls'] or "",
                                        pt['level'] or "", "", pt['dealt'], "",
                                        "", ab_name, ab_dmg])
                    else:
                        w.writerow(["PLAYER_TOTAL", pname, pt['cls'] or "",
                                    pt['level'] or "", "", pt['dealt'], "",
                                    "", "", ""])
                # Per-NPC section with player sub-rows
                for npc_name, agg in sorted(npc_agg.items(), key=lambda x: x[1]['total_dmg'], reverse=True):
                    avg_dmg = agg['total_dmg'] / agg['count'] if agg['count'] > 0 else 0
                    sorted_players = sorted(agg['players'].items(), key=lambda x: x[1]['dealt'], reverse=True)
                    if sorted_players:
                        for pname, pa in sorted_players:
                            avg_dealt = pa['dealt'] / pa['count'] if pa['count'] > 0 else 0
                            w.writerow(["BY_NPC", npc_name, agg['npc_class'] or "",
                                        agg['npc_level'] or "", agg['count'],
                                        agg['total_dmg'], round(avg_dmg),
                                        round(agg['total_dur'], 1),
                                        pname, pa['dealt']])
                    else:
                        w.writerow(["BY_NPC", npc_name, agg['npc_class'] or "",
                                    agg['npc_level'] or "", agg['count'],
                                    agg['total_dmg'], round(avg_dmg),
                                    round(agg['total_dur'], 1), "", ""])
            self._status_label.configure(text=f"Exported totals to {os.path.basename(path)}")
        except Exception as e:
            self._status_label.configure(text=f"Export failed: {e}")

    def _refresh_stats(self):
        # Sync auto-detected player name from tracker
        tracker_name = self._backend._tracker.player_name
        if (tracker_name
                and tracker_name != "YOU"
                and tracker_name != self._backend.player_name):
            self._backend.player_name = tracker_name
            tag = tracker_name
            sn = self._backend.server_name
            if sn:
                tag += f" | {sn}"
            self._player_label.configure(text=tag)
            title = f"ZekParser {APP_VERSION} \u2014 {tracker_name}"
            if sn:
                title += f" [{sn}]"
            self.title(title)
        self._stats_id = self.after(3000, self._refresh_stats)

    # --- Left Panel Toggle ---

    def _toggle_left_panel(self):
        """Hide or show the entire left panel (feed/items/triggers)."""
        cur_w = self.winfo_width()
        cur_h = self.winfo_height()
        cur_x = self.winfo_x()
        cur_y = self.winfo_y()
        if self._left_visible:
            self._saved_expanded_w = cur_w
            self._left_frame.grid_remove()
            self._divider.grid_remove()
            self._main_frame.columnconfigure(0, weight=0, uniform='')
            self._main_frame.columnconfigure(2, weight=1, uniform='')
            self._toggle_left_btn.configure(text="\u25B6")
            self._left_visible = False
            new_w = max(400, cur_w // 2)
            new_x = cur_x + (cur_w - new_w)
            self.geometry(f"{new_w}x{cur_h}+{new_x}+{cur_y}")
            self.minsize(350, 220)
        else:
            self._left_frame.grid()
            self._divider.grid()
            self._main_frame.columnconfigure(0, weight=1, uniform='half')
            self._main_frame.columnconfigure(2, weight=1, uniform='half')
            self._toggle_left_btn.configure(text="\u25C0")
            self._left_visible = True
            new_w = getattr(self, '_saved_expanded_w', None) or max(850, cur_w * 2)
            new_x = cur_x + cur_w - new_w
            if new_x < 0:
                new_x = 0
            self.geometry(f"{new_w}x{cur_h}+{new_x}+{cur_y}")
            self.minsize(600, 220)

    # --- Left Panel Tab Switching ---

    def _hide_left_view(self):
        """Pack-forget all widgets for the current left view."""
        v = self._left_view
        if v == "feed":
            self._feed.pack_forget()
            self._feed_sy.pack_forget()
            self._feed_sx.pack_forget()
        elif v in ("items", "item_detail"):
            self._item_back_btn.pack_forget()
            self._item_view.pack_forget()
            self._item_scroll_y.pack_forget()
            self._item_scroll_x.pack_forget()
            for w in self._item_buttons:
                w.destroy()
            self._item_buttons.clear()
        elif v == "triggers":
            self._trigger_add_frame.pack_forget()
            self._trigger_view.pack_forget()
            self._trigger_scroll_y.pack_forget()
            for w in self._trigger_buttons:
                w.destroy()
            self._trigger_buttons.clear()
        elif v == "experience":
            self._xp_view.pack_forget()
            self._xp_scroll_y.pack_forget()

    def _switch_left_tab(self, target):
        """Switch to target view: 'feed', 'items', 'triggers', or 'experience'."""
        if target == self._left_view:
            return
        if target == "items" and self._left_view == "item_detail":
            self._on_item_back()
            return
        self._hide_left_view()

        if target == "feed":
            self._feed_sy.pack(side=tk.RIGHT, fill=tk.Y)
            self._feed_sx.pack(side=tk.BOTTOM, fill=tk.X)
            self._feed.pack(fill=tk.BOTH, expand=True)
            self._left_view = "feed"
            self._item_selected_name = None
            self._item_fingerprint = None
        elif target == "items":
            self._item_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
            self._item_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
            self._item_view.pack(fill=tk.BOTH, expand=True)
            self._left_view = "items"
            self._item_selected_name = None
            self._item_fingerprint = None  # force redraw
        elif target == "triggers":
            self._trigger_add_frame.pack(fill=tk.X, pady=(2, 0))
            self._trigger_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
            self._trigger_view.pack(fill=tk.BOTH, expand=True)
            self._left_view = "triggers"
            self._trigger_fingerprint = None  # force redraw
        elif target == "experience":
            self._xp_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
            self._xp_view.pack(fill=tk.BOTH, expand=True)
            self._left_view = "experience"
            self._xp_fingerprint = None  # force redraw

        self._update_tab_styles()

    def _on_left_view_change(self, event=None):
        """Handle left panel dropdown selection."""
        label = self._left_view_var.get()
        view_map = {"Feed": "feed", "Items": "items", "Triggers": "triggers", "Experience": "experience"}
        target = view_map.get(label, "feed")
        self._switch_left_tab(target)
        # Unfocus the combobox
        try:
            self._feed.focus_set()
        except Exception:
            pass

    def _update_tab_styles(self):
        """Sync the dropdown to the current left view."""
        label_map = {"feed": "Feed", "items": "Items", "item_detail": "Items", "triggers": "Triggers", "experience": "Experience"}
        self._left_view_var.set(label_map.get(self._left_view, "Feed"))

    # --- Item Tracker ---

    def _refresh_items(self):
        """Periodic refresh for item tracker (1s interval)."""
        if self._left_view in ("items", "item_detail"):
            summary = self._backend.get_item_summary()
            fp = tuple((s["name"], s["count"]) for s in summary)
            if self._left_view == "item_detail":
                # Include selected item details in fingerprint
                sel = self._item_selected_name
                drops = self._backend.get_item_drops_for(sel) if sel else []
                fp = (fp, sel, len(drops))
            if fp != self._item_fingerprint:
                self._item_fingerprint = fp
                scroll_pos = self._item_view.yview()[0]
                if self._left_view == "item_detail":
                    self._render_item_detail()
                else:
                    self._render_item_list()
                self._item_view.after_idle(
                    lambda: self._item_view.yview_moveto(scroll_pos))
        self._item_id = self.after(1000, self._refresh_items)

    def _render_item_list(self):
        """Render clickable item rows in the item tracker."""
        summary = self._backend.get_item_summary()

        # Clear old embedded widgets
        for w in self._item_buttons:
            w.destroy()
        self._item_buttons.clear()

        self._item_view.configure(state=tk.NORMAL)
        self._item_view.delete('1.0', tk.END)

        if not summary:
            self._item_view.insert(tk.END, "  No items looted yet\n", 'item_count')
            self._item_view.configure(state=tk.DISABLED)
            return

        for entry in summary:
            name = entry["name"]
            count = entry["count"]
            hid = entry.get("hid")

            # Build compact stats preview
            stats_preview = ""
            if hid:
                rec = self._backend.get_item_record(hid)
                if rec:
                    stats_preview = self._item_stats_preview(rec)

            label_text = f"  {name}  x{count}"
            if stats_preview:
                label_text += f"   {stats_preview}"

            row = tk.Frame(self._item_view, bg=COLORS['bg_darker'])
            btn = tk.Button(
                row, text=label_text, anchor=tk.W,
                bg=COLORS['surface'], fg=COLORS['yellow'],
                activebackground=COLORS['border'], activeforeground=COLORS['yellow'],
                font=('Consolas', 9), relief=tk.FLAT, padx=4, pady=2,
                cursor="hand2",
                command=lambda n=name: self._on_item_click(n),
            )
            btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

            self._item_view.window_create(tk.END, window=row, stretch=True)
            self._item_view.insert(tk.END, '\n')
            self._item_buttons.append(row)

        self._item_view.configure(state=tk.DISABLED)

    def _item_stats_preview(self, rec):
        """Build a short stats preview string for an item list row."""
        parts = []
        if rec.get("damage"):
            delay = rec.get("delay")
            parts.append(f"DMG:{rec['damage']}/{delay}" if delay else f"DMG:{rec['damage']}")
        if rec.get("ac"):
            parts.append(f"AC:{rec['ac']}")
        stat_map = [("strength", "STR"), ("stamina", "STA"), ("dexterity", "DEX"),
                    ("agility", "AGI"), ("intelligence", "INT"), ("wisdom", "WIS"),
                    ("charisma", "CHA")]
        for key, label in stat_map:
            v = rec.get(key)
            if v and v != 0:
                parts.append(f"{label}:{v:+d}")
        if rec.get("health"):
            parts.append(f"HP:{rec['health']:+d}")
        if rec.get("mana"):
            parts.append(f"Mana:{rec['mana']:+d}")
        return " | ".join(parts[:5])  # limit preview width

    def _render_item_detail(self):
        """Render full item stats view for the selected item."""
        name = self._item_selected_name
        if not name:
            self._left_view = "items"
            self._on_item_back()
            return

        drops = self._backend.get_item_drops_for(name)
        # Find the item record from any drop with a valid HID
        rec = None
        for d in drops:
            if d.get("hid"):
                rec = self._backend.get_item_record(d["hid"])
                if rec:
                    break

        total_count = sum(d.get("quantity", 1) for d in drops)

        # Clear old embedded widgets
        for w in self._item_buttons:
            w.destroy()
        self._item_buttons.clear()

        self._item_view.configure(state=tk.NORMAL)
        self._item_view.delete('1.0', tk.END)

        # Header: name and count
        self._item_view.insert(tk.END, f"  {name}", 'item_name')
        self._item_view.insert(tk.END, f"  x{total_count}\n", 'item_count')
        self._item_view.insert(tk.END,
            "  " + "\u2500" * 40 + "\n", 'header_line')

        # Show HID from item record or from drops
        hid_val = None
        if rec:
            hid_val = rec.get("hid", "")
        if not hid_val:
            for d in drops:
                if d.get("hid"):
                    hid_val = d["hid"]
                    break
        if hid_val:
            self._item_view.insert(tk.END, "  HID: ", 'stat_label')
            self._item_view.insert(tk.END, f"{hid_val}\n", 'stat_value')

        if rec:

            # AC / Damage
            if rec.get("ac"):
                self._item_view.insert(tk.END, "  AC: ", 'stat_label')
                self._item_view.insert(tk.END, f"{rec['ac']}\n", 'stat_value')
            if rec.get("damage"):
                self._item_view.insert(tk.END, "  Damage: ", 'stat_label')
                delay = rec.get("delay")
                dtxt = f"{rec['damage']} / {delay} delay" if delay else str(rec['damage'])
                self._item_view.insert(tk.END, f"{dtxt}\n", 'stat_value')

            # Slot / Type / Level
            if rec.get("slot_mask") is not None and rec["slot_mask"] != 0:
                self._item_view.insert(tk.END, "  Slot: ", 'stat_label')
                self._item_view.insert(tk.END, f"{rec['slot_mask']}\n",
                                       'stat_value')
            if rec.get("item_type") is not None and rec["item_type"] != 0:
                self._item_view.insert(tk.END, "  Type: ", 'stat_label')
                self._item_view.insert(tk.END, f"{rec['item_type']}\n",
                                       'stat_value')
            if rec.get("required_level") is not None and rec["required_level"] > 0:
                self._item_view.insert(tk.END, "  Required Level: ", 'stat_label')
                self._item_view.insert(tk.END, f"{rec['required_level']}\n",
                                       'stat_value')

            # Class / Race
            cm = rec.get("class_mask")
            if cm is not None and cm != 0:
                cbits = bin(cm).count('1')
                clbl = "All Classes" if cbits >= 15 else f"{cbits} Classes"
                self._item_view.insert(tk.END, "  Class: ", 'stat_label')
                self._item_view.insert(tk.END, f"{clbl}\n", 'stat_value')
            rm = rec.get("race_mask")
            if rm is not None and rm != 0:
                rbits = bin(rm).count('1')
                rlbl = "All Races" if rbits >= 12 else f"{rbits} Races"
                self._item_view.insert(tk.END, "  Race: ", 'stat_label')
                self._item_view.insert(tk.END, f"{rlbl}\n", 'stat_value')

            # Flags
            flags = []
            if rec.get("is_magic"):
                flags.append("MAGIC")
            if rec.get("no_drop"):
                flags.append("NO DROP")
            if rec.get("is_unique"):
                flags.append("UNIQUE")
            if flags:
                self._item_view.insert(tk.END, "  " + "  ".join(flags) + "\n",
                                       'flag')

            # Primary stats
            stat_map = [
                ("strength", "Strength"), ("stamina", "Stamina"),
                ("dexterity", "Dexterity"), ("agility", "Agility"),
                ("intelligence", "Intelligence"), ("wisdom", "Wisdom"),
                ("charisma", "Charisma"),
            ]
            has_stat = False
            for key, label in stat_map:
                v = rec.get(key)
                if v and v != 0:
                    if not has_stat:
                        self._item_view.insert(tk.END, "\n")
                        has_stat = True
                    self._item_view.insert(tk.END, f"  {label}: ", 'stat_label')
                    tag = 'stat_positive' if v > 0 else 'stat_negative'
                    self._item_view.insert(tk.END, f"{v:+d}\n", tag)

            # HP/Mana/Regen
            pool_map = [
                ("health", "Health"), ("mana", "Mana"),
                ("health_regen", "Health Regen"), ("mana_regen", "Mana Regen"),
            ]
            has_pool = False
            for key, label in pool_map:
                v = rec.get(key)
                if v and v != 0:
                    if not has_pool:
                        self._item_view.insert(tk.END, "\n")
                        has_pool = True
                    self._item_view.insert(tk.END, f"  {label}: ", 'stat_label')
                    tag = 'stat_positive' if v > 0 else 'stat_negative'
                    self._item_view.insert(tk.END, f"{v:+d}\n", tag)

            # Haste
            haste_map = [
                ("melee_haste", "Melee Haste"), ("ranged_haste", "Ranged Haste"),
                ("spell_haste", "Spell Haste"),
            ]
            has_haste = False
            for key, label in haste_map:
                v = rec.get(key)
                if v and v != 0:
                    if not has_haste:
                        self._item_view.insert(tk.END, "\n")
                        has_haste = True
                    self._item_view.insert(tk.END, f"  {label}: ", 'stat_label')
                    tag = 'stat_positive' if v > 0 else 'stat_negative'
                    self._item_view.insert(tk.END, f"{v:+d}\n", tag)

            # Resists
            resist_map = [
                ("resist_fire", "Fire Resist"), ("resist_cold", "Cold Resist"),
                ("resist_poison", "Poison Resist"), ("resist_disease", "Disease Resist"),
                ("resist_magic", "Magic Resist"), ("resist_arcane", "Arcane Resist"),
                ("resist_nature", "Nature Resist"), ("resist_holy", "Holy Resist"),
            ]
            has_resist = False
            for key, label in resist_map:
                v = rec.get(key)
                if v and v != 0:
                    if not has_resist:
                        self._item_view.insert(tk.END, "\n")
                        has_resist = True
                    self._item_view.insert(tk.END, f"  {label}: ", 'stat_label')
                    tag = 'stat_positive' if v > 0 else 'stat_negative'
                    self._item_view.insert(tk.END, f"{v:+d}\n", tag)

            # Weight
            if rec.get("weight"):
                self._item_view.insert(tk.END, "\n")
                self._item_view.insert(tk.END, "  Weight: ", 'stat_label')
                self._item_view.insert(tk.END, f"{rec['weight']:.1f}\n", 'stat_value')

            # Description
            desc = rec.get("description")
            if desc:
                self._item_view.insert(tk.END, "\n")
                self._item_view.insert(tk.END, f'  "{desc}"\n', 'description')

            # Effects
            effects = rec.get("effects")
            if effects and isinstance(effects, list):
                self._item_view.insert(tk.END, "\n")
                for eff in effects:
                    self._item_view.insert(tk.END, f"  Effect: {eff}\n", 'effect')

        # Looted By summary
        looter_counts = {}
        for d in drops:
            who = d.get("looter")
            if who:
                looter_counts[who] = looter_counts.get(who, 0) + d.get("quantity", 1)
        if looter_counts:
            self._item_view.insert(tk.END, "\n")
            self._item_view.insert(tk.END,
                "  " + "\u2500" * 40 + "\n", 'header_line')
            self._item_view.insert(tk.END, "  Looted By:\n", 'stat_label')
            sorted_looters = sorted(looter_counts.items(), key=lambda x: x[1], reverse=True)
            for who, cnt in sorted_looters:
                self._item_view.insert(tk.END, f"    {who}", 'npc_name')
                self._item_view.insert(tk.END, f"  x{cnt}\n", 'item_count')

        # Drop history
        self._item_view.insert(tk.END, "\n")
        self._item_view.insert(tk.END,
            "  " + "\u2500" * 40 + "\n", 'header_line')
        self._item_view.insert(tk.END, "  Drop History:\n", 'stat_label')
        recent = drops[-10:]  # last 10 drops
        for d in reversed(recent):
            ts = time.strftime("%H:%M:%S", time.localtime(d["timestamp"]))
            npc = d.get("npc_name")
            qty = d.get("quantity", 1)
            looter = d.get("looter")
            line = f"    {ts}"
            if qty > 1:
                line += f" x{qty}"
            if looter:
                self._item_view.insert(tk.END, f"{line} ", 'stat_value')
                self._item_view.insert(tk.END, f"{looter}", 'npc_name')
                if npc:
                    self._item_view.insert(tk.END, f" from ", 'stat_value')
                    self._item_view.insert(tk.END, f"{npc}\n", 'npc_name')
                else:
                    self._item_view.insert(tk.END, "\n")
            elif npc:
                self._item_view.insert(tk.END, f"{line} from ", 'stat_value')
                self._item_view.insert(tk.END, f"{npc}\n", 'npc_name')
            else:
                self._item_view.insert(tk.END, f"{line}\n", 'stat_value')

        self._item_view.configure(state=tk.DISABLED)

    def _on_detail_back(self):
        """Handle back button — return to item list."""
        self._on_item_back()

    def _on_item_click(self, name):
        """Handle clicking an item row — switch to detail view."""
        self._item_selected_name = name
        self._left_view = "item_detail"
        self._item_back_btn.pack(side=tk.LEFT, padx=4, after=self._left_combo)
        self._item_fingerprint = None  # force redraw
        self._render_item_detail()

    def _on_item_back(self):
        """Return from item detail to item list."""
        self._item_back_btn.pack_forget()
        self._left_view = "items"
        self._item_selected_name = None
        self._item_fingerprint = None  # force redraw
        self._render_item_list()

    # --- Triggers ---

    def _refresh_triggers(self):
        """500ms timer: drain sound queue (always), redraw trigger list (if viewing)."""
        # Drain sound queue regardless of which view is active
        while True:
            try:
                path = self._backend._trigger_sound_queue.get_nowait()
            except queue.Empty:
                break
            try:
                winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
            except Exception:
                pass

        # Redraw trigger list if on triggers tab
        if self._left_view == "triggers":
            snapshot = self._backend.get_trigger_snapshot()
            fp = tuple((p, c) for p, _, c in snapshot)
            if fp != self._trigger_fingerprint:
                self._trigger_fingerprint = fp
                self._render_trigger_list(snapshot)

        self._trigger_id = self.after(500, self._refresh_triggers)

    def _render_trigger_list(self, snapshot=None):
        """Render the trigger list in the trigger view."""
        if snapshot is None:
            snapshot = self._backend.get_trigger_snapshot()

        # Destroy old embedded widgets
        for w in self._trigger_buttons:
            w.destroy()
        self._trigger_buttons.clear()

        self._trigger_view.configure(state=tk.NORMAL)
        self._trigger_view.delete("1.0", tk.END)

        if not snapshot:
            self._trigger_view.insert(tk.END, "\n  Triggers match text patterns in real-time\n", 'help_text')
            self._trigger_view.insert(tk.END, "  and play audio alerts when matched.\n\n", 'help_text')
            self._trigger_view.insert(tk.END, "  Add a pattern above to get started.\n", 'help_text')
            self._trigger_view.insert(tk.END, "  Matching is case-insensitive.\n\n", 'help_text')
            self._trigger_view.insert(tk.END, "  Examples:\n", 'help_text')
            self._trigger_view.insert(tk.END, '    "tells you"       — whisper alert\n', 'help_text')
            self._trigger_view.insert(tk.END, '    "has been slain"   — kill alert\n', 'help_text')
            self._trigger_view.insert(tk.END, '    "resisted"         — resist tracking\n', 'help_text')
            self._trigger_view.configure(state=tk.DISABLED)
            return

        for pattern, sound_label, count in snapshot:
            # Remove button (✖)
            btn = tk.Button(
                self._trigger_view, text="\u2716", fg=COLORS['red'],
                bg=COLORS['bg_darker'], activebackground=COLORS['surface'],
                activeforeground=COLORS['red'], relief=tk.FLAT,
                font=('Consolas', 9), cursor="hand2", bd=0,
                command=lambda p=pattern: self._remove_trigger(p))
            self._trigger_buttons.append(btn)
            self._trigger_view.window_create(tk.END, window=btn)

            self._trigger_view.insert(tk.END, "  ")
            self._trigger_view.insert(tk.END, f'"{pattern}"', 'pattern')

            count_str = f"  x{count}" if count > 0 else ""
            if count_str:
                self._trigger_view.insert(tk.END, f"  x{count}", 'count')

            if sound_label and sound_label != "(none)":
                self._trigger_view.insert(tk.END, f"  [{sound_label}]", 'sound')

            self._trigger_view.insert(tk.END, "\n")

        self._trigger_view.configure(state=tk.DISABLED)

    def _add_trigger(self):
        """Add a trigger from the entry fields."""
        pattern = self._trigger_pattern_entry.get().strip()
        if not pattern:
            return
        sound_label = self._trigger_sound_var.get()
        sound_path = None
        for name, path in TRIGGER_SOUNDS:
            if name == sound_label:
                sound_path = path
                break
        self._backend.add_trigger(pattern, sound_path, sound_label)
        self._trigger_pattern_entry.delete(0, tk.END)
        self._trigger_fingerprint = None  # force redraw

    def _remove_trigger(self, pattern):
        """Remove a trigger by pattern."""
        self._backend.remove_trigger(pattern)
        self._trigger_fingerprint = None  # force redraw

    def _preview_trigger_sound(self):
        """Play the currently selected sound from the combobox."""
        sound_label = self._trigger_sound_var.get()
        for name, path in TRIGGER_SOUNDS:
            if name == sound_label and path:
                try:
                    winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
                except Exception:
                    pass
                return

    # --- Chat log ---

    def _toggle_chat_log(self):
        """Toggle chat logging to a text file on/off."""
        if not self._chatlog_var.get():
            # Turn off
            self._backend.chat_log_enabled = False
            try:
                if self._chat_log_file:
                    self._chat_log_file.close()
            except Exception:
                pass
            self._chat_log_file = None
            self._status_label.configure(
                text=f"Chat log saved: {os.path.basename(self._chat_log_path)}")
        else:
            # Turn on — create file in parser/logs/
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
            os.makedirs(log_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self._chat_log_path = os.path.join(log_dir, f"chat_{ts}.txt")
            try:
                self._chat_log_file = open(self._chat_log_path, "a", encoding="utf-8")
                self._chat_log_file.write(f"# Chat log started {datetime.now().isoformat()}\n")
                self._chat_log_file.flush()
            except Exception as e:
                self._status_label.configure(text=f"Chat log failed: {e}")
                self._chatlog_var.set(False)
                return
            self._backend.chat_log_enabled = True
            self._status_label.configure(
                text=f"Chat logging to {os.path.basename(self._chat_log_path)}")

    # --- Experience ---

    def _refresh_experience(self):
        """1s timer: redraw experience view if active and data changed."""
        if self._left_view == "experience":
            tracker = self._backend._tracker
            xp_events = tracker._xp_events
            fp = len(xp_events)
            if fp != self._xp_fingerprint:
                self._xp_fingerprint = fp
                self._render_experience()
        self._xp_id = self.after(1000, self._refresh_experience)

    def _render_experience(self):
        """Render the experience event log in the XP view."""
        tracker = self._backend._tracker
        xp_events = list(tracker._xp_events)  # snapshot

        self._xp_view.configure(state=tk.NORMAL)
        self._xp_view.delete("1.0", tk.END)

        if not xp_events:
            self._xp_view.insert(tk.END, "\n  No experience data yet.\n\n", 'help_text')
            self._xp_view.insert(tk.END, "  XP gains will appear here as\n", 'help_text')
            self._xp_view.insert(tk.END, "  you defeat enemies.\n\n", 'help_text')
            self._xp_view.insert(tk.END, "  Note: XP tracking requires two\n", 'help_text')
            self._xp_view.insert(tk.END, "  kills to start — the first kill\n", 'help_text')
            self._xp_view.insert(tk.END, "  sets your baseline XP.\n", 'help_text')
            self._xp_view.configure(state=tk.DISABLED)
            return

        # Summary at top
        total_gained = sum(e["xp_gained"] for e in xp_events if e["xp_gained"] > 0)
        num_gains = sum(1 for e in xp_events if e["xp_gained"] > 0)
        latest_total = xp_events[-1]["xp_total"] if xp_events else 0
        latest_eid = xp_events[-1]["eid"] if xp_events else None

        # Session duration from first to last XP event
        if len(xp_events) >= 2:
            dur = xp_events[-1]["timestamp"] - xp_events[0]["timestamp"]
            if dur > 0:
                xp_per_hr = total_gained / (dur / 3600)
            else:
                xp_per_hr = 0
        else:
            dur = 0
            xp_per_hr = 0

        self._xp_view.insert(tk.END, " Experience Tracker\n", 'header')
        self._xp_view.insert(tk.END, " " + "\u2500" * 36 + "\n", 'sep')

        # Class display from ClientPartyUpdate / SpawnEntity
        if latest_eid is not None:
            class_hid = tracker.classes.get(latest_eid)
            if class_hid:
                self._xp_view.insert(tk.END, "  Class:     ", 'summary_label')
                self._xp_view.insert(tk.END, f"{_class_label(class_hid)}", 'summary_value')
                self._xp_view.insert(tk.END, "\n")

        # Level progress — XP value is progress into current level
        if latest_eid is not None:
            level = tracker.levels.get(latest_eid)
            level_needed = tracker._xp_level_needed.get(latest_eid)
            if level is not None:
                self._xp_view.insert(tk.END, "  Level:     ", 'summary_label')
                self._xp_view.insert(tk.END, f"{level}", 'summary_value')
                if level_needed:
                    level_pct = latest_total / level_needed * 100
                    self._xp_view.insert(tk.END, f"  ({latest_total:,} / {level_needed:,}  {level_pct:.1f}%)", 'xp_total')
                self._xp_view.insert(tk.END, "\n")

        # Zone from ClientPartyUpdate
        if latest_eid is not None:
            zone_hid = tracker.zones.get(latest_eid)
            if zone_hid:
                zone_label = zone_hid.replace('_', ' ').title()
                self._xp_view.insert(tk.END, "  Zone:      ", 'summary_label')
                self._xp_view.insert(tk.END, f"{zone_label}\n", 'summary_value')

        self._xp_view.insert(tk.END, "  Total:     ", 'summary_label')
        self._xp_view.insert(tk.END, f"+{total_gained:,}", 'summary_value')
        self._xp_view.insert(tk.END, f"  ({num_gains} kills)\n", 'xp_total')

        if xp_per_hr > 0:
            self._xp_view.insert(tk.END, "  XP/hour:   ", 'summary_label')
            self._xp_view.insert(tk.END, f"{xp_per_hr:,.0f}\n", 'summary_value')

        self._xp_view.insert(tk.END, " " + "\u2500" * 36 + "\n\n", 'sep')

        # Individual XP events (newest first)
        for ev in reversed(xp_events):
            ts = time.strftime("%H:%M:%S", time.localtime(ev["timestamp"]))
            gained = ev["xp_gained"]
            npc = ev.get("npc_name", "")
            pct = ev.get("pct")

            self._xp_view.insert(tk.END, f"  {ts}  ", 'xp_total')
            if ev.get("leveled_up"):
                self._xp_view.insert(tk.END, "LEVEL UP!", 'header')
                if gained > 0:
                    self._xp_view.insert(tk.END, f"  +{gained:,} XP", 'xp_gain')
            elif gained > 0:
                self._xp_view.insert(tk.END, f"+{gained:,} XP", 'xp_gain')
                if pct is not None:
                    self._xp_view.insert(tk.END, f" ({pct:.2f}%)", 'xp_total')
            if npc:
                self._xp_view.insert(tk.END, f"  \u2190 ", 'xp_total')
                self._xp_view.insert(tk.END, f"{npc}", 'npc_name')
            self._xp_view.insert(tk.END, "\n")

        self._xp_view.configure(state=tk.DISABLED)

    # --- Cleanup ---

    def _on_close(self):
        if self._chat_log_file:
            try:
                self._chat_log_file.close()
            except Exception:
                pass
        self._backend.stop()
        if self._poll_id:
            self.after_cancel(self._poll_id)
        if self._meter_id:
            self.after_cancel(self._meter_id)
        if self._item_id:
            self.after_cancel(self._item_id)
        if self._trigger_id:
            self.after_cancel(self._trigger_id)
        if self._xp_id:
            self.after_cancel(self._xp_id)
        if self._stats_id:
            self.after_cancel(self._stats_id)
        self.destroy()


# ===================================================================
# Entry point
# ===================================================================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def _crash_log_dir():
    """Return the directory next to the exe (frozen) or next to this .py file."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _show_error(title, msg):
    """Show error via message box (works without console)."""
    try:
        ctypes.windll.user32.MessageBoxW(0, msg, title, 0x10)  # MB_ICONERROR
    except Exception:
        print(f"{title}: {msg}")


def main():
    if not is_admin():
        _show_error("ZekParser", "This tool requires Administrator privileges.\n\n"
                     "Right-click ZekParser and select 'Run as administrator'.")
        sys.exit(1)

    try:
        app = CombatApp()
        app.mainloop()
    except Exception:
        import traceback
        tb = traceback.format_exc()
        crash_path = os.path.join(_crash_log_dir(), "crash.log")
        try:
            with open(crash_path, "w", encoding="utf-8") as f:
                f.write(f"ZekParser crash — {datetime.now().isoformat()}\n\n{tb}")
        except Exception:
            crash_path = "(failed to write)"
        _show_error("ZekParser — Crash",
                     f"An unexpected error occurred.\n\n{tb[:600]}\n\nFull log: {crash_path}")


if __name__ == '__main__':
    try:
        main()
    except Exception:
        import traceback
        tb = traceback.format_exc()
        crash_path = os.path.join(_crash_log_dir(), "crash.log")
        try:
            with open(crash_path, "w", encoding="utf-8") as f:
                f.write(f"ZekParser crash — {datetime.now().isoformat()}\n\n{tb}")
        except Exception:
            pass
        _show_error("ZekParser — Crash", f"Fatal error:\n\n{tb[:600]}")
