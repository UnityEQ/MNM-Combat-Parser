"""
ChatParser — Chat Parser for Monsters & Memories.

No dependencies on core/ or parser/. Requires: pycryptodome, tkinter (stdlib).
Must run as Administrator (raw socket capture).

Usage:
    python chatparser/bot.py
"""

import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import io
import json
import logging
import logging.handlers
import os
import queue
import socket
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
import wave
import winsound


# ---- Half-volume beep WAV (generated once at import) ---------------
def _make_beep_wav(freq=1000, duration_ms=300, volume=0.5, sample_rate=22050):
    """Generate a beep WAV in memory at the given volume (0.0-1.0)."""
    import math
    n_samples = int(sample_rate * duration_ms / 1000)
    amplitude = int(32767 * max(0.0, min(1.0, volume)))
    raw = bytearray(n_samples * 2)
    for i in range(n_samples):
        val = int(amplitude * math.sin(2.0 * math.pi * freq * i / sample_rate))
        struct.pack_into('<h', raw, i * 2, val)
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(bytes(raw))
    return buf.getvalue()

_BEEP_WAV = _make_beep_wav(freq=1000, duration_ms=300, volume=1.0)


# ===================================================================
# Debug logger — writes to chatparser/logs/
# ===================================================================
def _setup_bot_log():
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(log_dir, f"bot_{ts}.log")
    logger = logging.getLogger("chatparser")
    logger.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=10*1024*1024, backupCount=3, encoding="utf-8"
    )
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%H:%M:%S"
    ))
    logger.addHandler(handler)
    return logger

_blog = _setup_bot_log()

try:
    from Crypto.Cipher import AES
except ImportError:
    import subprocess
    print("pycryptodome not found — installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Cipher import AES


# ===================================================================
# Windows API — Process discovery
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

user32 = ctypes.windll.user32


# ===================================================================
# Windows API — SendInput structures for keystroke injection
# ===================================================================

KEYEVENTF_KEYUP = 0x0002
VK_RETURN = 0x0D
VK_SHIFT = 0x10
MAPVK_VK_TO_VSC = 0
user32.SetForegroundWindow.restype = wt.BOOL
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.GetForegroundWindow.restype = wt.HWND
user32.GetForegroundWindow.argtypes = []
user32.GetWindowThreadProcessId.restype = wt.DWORD
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
user32.AttachThreadInput.restype = wt.BOOL
user32.AttachThreadInput.argtypes = [wt.DWORD, wt.DWORD, wt.BOOL]
user32.BringWindowToTop.restype = wt.BOOL
user32.BringWindowToTop.argtypes = [wt.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextLengthW.argtypes = [wt.HWND]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wt.HWND, ctypes.c_wchar_p, ctypes.c_int]
user32.EnumWindows.restype = wt.BOOL
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
user32.IsWindowVisible.restype = wt.BOOL
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.MapVirtualKeyW.restype = wt.UINT
user32.MapVirtualKeyW.argtypes = [wt.UINT, wt.UINT]
user32.VkKeyScanW.restype = ctypes.c_short
user32.VkKeyScanW.argtypes = [wt.WCHAR]
user32.keybd_event.restype = None
user32.keybd_event.argtypes = [wt.BYTE, wt.BYTE, wt.DWORD, ctypes.POINTER(wt.ULONG)]


# ===================================================================
# Process finder
# ===================================================================

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
# Connection monitoring
# ===================================================================

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1


def _dword_to_ip(dword):
    return socket.inet_ntoa(struct.pack("<I", dword))


def _port_from_dword(dword):
    return socket.ntohs(dword & 0xFFFF)


def get_game_connections(pid):
    local_eps = set()
    remote_eps = set()
    local_ports = set()

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
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), "rva_cache.json")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "rva_cache.json")


def _load_rva():
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
    try:
        with open(_rva_config_path(), "w") as f:
            f.write(json.dumps({"typeinfo_rva": rva}))
    except Exception:
        pass


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
        ns_ptr = _read_ptr(handle, class_ptr + 0x18)
        if ns_ptr:
            ns_raw = _read_mem(handle, ns_ptr, 32)
            if ns_raw:
                namespace = ns_raw.split(b'\x00', 1)[0].decode("utf-8", errors="replace")
                if namespace == "Client":
                    return True
                return False
        return True
    except Exception:
        return False


def _scan_for_class(handle, base, mod_size):
    chunk_size = 65536
    search_start = mod_size // 2
    candidates_checked = 0
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
        for i in range(0, read_size - 7, 8):
            ptr_val = struct.unpack_from("<Q", chunk, i)[0]
            if ptr_val < 0x10000 or ptr_val > 0x7FFFFFFFFFFF:
                continue
            if base <= ptr_val < base + mod_size:
                continue
            candidates_checked += 1
            if candidates_checked > 2000000:
                return None, None
            if _validate_class_ptr(handle, ptr_val):
                rva = offset + i
                return ptr_val, rva
    return None, None


def read_encryption_keys(pid):
    global _cached_class_ptr, _scan_attempted
    base, mod_size = find_module_base(pid)
    if not base:
        return None

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None

    try:
        class_ptr = _cached_class_ptr
        if class_ptr and _validate_class_ptr(handle, class_ptr):
            pass
        else:
            class_ptr = None

        if not class_ptr:
            rva = _load_rva()
            if rva < mod_size:
                ptr = _read_ptr(handle, base + rva)
                if ptr and _validate_class_ptr(handle, ptr):
                    class_ptr = ptr
                    _cached_class_ptr = ptr

        if not class_ptr and not _scan_attempted:
            _scan_attempted = True
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
# Decryption pipeline
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
    if len(raw_payload) < 36:
        return None
    data = raw_payload[:-4]
    expected_crc = struct.unpack_from("<I", raw_payload, len(raw_payload) - 4)[0]
    if expected_crc != crc32c(data):
        return None
    if hmac_key and len(hmac_key) > 0:
        if len(data) < 33:
            return None
        msg = data[:-32]
        tag = data[-32:]
        expected_hmac = hmac_mod.new(hmac_key, msg, hashlib.sha256).digest()
        if not hmac_mod.compare_digest(tag, expected_hmac):
            return None
        data = msg
    if len(data) < 32 or len(data) % 16 != 0:
        return None
    iv = data[:16]
    ct = data[16:]
    raw = AES.new(aes_key, AES.MODE_CBC, iv=iv).decrypt(ct)
    plaintext = pkcs7_unpad(raw)
    if plaintext is None:
        return None
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

CONTROL_TYPES = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17}


def parse_lnl_frame(payload):
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
    if prop == 12:  # Merged
        messages = []
        offset = 1
        while offset + 2 <= len(payload):
            msg_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            if msg_len == 0 or offset + msg_len > len(payload):
                break
            sub_payloads = parse_lnl_frame(payload[offset:offset + msg_len])
            messages.extend(sub_payloads)
            offset += msg_len
        return messages
    return [payload[1:]] if len(payload) > 1 else []


def extract_game_messages(plaintext):
    inner_payloads = parse_lnl_frame(plaintext)
    messages = []
    for data in inner_payloads:
        if len(data) >= 2:
            msg_id = struct.unpack_from("<H", data, 0)[0]
            messages.append((msg_id, data[2:]))
    return messages


# ===================================================================
# Wire format helpers
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

def _r_str(data, off):
    if off + 2 > len(data): return None, off
    slen = struct.unpack_from("<H", data, off)[0]
    off += 2
    if slen == 0: return "", off
    if off + slen > len(data): return None, off - 2
    raw = data[off:off + slen]
    stripped = raw
    while stripped and stripped[-1:] < b'\x20':
        stripped = stripped[:-1]
    s = stripped.decode("utf-8", errors="replace").rstrip()
    return s, off + slen


# ===================================================================
# Game message IDs / opcode names
# ===================================================================

OPCODE_NAMES = {
    # Verified from parser/parser.py MESSAGE_IDS
    0x0011: "ChangeTarget",
    0x0012: "Autoattack",
    0x0013: "Die",
    0x0020: "SpawnEntity",
    0x0021: "DespawnEntity",
    0x0022: "UpdateHealth",
    0x0023: "UpdateMana",
    0x0024: "UpdateExperience",
    0x0025: "UpdateLevel",
    0x0027: "UpdateHealthMana",
    0x0040: "ChatMessage",
    0x0050: "CastAbility",
    0x0053: "AddBuffIcon",
    0x0054: "RemoveBuffIcon",
    0x0055: "BeginCasting",
    0x0056: "EndCasting",
    0x005C: "ParticleHit",
    0x0063: "AddItemToInventory",
    0x0065: "LootItemFromCorpse",
    0x007F: "InspectItem",
    0x0080: "ItemInformation",
    0x022F: "UpdateEndurance",
    0x0380: "ClientPartyUpdate",
    0x644B: "CombatAnimation",
}


# ===================================================================
# Message handler — parses chat/combat text from game messages
# ===================================================================

class MessageHandler:
    _OPCODE_LOG_MAX = 5000

    def __init__(self):
        self._lock = threading.Lock()
        self._messages = []       # text triggers (chat/combat only)
        self._opcode_log = []     # rich opcode dicts for browser
        self._names = {}          # eid -> name from SpawnEntity

    def _name(self, eid):
        """Resolve eid to name, or None."""
        return self._names.get(eid) if eid is not None else None

    def process(self, msg_id, body):
        off = 0
        text = None
        fields = {}
        now = time.time()
        opcode_name = OPCODE_NAMES.get(msg_id, f"0x{msg_id:04X}")

        # --- SpawnEntity: track eid -> name ---
        if msg_id == 0x0020:  # SpawnEntity
            eid, off = _r_u32(body, off)
            etype, off = _r_u16(body, off)
            name, off = _r_str(body, off)
            fields["entity_id"] = eid
            fields["entity_type"] = etype
            fields["name"] = name
            if eid is not None and name:
                self._names[eid] = name

        elif msg_id == 0x0040:  # ChatMessage
            channel, off = _r_u32(body, off)
            fields["channel"] = channel
            if channel is not None and channel == 1:
                msg_text, off = _r_str(body, off)
                if msg_text:
                    text = msg_text
                    fields["text"] = text
                    _blog.debug("CHAT_COMBAT: %s", text)
            else:
                msg_text, off = _r_str(body, off)
                if msg_text:
                    fields["text"] = msg_text

        elif msg_id == 0x0056:  # EndCasting
            eid, off = _r_u32(body, off)
            target_id, off = _r_u32(body, off)
            msg_text, off = _r_str(body, off)
            fields["entity_id"] = eid
            fields["entity_name"] = self._name(eid)
            fields["target_id"] = target_id
            fields["target_name"] = self._name(target_id)
            if msg_text:
                text = msg_text
                fields["text"] = text
                _blog.debug("END_CASTING: %s", text)

        elif msg_id == 0x0013:  # Die
            eid, off = _r_u32(body, off)
            fields["entity_id"] = eid
            fields["entity_name"] = self._name(eid)
            if eid is not None:
                name = self._name(eid) or f"Entity#{eid}"
                text = f"{name} has died."
                _blog.debug("DIE: %s (eid=%d)", name, eid)

        elif msg_id == 0x0022:  # UpdateHealth
            eid, off = _r_u32(body, off)
            hp, off = _r_i32(body, off)
            max_hp, off = _r_i32(body, off)
            fields["entity_id"] = eid
            fields["entity_name"] = self._name(eid)
            fields["hp"] = hp
            fields["max_hp"] = max_hp

        elif msg_id == 0x0027:  # UpdateHealthMana
            eid, off = _r_u32(body, off)
            hp, off = _r_i32(body, off)
            max_hp, off = _r_i32(body, off)
            mp, off = _r_i32(body, off)
            max_mp, off = _r_i32(body, off)
            fields["entity_id"] = eid
            fields["entity_name"] = self._name(eid)
            fields["hp"] = hp
            fields["max_hp"] = max_hp
            fields["mp"] = mp
            fields["max_mp"] = max_mp

        elif msg_id == 0x0024:  # UpdateExperience
            eid, off = _r_u32(body, off)
            xp, off = _r_u32(body, off)
            fields["entity_id"] = eid
            fields["entity_name"] = self._name(eid)
            fields["experience"] = xp

        elif msg_id == 0x0055:  # BeginCasting
            eid, off = _r_u32(body, off)
            target_id, off = _r_u32(body, off)
            msg_text, off = _r_str(body, off)
            fields["entity_id"] = eid
            fields["entity_name"] = self._name(eid)
            fields["target_id"] = target_id
            fields["target_name"] = self._name(target_id)
            if msg_text:
                fields["text"] = msg_text

        elif msg_id == 0x0021:  # DespawnEntity
            eid, off = _r_u32(body, off)
            fields["entity_id"] = eid
            fields["entity_name"] = self._name(eid)

        # Build hex preview of first 32 bytes for detail view
        raw_hex = body[:32].hex(' ') if body else ""

        # Strip None-valued fields so they don't clutter the UI
        fields = {k: v for k, v in fields.items() if v is not None}

        with self._lock:
            if text:
                self._messages.append({"text": text, "timestamp": now})
            entry = {
                "opcode": msg_id,
                "opcode_name": opcode_name,
                "fields": fields,
                "raw_len": len(body),
                "raw_hex": raw_hex,
                "timestamp": now,
            }
            self._opcode_log.append(entry)
            if len(self._opcode_log) > self._OPCODE_LOG_MAX:
                self._opcode_log = self._opcode_log[-self._OPCODE_LOG_MAX:]

    def get_messages(self):
        with self._lock:
            msgs = self._messages[:]
            self._messages.clear()
        return msgs

    def get_opcode_messages(self):
        with self._lock:
            msgs = self._opcode_log[:]
            self._opcode_log.clear()
        return msgs


# ===================================================================
# Trigger system — persistent pattern matching
# ===================================================================

def _triggers_path():
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), "triggers.json")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "triggers.json")


def _load_triggers():
    try:
        with open(_triggers_path(), "r") as f:
            data = json.loads(f.read())
            if isinstance(data, list):
                result = []
                for t in data:
                    if isinstance(t, dict) and "pattern" in t:
                        ttype = t.get("type", "text")
                        if ttype == "opcode":
                            result.append({
                                "type": "opcode",
                                "opcode": t.get("opcode", 0),
                                "field": t.get("field", "text"),
                                "pattern": t["pattern"],
                                "loop": t.get("loop", True),
                                "sound": t.get("sound", False),
                            })
                        else:
                            result.append({
                                "type": "text",
                                "pattern": t["pattern"],
                                "loop": t.get("loop", True),
                                "sound": t.get("sound", False),
                            })
                return result
    except Exception:
        pass
    return []


def _save_triggers(triggers):
    try:
        with open(_triggers_path(), "w") as f:
            f.write(json.dumps(triggers, indent=2))
    except Exception:
        pass


# ===================================================================
# Capture backend — simplified for bot
# ===================================================================

class CaptureBackend:
    def __init__(self, status_callback=None):
        self._status_cb = status_callback
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
        self.message_handler = MessageHandler()
        self.connected = False
        self.has_keys = False

    def _status(self, msg):
        if self._status_cb:
            self._status_cb(msg)

    def start(self):
        self._stop.clear()
        t = threading.Thread(target=self._lifecycle_loop, daemon=True, name="Lifecycle")
        t.start()
        self._threads.append(t)

    def stop(self):
        self._stop.set()
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
        self._status("Waiting for game...")
        _blog.info("LIFECYCLE waiting for game process...")
        while not self._stop.is_set():
            pid = find_game_pid()
            if pid:
                self._pid = pid
                self._status("Game found, connecting...")
                _blog.info("LIFECYCLE game found pid=%d", pid)
                self.connected = True
                break
            self._stop.wait(2)

        if self._stop.is_set():
            return

        threads = [
            threading.Thread(target=self._conn_loop, daemon=True, name="ConnMon"),
            threading.Thread(target=self._key_loop, daemon=True, name="KeyWatch"),
            threading.Thread(target=self._capture_loop, daemon=True, name="Capture"),
            threading.Thread(target=self._process_loop, daemon=True, name="Process"),
        ]
        for t in threads:
            t.start()
            self._threads.append(t)

        while not self._stop.is_set():
            if not is_process_alive(self._pid):
                self._status("Game exited, waiting...")
                self.connected = False
                self.has_keys = False
                while not self._stop.is_set():
                    pid = find_game_pid()
                    if pid:
                        self._pid = pid
                        self._status("Reconnected")
                        self.connected = True
                        break
                    self._stop.wait(2)
            self._stop.wait(3)

    def _conn_loop(self):
        while not self._stop.is_set():
            if self._pid:
                try:
                    local_eps, remote_eps, local_ports = get_game_connections(self._pid)
                    with self._conn_lock:
                        self._local_eps = local_eps
                        self._remote_eps = remote_eps
                        self._local_ports = local_ports
                    _blog.debug("CONN local_eps=%s remote_eps=%s local_ports=%s",
                                local_eps, remote_eps, local_ports)
                except Exception as e:
                    _blog.warning("CONN error: %s", e)
            self._stop.wait(5)

    def _key_loop(self):
        while not self._stop.is_set():
            if self._pid:
                try:
                    keys = read_encryption_keys(self._pid)
                    if keys and keys.get("aes_key"):
                        with self._key_lock:
                            self._aes_key = keys["aes_key"]
                            self._hmac_key = keys.get("hmac_key")
                            self._xor_key = keys.get("xor_key")
                        if not self.has_keys:
                            self.has_keys = True
                            self._status("Keys acquired, capturing...")
                            _blog.info("KEYS acquired aes=%d bytes", len(keys["aes_key"]))
                    else:
                        _blog.debug("KEYS not yet available")
                except Exception as e:
                    _blog.warning("KEYS error: %s", e)
            self._stop.wait(5)

    def _capture_loop(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "0.0.0.0"

        _blog.info("CAPTURE binding to %s", local_ip)
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._sock.bind((local_ip, 0))
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            _blog.info("CAPTURE raw socket active")
        except (PermissionError, OSError) as e:
            _blog.error("CAPTURE failed: %s", e)
            self._status("Capture failed (run as Admin)")
            return

        while not self._stop.is_set():
            try:
                self._sock.settimeout(1.0)
                data = self._sock.recvfrom(65535)[0]
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

    def _process_loop(self):
        _pkt_count = 0
        _match_count = 0
        _decrypt_ok = 0
        _decrypt_fail = 0
        _msg_count = 0
        _last_stats = time.time()

        while not self._stop.is_set():
            try:
                raw = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                # Periodic stats dump
                now = time.time()
                if now - _last_stats >= 10:
                    _blog.info("PIPELINE pkts=%d matched=%d decrypt_ok=%d decrypt_fail=%d msgs=%d qsize=%d",
                               _pkt_count, _match_count, _decrypt_ok, _decrypt_fail, _msg_count,
                               self._packet_queue.qsize())
                    _last_stats = now
                continue

            _pkt_count += 1
            ip = parse_ip_header(raw)
            if not ip:
                continue
            proto_num, src_ip, dst_ip, ihl = ip
            transport = raw[ihl:]

            if proto_num == 17:
                result = parse_udp_header(transport)
            elif proto_num == 6:
                result = parse_tcp_header(transport)
            else:
                continue
            if not result:
                continue
            src_port, dst_port, payload = result

            if not payload or not self._matches_game(src_ip, src_port, dst_ip, dst_port):
                continue

            _match_count += 1

            with self._key_lock:
                aes_key = self._aes_key
                hmac_key = self._hmac_key
                xor_key = self._xor_key

            if not aes_key or len(payload) < 36:
                continue

            plaintext = decrypt_packet(payload, aes_key, hmac_key, xor_key)
            if not plaintext:
                _decrypt_fail += 1
                continue
            _decrypt_ok += 1

            messages = extract_game_messages(plaintext)
            for msg_id, body in messages:
                _msg_count += 1
                _blog.debug("MSG 0x%04X len=%d", msg_id, len(body))
                self.message_handler.process(msg_id, body)

            # Periodic stats
            now = time.time()
            if now - _last_stats >= 10:
                _blog.info("PIPELINE pkts=%d matched=%d decrypt_ok=%d decrypt_fail=%d msgs=%d qsize=%d",
                           _pkt_count, _match_count, _decrypt_ok, _decrypt_fail, _msg_count,
                           self._packet_queue.qsize())
                _last_stats = now


# ===================================================================
# Keystroke sending
# ===================================================================

def _find_game_window():
    """Find the Monsters and Memories game window handle."""
    result = []
    def _enum_cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value
            if "Monsters" in title and "Memories" in title:
                result.append(hwnd)
        return True
    cb = WNDENUMPROC(_enum_cb)
    user32.EnumWindows(cb, 0)
    return result[0] if result else None


def _send_vk(vk_code):
    """Send a virtual key press + release via keybd_event (same as AHK SendEvent)."""
    scan = user32.MapVirtualKeyW(vk_code, MAPVK_VK_TO_VSC)
    user32.keybd_event(vk_code, scan, 0, None)
    time.sleep(0.01)
    user32.keybd_event(vk_code, scan, KEYEVENTF_KEYUP, None)


def _send_char(ch):
    """Send a character via keybd_event with VK + scan code."""
    vk_scan = user32.VkKeyScanW(ch)
    vk = vk_scan & 0xFF
    shift = (vk_scan >> 8) & 0x01

    if vk_scan == -1 or vk == 0xFF:
        # Unmappable character — skip (shouldn't happen for ASCII game commands)
        return

    scan = user32.MapVirtualKeyW(vk, MAPVK_VK_TO_VSC)
    shift_scan = user32.MapVirtualKeyW(VK_SHIFT, MAPVK_VK_TO_VSC)

    if shift:
        user32.keybd_event(VK_SHIFT, shift_scan, 0, None)
        time.sleep(0.005)

    user32.keybd_event(vk, scan, 0, None)
    time.sleep(0.005)
    user32.keybd_event(vk, scan, KEYEVENTF_KEYUP, None)

    if shift:
        time.sleep(0.005)
        user32.keybd_event(VK_SHIFT, shift_scan, KEYEVENTF_KEYUP, None)


def _send_string(text):
    """Send a string of characters via keybd_event."""
    for ch in text:
        _send_char(ch)
        time.sleep(0.01)


def _force_foreground(hwnd):
    """Force a window to foreground using AttachThreadInput trick."""
    cur_thread = kernel32.GetCurrentThreadId()
    fg_hwnd = user32.GetForegroundWindow()
    fg_thread = user32.GetWindowThreadProcessId(fg_hwnd, None)
    if cur_thread != fg_thread:
        user32.AttachThreadInput(cur_thread, fg_thread, True)
    user32.BringWindowToTop(hwnd)
    user32.SetForegroundWindow(hwnd)
    if cur_thread != fg_thread:
        user32.AttachThreadInput(cur_thread, fg_thread, False)


def send_attack_keys(keys):
    """Send a sequence of attack keys to the game window. Returns True on success.
    keys: list of single-character strings, e.g. ["4", "2"]
    """
    hwnd = _find_game_window()
    if not hwnd:
        return False
    _force_foreground(hwnd)
    time.sleep(0.1)
    if user32.GetForegroundWindow() != hwnd:
        return False
    for key in keys:
        _send_char(key)
        time.sleep(0.2)
    return True


# ===================================================================
# GUI
# ===================================================================

COLORS = {
    "bg": "#000000",
    "bg_dark": "#000000",
    "bg_light": "#1a1a1a",
    "fg": "#ffffff",
    "fg_dim": "#aaaaaa",
    "green": "#a6e3a1",
    "red": "#f38ba8",
    "yellow": "#f9e2af",
    "blue": "#89b4fa",
    "peach": "#fab387",
    "mauve": "#cba6f7",
    "teal": "#94e2d5",
    "gold": "#c9a44a",
    "gold_dim": "#7a6530",
}


class BotApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ChatParser V1.1")
        self.configure(bg=COLORS["bg"])
        self.geometry("460x900")
        self.minsize(400, 700)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.75)

        # Bot state
        self._bot_running = False
        self._bot_thread = None
        self._bot_stop = threading.Event()
        self._bot_triggered = False
        self._bot_loop_mode = True   # True=loop keys, False=once
        self._bot_sound_enabled = False  # whether active trigger has sound
        self._active_trigger_pattern = None  # pattern of currently active trigger
        self._bot_attack_keys = tk.StringVar(value="4,2,5,3")
        self._bot_loop_delay = tk.StringVar(value="5000")
        self._bot_loop_count = tk.StringVar(value="3")
        self._bot_status = "Idle"

        # Triggers
        self._triggers = _load_triggers()

        # Opcode browser state
        self._trigger_tab = "text"      # "text" or "opcode"
        self._opcode_buffers = {"Chat": [], "Combat": [], "All": []}
        self._opcode_buf_caps = {"Chat": 2000, "Combat": 2000, "All": 5000}
        self._opcode_view = "list"      # "list" or "detail"
        self._opcode_detail_msg = None  # currently viewed message
        self._opcode_last_filter = None # track filter for rebuild

        # Connection status
        self._conn_status = tk.StringVar(value="Starting...")

        # Capture backend
        self._backend = CaptureBackend(status_callback=self._on_status)

        self._build_ui()
        self._backend.start()
        self._poll_loop()

    def _on_status(self, msg):
        self._conn_status.set(msg)

    def _check_triggers(self, text):
        """Return the first matching text trigger dict, or None."""
        text_lower = text.lower()
        for trig in self._triggers:
            if trig.get("type", "text") != "text":
                continue
            pat = trig["pattern"]
            if pat == "*" or pat.lower() in text_lower:
                return trig
        return None

    @staticmethod
    def _is_scrolled_to_bottom(text_widget):
        """Return True if the text widget is scrolled to (or near) the bottom."""
        return text_widget.yview()[1] >= 0.95

    def _scrollable_text(self, parent, **text_kwargs):
        """Create a Text widget with a gold-themed scrollbar.

        Returns (container_frame, text_widget).
        Caller should pack/grid the container_frame.
        """
        container = tk.Frame(parent, bg=COLORS["bg"])

        # Scrollbar (gold trough, dark slider)
        sb = tk.Scrollbar(container, orient="vertical",
                          troughcolor=COLORS["bg_dark"],
                          bg=COLORS["gold_dim"], activebackground=COLORS["gold"],
                          highlightbackground=COLORS["bg"], highlightcolor=COLORS["bg"],
                          relief="flat", width=10, bd=0)
        sb.pack(side="right", fill="y")

        text = tk.Text(container, yscrollcommand=sb.set, **text_kwargs)
        text.pack(side="left", fill="both", expand=True)
        sb.config(command=text.yview)

        return container, text

    def _deco_section(self, parent, title=None, expand=False):
        """Create an art-deco bordered section. Returns the inner content frame."""
        # Outer gold border frame
        outer = tk.Frame(parent, bg=COLORS["gold"])
        pk = {"fill": "both" if expand else "x", "padx": 10, "pady": 4}
        if expand:
            pk["expand"] = True
        outer.pack(**pk)

        # Inner content area (1px gold border via padding)
        inner = tk.Frame(outer, bg=COLORS["bg"], padx=10, pady=6)
        inner.pack(fill="both", expand=True, padx=1, pady=1)

        if title:
            hdr = tk.Frame(inner, bg=COLORS["bg"])
            hdr.pack(fill="x", pady=(0, 6))
            tk.Label(hdr, text="\u25C6", bg=COLORS["bg"], fg=COLORS["gold"],
                     font=("Consolas", 7)).pack(side="left")
            tk.Label(hdr, text=f" {title} ", bg=COLORS["bg"], fg=COLORS["gold"],
                     font=("Consolas", 9, "bold")).pack(side="left")
            tk.Frame(hdr, bg=COLORS["gold"], height=1).pack(
                side="left", fill="x", expand=True, padx=(4, 4), pady=1)
            tk.Label(hdr, text="\u25C6", bg=COLORS["bg"], fg=COLORS["gold"],
                     font=("Consolas", 7)).pack(side="right")

        inner._deco_outer = outer  # stash ref for callers that need it
        return inner

    def _build_ui(self):
        # Status bar
        status_frame = tk.Frame(self, bg=COLORS["bg_dark"], pady=4, padx=8)
        status_frame.pack(fill="x")
        tk.Label(status_frame, textvariable=self._conn_status,
                 bg=COLORS["bg_dark"], fg=COLORS["fg_dim"],
                 font=("Consolas", 9)).pack(side="left")

        # Title
        title_frame = tk.Frame(self, bg=COLORS["bg"], pady=4)
        title_frame.pack(fill="x")
        tk.Label(title_frame, text="\u2500\u2500 ChatParser \u2500\u2500", bg=COLORS["bg"],
                 fg=COLORS["gold"], font=("Consolas", 16, "bold")).pack()

        # ══════════════════════════════════════
        # Section 1: Bot Controls
        # ══════════════════════════════════════
        ctrl_sec = self._deco_section(self, title="Bot Controls")

        # ON/OFF toggle
        self._toggle_btn = tk.Button(
            ctrl_sec, text="OFF", width=10,
            bg=COLORS["red"], fg=COLORS["bg_dark"],
            activebackground=COLORS["red"],
            font=("Consolas", 14, "bold"),
            relief="flat", cursor="hand2",
            command=self._toggle_bot)
        self._toggle_btn.pack(pady=(0, 6))

        # Settings grid
        settings = tk.Frame(ctrl_sec, bg=COLORS["bg"])
        settings.pack(fill="x", pady=2)

        row = 0
        for label_text, var in [
            ("Attack Keys", self._bot_attack_keys),
            ("Loop Delay ms", self._bot_loop_delay),
            ("Loop Count", self._bot_loop_count),
        ]:
            tk.Label(settings, text=label_text, bg=COLORS["bg"],
                     fg=COLORS["fg_dim"], font=("Consolas", 9),
                     anchor="w").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
            e = tk.Entry(settings, textvariable=var, bg=COLORS["bg_light"],
                         fg=COLORS["fg"], insertbackground=COLORS["fg"],
                         font=("Consolas", 10), width=20, relief="flat",
                         border=2)
            e.grid(row=row, column=1, sticky="ew", pady=2)
            if label_text == "Attack Keys":
                row += 1
                tk.Label(settings, text="assist,pet attack,instant,nuke",
                         bg=COLORS["bg"], fg=COLORS["fg_dim"],
                         font=("Consolas", 7), anchor="w").grid(
                    row=row, column=1, sticky="w", pady=(0, 2))
            row += 1

        settings.columnconfigure(1, weight=1)

        # Bot status line
        self._status_label = tk.Label(
            ctrl_sec, text="Status: Idle", bg=COLORS["bg"],
            fg=COLORS["fg_dim"], font=("Consolas", 10), anchor="w")
        self._status_label.pack(fill="x", pady=(6, 0))

        # ══════════════════════════════════════
        # Section 2: Triggers / Opcode Browser
        # ══════════════════════════════════════
        trig_sec = self._deco_section(self, title="Triggers", expand=True)

        # Tab buttons — art deco bordered sub-section
        tab_border = tk.Frame(trig_sec, bg=COLORS["gold"])
        tab_border.pack(fill="x", pady=(0, 6))
        tab_inner = tk.Frame(tab_border, bg=COLORS["bg"], padx=6, pady=4)
        tab_inner.pack(fill="x", padx=1, pady=1)

        # Decorative left accent
        tk.Label(tab_inner, text="\u25C0\u2500", bg=COLORS["bg"], fg=COLORS["gold"],
                 font=("Consolas", 9)).pack(side="left")

        self._tab_text_btn = tk.Button(
            tab_inner, text="\u25C6 Main", font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2", padx=12, pady=3,
            command=lambda: self._switch_trigger_tab("text"))
        self._tab_text_btn.pack(side="left", padx=(4, 2))

        # Center divider
        tk.Label(tab_inner, text="\u2502", bg=COLORS["bg"], fg=COLORS["gold"],
                 font=("Consolas", 10)).pack(side="left", padx=2)

        self._tab_opcode_btn = tk.Button(
            tab_inner, text="\u25C6 Opcode Browser", font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2", padx=12, pady=3,
            command=lambda: self._switch_trigger_tab("opcode"))
        self._tab_opcode_btn.pack(side="left", padx=(2, 4))

        # Decorative right accent
        tk.Label(tab_inner, text="\u2500\u25B6", bg=COLORS["bg"], fg=COLORS["gold"],
                 font=("Consolas", 9)).pack(side="right")

        # ---- Text Triggers container ----
        self._text_trig_frame = tk.Frame(trig_sec, bg=COLORS["bg"])
        self._text_trig_frame.pack(fill="both", expand=True)

        # Label above input
        tk.Label(self._text_trig_frame, text="Text Trigger", bg=COLORS["bg"],
                 fg=COLORS["gold"], font=("Consolas", 9, "bold"),
                 anchor="w").pack(fill="x", pady=(4, 0))

        # Add trigger row
        add_frame = tk.Frame(self._text_trig_frame, bg=COLORS["bg"])
        add_frame.pack(fill="x", pady=(2, 2))

        self._trigger_entry = tk.Entry(
            add_frame, bg=COLORS["bg_light"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"], font=("Consolas", 10),
            relief="flat", border=2)
        self._trigger_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._trigger_entry.bind("<Return>", lambda e: self._add_trigger())

        tk.Button(add_frame, text="Add", bg=COLORS["blue"],
                  fg=COLORS["bg_dark"], font=("Consolas", 9, "bold"),
                  relief="flat", cursor="hand2", width=6,
                  command=self._add_trigger).pack(side="right")

        # Trigger table header
        hdr_frame = tk.Frame(self._text_trig_frame, bg=COLORS["bg_dark"])
        hdr_frame.pack(fill="x", pady=(4, 0))
        tk.Label(hdr_frame, text="Pattern", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8),
                 anchor="w").pack(side="left", fill="x", expand=True, padx=4)
        tk.Label(hdr_frame, text="Mode", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8),
                 width=6).pack(side="left", padx=2)
        tk.Label(hdr_frame, text="SFX", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8),
                 width=3).pack(side="left", padx=2)
        tk.Label(hdr_frame, text="", bg=COLORS["bg_dark"],
                 width=2).pack(side="left", padx=2)

        # Trigger table rows container
        self._trigger_table = tk.Frame(self._text_trig_frame, bg=COLORS["bg_dark"])
        self._trigger_table.pack(fill="x", pady=(0, 4))
        self._trigger_rows = []
        for trig in self._triggers:
            self._add_trigger_row(trig)

        # ---- Opcode Browser container (hidden by default) ----
        self._opcode_frame = tk.Frame(trig_sec, bg=COLORS["bg"])
        # Not packed yet — shown when tab switches

        # Opcode filter dropdown + search
        filter_row = tk.Frame(self._opcode_frame, bg=COLORS["bg"])
        filter_row.pack(fill="x", pady=(4, 4))
        tk.Label(filter_row, text="Filter:", bg=COLORS["bg"],
                 fg=COLORS["fg_dim"], font=("Consolas", 9)).pack(side="left", padx=(0, 4))
        self._opcode_filter_var = tk.StringVar(value="All")
        self._opcode_filter = ttk.Combobox(
            filter_row, textvariable=self._opcode_filter_var,
            values=["Chat", "Combat", "All"], state="readonly", width=10)
        self._opcode_filter.pack(side="left")
        self._opcode_filter.bind("<<ComboboxSelected>>", lambda e: self._on_filter_change())

        self._opcode_search_var = tk.StringVar()
        self._opcode_search = tk.Entry(
            filter_row, textvariable=self._opcode_search_var,
            bg=COLORS["bg_light"], fg=COLORS["fg"], insertbackground=COLORS["fg"],
            font=("Consolas", 9), relief="flat", border=2, width=14)
        self._opcode_search.pack(side="left", padx=(8, 0))
        self._opcode_search.insert(0, "")
        self._opcode_search_var.trace_add("write", lambda *_: self._on_opcode_search())

        # Opcode list (scrollable text widget with clickable rows)
        self._opcode_list_frame, self._opcode_list = self._scrollable_text(
            self._opcode_frame,
            bg=COLORS["bg_dark"], fg=COLORS["fg"],
            font=("Consolas", 9), wrap="none", relief="flat",
            border=0, padx=6, pady=4, cursor="hand2",
            state="disabled", height=14)
        self._opcode_list_frame.pack(fill="both", expand=True, pady=(0, 4))
        self._opcode_list.tag_configure("ts", foreground=COLORS["fg_dim"])
        self._opcode_list.tag_configure("opname", foreground=COLORS["blue"])
        self._opcode_list.tag_configure("preview", foreground=COLORS["fg"])
        self._opcode_list.bind("<Button-1>", self._on_opcode_list_click)
        self._opcode_list_entries = []  # parallel list of opcode msg dicts

        # Opcode detail view (scrollable canvas — hidden until a row is clicked)
        self._opcode_detail_outer = tk.Frame(self._opcode_frame, bg=COLORS["bg"])
        # Not packed yet
        self._opcode_detail_canvas = tk.Canvas(
            self._opcode_detail_outer, bg=COLORS["bg"], highlightthickness=0)
        self._opcode_detail_sb = tk.Scrollbar(
            self._opcode_detail_outer, orient="vertical",
            command=self._opcode_detail_canvas.yview,
            troughcolor=COLORS["bg_dark"], bg=COLORS["gold_dim"],
            activebackground=COLORS["gold"], relief="flat", width=10, bd=0)
        self._opcode_detail_sb.pack(side="right", fill="y")
        self._opcode_detail_canvas.pack(side="left", fill="both", expand=True)
        self._opcode_detail_canvas.configure(yscrollcommand=self._opcode_detail_sb.set)
        self._opcode_detail_frame = tk.Frame(self._opcode_detail_canvas, bg=COLORS["bg"])
        self._opcode_detail_window = self._opcode_detail_canvas.create_window(
            (0, 0), window=self._opcode_detail_frame, anchor="nw")
        self._opcode_detail_frame.bind("<Configure>",
            lambda e: self._opcode_detail_canvas.configure(
                scrollregion=self._opcode_detail_canvas.bbox("all")))
        self._opcode_detail_canvas.bind("<Configure>",
            lambda e: self._opcode_detail_canvas.itemconfig(
                self._opcode_detail_window, width=e.width))
        # Mousewheel scroll
        def _on_detail_mousewheel(e):
            self._opcode_detail_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        self._opcode_detail_canvas.bind("<MouseWheel>", _on_detail_mousewheel)
        self._opcode_detail_frame.bind("<MouseWheel>", _on_detail_mousewheel)

        # Apply initial tab style
        self._apply_tab_style()

        # ══════════════════════════════════════
        # Section 3: Combat Log
        # ══════════════════════════════════════
        log_sec = self._deco_section(self, title="Run Log", expand=True)

        log_container, self._combat_log = self._scrollable_text(
            log_sec,
            bg=COLORS["bg_dark"], fg=COLORS["fg"],
            font=("Consolas", 9), wrap="word", relief="flat",
            border=0, padx=6, pady=4, cursor="arrow",
            state="disabled", height=6)
        log_container.pack(fill="both", expand=True, pady=(0, 2))

        self._combat_log.tag_configure("normal", foreground=COLORS["fg"])
        self._combat_log.tag_configure("matched", foreground=COLORS["yellow"],
                                       font=("Consolas", 9, "bold"))
        self._combat_log.tag_configure("timestamp", foreground=COLORS["fg_dim"])

    def _add_trigger_row(self, trig):
        """Build one trigger row: [pattern] [Loop/Once] [sound] [X]."""
        idx = len(self._trigger_rows)
        row = tk.Frame(self._trigger_table, bg=COLORS["bg_light"], pady=2)
        row.pack(fill="x", pady=(1, 0))

        # Pattern label — opcode triggers show [0xNNNN.field] prefix
        if trig.get("type") == "opcode":
            op = trig.get("opcode", 0)
            field = trig.get("field", "")
            label_text = f"[0x{op:04X}.{field}] {trig['pattern']}"
            label_fg = COLORS["fg_dim"]
        else:
            label_text = trig["pattern"]
            label_fg = COLORS["fg"]
        tk.Label(row, text=label_text, bg=COLORS["bg_light"],
                 fg=label_fg, font=("Consolas", 9),
                 anchor="w").pack(side="left", fill="x", expand=True, padx=4)

        # Loop / Once toggle button
        is_loop = trig.get("loop", True)
        mode_btn = tk.Button(
            row, text="Loop" if is_loop else "Once",
            bg=COLORS["teal"] if is_loop else COLORS["peach"],
            fg=COLORS["bg_dark"], font=("Consolas", 8, "bold"),
            relief="flat", cursor="hand2", width=5,
            command=lambda i=idx: self._toggle_trigger_mode(i))
        mode_btn.pack(side="left", padx=2)

        # Sound toggle button (speaker icon)
        has_sound = trig.get("sound", False)
        sound_btn = tk.Button(
            row, text="\U0001F50A" if has_sound else "\U0001F507",
            bg=COLORS["yellow"] if has_sound else COLORS["bg_dark"],
            fg=COLORS["bg_dark"] if has_sound else COLORS["fg_dim"],
            font=("Segoe UI Emoji", 8), relief="flat",
            cursor="hand2", width=3,
            command=lambda i=idx: self._toggle_trigger_sound(i))
        sound_btn.pack(side="left", padx=2)

        # Red X remove button
        tk.Button(row, text="X",
                  bg=COLORS["red"], fg=COLORS["bg_dark"],
                  font=("Consolas", 8, "bold"),
                  relief="flat", cursor="hand2", width=2,
                  command=lambda i=idx: self._remove_trigger(i)).pack(side="left", padx=(2, 4))

        self._trigger_rows.append({"frame": row, "mode_btn": mode_btn, "sound_btn": sound_btn})

    def _rebuild_trigger_table(self):
        """Destroy all rows and rebuild from self._triggers."""
        for row_info in self._trigger_rows:
            row_info["frame"].destroy()
        self._trigger_rows.clear()
        for trig in self._triggers:
            self._add_trigger_row(trig)

    def _add_trigger(self):
        pattern = self._trigger_entry.get().strip()
        if not pattern:
            return
        # Prevent duplicate patterns
        for t in self._triggers:
            if t["pattern"] == pattern:
                self._trigger_entry.delete(0, "end")
                return
        trig = {"type": "text", "pattern": pattern, "loop": False, "sound": False}
        self._triggers.append(trig)
        self._add_trigger_row(trig)
        _save_triggers(self._triggers)
        _blog.info("TRIGGER_ADD: %s", pattern)
        self._trigger_entry.delete(0, "end")

    def _remove_trigger(self, idx):
        if idx < 0 or idx >= len(self._triggers):
            return
        pattern = self._triggers[idx]["pattern"]
        del self._triggers[idx]
        _save_triggers(self._triggers)
        _blog.info("TRIGGER_REMOVE: %s", pattern)
        self._rebuild_trigger_table()

    def _toggle_trigger_mode(self, idx):
        if idx < 0 or idx >= len(self._triggers):
            return
        trig = self._triggers[idx]
        trig["loop"] = not trig["loop"]
        _save_triggers(self._triggers)
        # Update button in-place
        btn = self._trigger_rows[idx]["mode_btn"]
        if trig["loop"]:
            btn.configure(text="Loop", bg=COLORS["teal"])
        else:
            btn.configure(text="Once", bg=COLORS["peach"])
        # Reset active loop if this trigger is currently running
        if (self._bot_triggered and
                self._active_trigger_pattern == trig["pattern"]):
            self._bot_triggered = False
            self._bot_sound_enabled = False
            self._active_trigger_pattern = None
            self._bot_status = "Waiting for trigger..."
            self._log(f"Loop reset: {trig['pattern']}")
        _blog.info("TRIGGER_MODE: %s → %s", trig["pattern"],
                   "loop" if trig["loop"] else "once")

    def _toggle_trigger_sound(self, idx):
        if idx < 0 or idx >= len(self._triggers):
            return
        trig = self._triggers[idx]
        trig["sound"] = not trig["sound"]
        _save_triggers(self._triggers)
        btn = self._trigger_rows[idx]["sound_btn"]
        if trig["sound"]:
            btn.configure(text="\U0001F50A", bg=COLORS["yellow"],
                          fg=COLORS["bg_dark"])
        else:
            btn.configure(text="\U0001F507", bg=COLORS["bg_dark"],
                          fg=COLORS["fg_dim"])
        _blog.info("TRIGGER_SOUND: %s → %s", trig["pattern"],
                   "on" if trig["sound"] else "off")

    # ----- Tab switching -----

    def _apply_tab_style(self):
        """Style tab buttons based on current _trigger_tab."""
        if self._trigger_tab == "text":
            self._tab_text_btn.configure(bg=COLORS["gold"], fg=COLORS["bg_dark"])
            self._tab_opcode_btn.configure(bg=COLORS["bg_light"], fg=COLORS["fg_dim"])
        else:
            self._tab_text_btn.configure(bg=COLORS["bg_light"], fg=COLORS["fg_dim"])
            self._tab_opcode_btn.configure(bg=COLORS["gold"], fg=COLORS["bg_dark"])

    def _switch_trigger_tab(self, tab):
        if tab == self._trigger_tab:
            return
        self._trigger_tab = tab
        self._apply_tab_style()
        if tab == "text":
            self._opcode_frame.pack_forget()
            self._text_trig_frame.pack(fill="both", expand=True)
        else:
            self._text_trig_frame.pack_forget()
            self._opcode_view = "list"
            self._opcode_detail_outer.pack_forget()
            self._opcode_list_frame.pack(fill="both", expand=True)
            self._opcode_frame.pack(fill="both", expand=True)
            # Full rebuild from buffer when switching to this tab
            self._render_opcode_list()

    # ----- Opcode Browser -----

    def _opcode_preview(self, msg):
        """Build a short preview string for an opcode message."""
        fields = msg.get("fields", {})
        opcode = msg.get("opcode", 0)
        if "text" in fields and fields["text"]:
            txt = fields["text"]
            return txt[:50] + ("..." if len(txt) > 50 else "")
        if opcode == 0x0013:
            eid = fields.get("entity_id")
            return f"Entity#{eid} has died" if eid is not None else "died"
        if opcode == 0x0018:
            eid = fields.get("entity_id")
            return f"Entity#{eid}" if eid is not None else ""
        if opcode == 0x0024:
            eid = fields.get("entity_id")
            xp = fields.get("experience")
            parts = []
            if eid is not None:
                parts.append(f"eid={eid}")
            if xp is not None:
                parts.append(f"xp={xp}")
            return " ".join(parts) if parts else ""
        # For any opcode with parsed fields, show them compactly
        if fields:
            parts = []
            for k, v in fields.items():
                if v is not None:
                    parts.append(f"{k}={v}")
            preview = " ".join(parts)
            return preview[:50] + ("..." if len(preview) > 50 else "")
        # Fallback: show hex snippet of raw data
        raw_hex = msg.get("raw_hex", "")
        if raw_hex:
            return raw_hex[:35] + ("..." if len(raw_hex) > 35 else "")
        return f"{msg.get('raw_len', 0)} bytes"

    @staticmethod
    def _opcode_categories(opcode):
        """Return list of filter categories this opcode belongs to."""
        cats = []
        if opcode == 0x0040:
            cats.append("Chat")
        elif opcode in (0x0055, 0x0056, 0x0013):
            cats.append("Combat")
        # Only include in All if it has a known plaintext name
        if opcode in OPCODE_NAMES:
            cats.append("All")
        return cats

    def _opcode_matches_search(self, msg, search):
        """Check if an opcode message matches the search text (case-insensitive)."""
        if not search:
            return True
        s = search.lower()
        # Check opcode name
        if s in msg.get("opcode_name", "").lower():
            return True
        # Check all field values
        for v in msg.get("fields", {}).values():
            if s in str(v).lower():
                return True
        return False

    def _render_opcode_list(self):
        """Full rebuild of opcode list from the active filter's buffer."""
        self._opcode_list.configure(state="normal")
        self._opcode_list.delete("1.0", "end")
        self._opcode_list_entries.clear()
        filt = self._opcode_filter_var.get()
        self._opcode_last_filter = filt
        search = self._opcode_search_var.get().strip()

        for msg in self._opcode_buffers.get(filt, []):
            if self._opcode_matches_search(msg, search):
                self._insert_opcode_line(msg)

        self._trim_opcode_list()
        if self._is_scrolled_to_bottom(self._opcode_list):
            self._opcode_list.see("end")
        self._opcode_list.configure(state="disabled")

    def _insert_opcode_line(self, msg):
        """Insert a single opcode entry line into the text widget."""
        ts = time.strftime("%H:%M:%S", time.localtime(msg["timestamp"]))
        opname = msg.get("opcode_name", "???")
        preview = self._opcode_preview(msg)
        self._opcode_list.insert("end", f"[{ts}] ", "ts")
        self._opcode_list.insert("end", opname, "opname")
        self._opcode_list.insert("end", f" — {preview}\n", "preview")
        self._opcode_list_entries.append(msg)

    def _trim_opcode_list(self):
        """Trim opcode list widget to 1000 visible lines."""
        while len(self._opcode_list_entries) > 1000:
            self._opcode_list.delete("1.0", "2.0")
            self._opcode_list_entries.pop(0)

    def _append_opcode_entries(self, new_msgs):
        """Incrementally append new entries matching active filter + search."""
        filt = self._opcode_filter_var.get()
        search = self._opcode_search_var.get().strip()
        added = False
        self._opcode_list.configure(state="normal")
        for msg in new_msgs:
            if filt in self._opcode_categories(msg.get("opcode", 0)):
                if self._opcode_matches_search(msg, search):
                    self._insert_opcode_line(msg)
                    added = True
        if added:
            self._trim_opcode_list()
            if self._is_scrolled_to_bottom(self._opcode_list):
                self._opcode_list.see("end")
        self._opcode_list.configure(state="disabled")

    def _on_opcode_list_click(self, event):
        """Handle click on opcode list — determine line and show detail."""
        index = self._opcode_list.index(f"@{event.x},{event.y}")
        line = int(index.split(".")[0]) - 1  # 0-based
        if 0 <= line < len(self._opcode_list_entries):
            self._show_opcode_detail(line)

    def _on_filter_change(self):
        """Rebuild opcode list when filter dropdown changes."""
        if self._trigger_tab == "opcode" and self._opcode_view == "list":
            self._render_opcode_list()

    def _on_opcode_search(self):
        """Dynamically rebuild opcode list when search text changes."""
        if self._trigger_tab == "opcode" and self._opcode_view == "list":
            self._render_opcode_list()

    def _show_opcode_detail(self, idx):
        """Switch opcode browser to detail view for the clicked message."""
        if idx < 0 or idx >= len(self._opcode_list_entries):
            return
        self._opcode_detail_msg = self._opcode_list_entries[idx]
        self._opcode_view = "detail"

        # Hide list, show detail
        self._opcode_list_frame.pack_forget()
        for w in self._opcode_detail_frame.winfo_children():
            w.destroy()

        msg = self._opcode_detail_msg
        opname = msg.get("opcode_name", "???")
        opcode = msg.get("opcode", 0)
        ts = time.strftime("%H:%M:%S", time.localtime(msg["timestamp"]))

        # Back button
        tk.Button(self._opcode_detail_frame, text="< Back", bg=COLORS["bg_light"],
                  fg=COLORS["fg"], font=("Consolas", 9, "bold"),
                  relief="flat", cursor="hand2",
                  command=self._opcode_detail_back).pack(anchor="w", pady=(4, 4))

        # Header
        tk.Label(self._opcode_detail_frame,
                 text=f"{opname} (0x{opcode:04X})",
                 bg=COLORS["bg"], fg=COLORS["blue"],
                 font=("Consolas", 11, "bold"), anchor="w").pack(fill="x")
        tk.Frame(self._opcode_detail_frame, bg=COLORS["fg_dim"], height=1).pack(fill="x", pady=(2, 4))

        # Fields
        fields = msg.get("fields", {})
        detail_text = tk.Text(
            self._opcode_detail_frame, bg=COLORS["bg_dark"], fg=COLORS["fg"],
            font=("Consolas", 9), wrap="word", relief="flat",
            border=0, padx=6, pady=4, height=6, state="normal")
        detail_text.pack(fill="both", expand=True, pady=(0, 4))

        detail_text.tag_configure("key", foreground=COLORS["teal"])
        detail_text.tag_configure("val", foreground=COLORS["fg"])

        for key, val in fields.items():
            detail_text.insert("end", f"  {key}:  ", "key")
            val_str = str(val) if val is not None else "None"
            if len(val_str) > 80:
                val_str = val_str[:80] + "..."
            detail_text.insert("end", f"{val_str}\n", "val")

        detail_text.insert("end", f"  raw_len:  ", "key")
        detail_text.insert("end", f"{msg.get('raw_len', 0)} bytes\n", "val")
        raw_hex = msg.get("raw_hex", "")
        if raw_hex:
            detail_text.tag_configure("hex", foreground=COLORS["peach"])
            detail_text.insert("end", f"  raw_hex:  ", "key")
            detail_text.insert("end", f"{raw_hex}\n", "hex")
        detail_text.insert("end", f"  time:  ", "key")
        detail_text.insert("end", f"{ts}\n", "val")
        detail_text.configure(state="disabled")

        # "Add as Trigger" button — only for opcodes with useful fields
        if fields:
            self._build_opcode_trigger_form(msg)

        # Bind mousewheel to all children for smooth scrolling
        def _bind_mw(widget):
            widget.bind("<MouseWheel>",
                lambda e: self._opcode_detail_canvas.yview_scroll(
                    int(-1*(e.delta/120)), "units"))
            for child in widget.winfo_children():
                _bind_mw(child)
        _bind_mw(self._opcode_detail_frame)

        self._opcode_detail_outer.pack(fill="both", expand=True)
        self._opcode_detail_canvas.yview_moveto(0)

    def _build_opcode_trigger_form(self, msg):
        """Build inline form to create opcode triggers from the detail view.

        Shows an editable opcode row, then one row per field (excluding
        raw_hex / raw_len / time) with a pre-filled pattern entry and its
        own Add button.
        """
        _SKIP_FIELDS = {"raw_hex", "raw_len", "time"}

        form = tk.Frame(self._opcode_detail_frame, bg=COLORS["bg_dark"], padx=6, pady=4)
        form.pack(fill="x", pady=(0, 4))

        tk.Label(form, text="Add as Trigger", bg=COLORS["bg_dark"],
                 fg=COLORS["yellow"], font=("Consolas", 9, "bold"),
                 anchor="w").pack(fill="x", pady=(0, 4))

        # --- Editable opcode row ---
        op_row = tk.Frame(form, bg=COLORS["bg_dark"])
        op_row.pack(fill="x", pady=(0, 4))
        tk.Label(op_row, text="Opcode:", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 9),
                 width=10, anchor="w").pack(side="left")
        opcode_var = tk.StringVar(value=f"0x{msg.get('opcode', 0):04X}")
        opcode_entry = tk.Entry(op_row, textvariable=opcode_var,
                                bg=COLORS["bg_light"], fg=COLORS["fg"],
                                insertbackground=COLORS["fg"],
                                font=("Consolas", 9), relief="flat",
                                border=2, width=10)
        opcode_entry.pack(side="left", padx=(0, 4))

        def _parse_opcode():
            """Parse the opcode entry as int (supports 0x hex or decimal)."""
            raw = opcode_var.get().strip()
            try:
                return int(raw, 16) if raw.lower().startswith("0x") else int(raw)
            except ValueError:
                return msg.get("opcode", 0)

        # --- Separator ---
        tk.Frame(form, bg=COLORS["fg_dim"], height=1).pack(fill="x", pady=(0, 4))

        # --- One row per field ---
        fields = msg.get("fields", {})
        field_names = [k for k in fields if k not in _SKIP_FIELDS and fields[k] is not None]
        if not field_names:
            return

        for fname in field_names:
            fval = str(fields[fname])
            if len(fval) > 60:
                fval = fval[:60]

            row = tk.Frame(form, bg=COLORS["bg_dark"])
            row.pack(fill="x", pady=(0, 3))

            tk.Label(row, text=f"{fname}:", bg=COLORS["bg_dark"],
                     fg=COLORS["teal"], font=("Consolas", 9),
                     width=10, anchor="w").pack(side="left")

            entry = tk.Entry(row, bg=COLORS["bg_light"], fg=COLORS["fg"],
                             insertbackground=COLORS["fg"],
                             font=("Consolas", 9), relief="flat", border=2)
            entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
            entry.insert(0, fval)

            def _add(field=fname, ent=entry):
                pattern = ent.get().strip()
                if not pattern:
                    return
                opcode = _parse_opcode()
                trig = {
                    "type": "opcode",
                    "opcode": opcode,
                    "field": field,
                    "pattern": pattern,
                    "loop": False,
                    "sound": False,
                }
                self._triggers.append(trig)
                self._add_trigger_row(trig)
                _save_triggers(self._triggers)
                _blog.info("OPCODE_TRIGGER_ADD: 0x%04X.%s = %s",
                           opcode, field, pattern)
                self._switch_trigger_tab("text")

            tk.Button(row, text="Add", bg=COLORS["green"],
                      fg=COLORS["bg_dark"], font=("Consolas", 8, "bold"),
                      relief="flat", cursor="hand2", width=4,
                      command=_add).pack(side="right")

    def _opcode_detail_back(self):
        """Return from detail view to list view."""
        self._opcode_view = "list"
        self._opcode_detail_outer.pack_forget()
        for w in self._opcode_detail_frame.winfo_children():
            w.destroy()
        self._opcode_list_frame.pack(fill="both", expand=True)
        self._render_opcode_list()

    # ----- Opcode trigger matching -----

    def _check_opcode_triggers(self, opcode_msg):
        """Check opcode log entry against opcode triggers. Returns first match or None."""
        msg_opcode = opcode_msg.get("opcode", -1)
        fields = opcode_msg.get("fields", {})
        for trig in self._triggers:
            if trig.get("type") != "opcode":
                continue
            if trig.get("opcode") != msg_opcode:
                continue
            field_name = trig.get("field", "")
            field_val = fields.get(field_name)
            if field_val is None:
                continue
            pat = trig["pattern"]
            if pat == "*" or pat.lower() in str(field_val).lower():
                return trig
        return None

    def _toggle_bot(self):
        if self._bot_running:
            self._stop_bot()
        else:
            self._start_bot()

    def _start_bot(self):
        if self._bot_running:
            return
        self._bot_running = True
        self._bot_triggered = False
        self._bot_sound_enabled = False
        self._active_trigger_pattern = None
        self._bot_stop.clear()
        self._toggle_btn.configure(text="ON", bg=COLORS["green"])
        self._bot_status = "Waiting for trigger..."
        self._log("Bot ON — waiting for trigger")
        self._bot_thread = threading.Thread(target=self._bot_loop, daemon=True)
        self._bot_thread.start()

    def _stop_bot(self):
        if not self._bot_running:
            return
        self._bot_running = False
        self._bot_stop.set()
        self._bot_triggered = False
        self._bot_sound_enabled = False
        self._active_trigger_pattern = None
        self._toggle_btn.configure(text="OFF", bg=COLORS["red"])
        self._bot_status = "Idle"
        self._log("Bot OFF")

    def _play_beep(self):
        """Play Windows alert sound on the main thread."""
        def _do_beep():
            try:
                winsound.PlaySound("SystemExclamation",
                                   winsound.SND_ALIAS | winsound.SND_ASYNC)
            except Exception:
                pass
        if threading.current_thread() is threading.main_thread():
            _do_beep()
        else:
            self.after(0, _do_beep)

    def _log(self, msg, tag="normal"):
        ts = time.strftime("%H:%M:%S")
        def _do():
            at_bottom = self._is_scrolled_to_bottom(self._combat_log)
            self._combat_log.configure(state="normal")
            self._combat_log.insert("end", f"[{ts}] ", "timestamp")
            self._combat_log.insert("end", f"{msg}\n", tag)
            lines = int(self._combat_log.index("end-1c").split(".")[0])
            if lines > 1000:
                self._combat_log.delete("1.0", f"{lines - 1000}.0")
            if at_bottom:
                self._combat_log.see("end")
            self._combat_log.configure(state="disabled")
        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

    def _bot_loop(self):
        """Bot thread — when triggered + ON, send attack keys (loop or once)."""
        loops_done = 0
        while not self._bot_stop.is_set():
            if not self._bot_triggered:
                loops_done = 0
                self._bot_stop.wait(0.2)
                continue

            if not self._backend.has_keys:
                self._bot_status = "Waiting for game..."
                self._bot_stop.wait(1)
                continue

            try:
                keys_str = self._bot_attack_keys.get()
                keys = [k.strip() for k in keys_str.split(",") if k.strip()]
            except tk.TclError:
                keys = ["4", "2", "5", "3"]
            try:
                delay_ms = int(self._bot_loop_delay.get())
            except (ValueError, tk.TclError):
                delay_ms = 5000
            try:
                max_loops = int(self._bot_loop_count.get())
            except (ValueError, tk.TclError):
                max_loops = 0

            self._bot_status = "Attacking..."
            if keys:
                if send_attack_keys(keys):
                    loops_done += 1
                    if max_loops > 0:
                        self._log(f"Sent keys: {', '.join(keys)} ({loops_done}/{max_loops})")
                    else:
                        self._log(f"Sent keys: {', '.join(keys)}")
                else:
                    self._log("Game window not found")

            # Beep on every loop iteration if sound enabled
            if self._bot_sound_enabled:
                self._play_beep()

            if not self._bot_loop_mode:
                # Once mode — fire keys once then reset
                self._bot_triggered = False
                loops_done = 0
                self._bot_status = "Waiting for trigger..."
                continue

            # Check loop count limit (0 = infinite)
            if max_loops > 0 and loops_done >= max_loops:
                self._log(f"Loop count reached ({max_loops})")
                self._bot_triggered = False
                loops_done = 0
                self._bot_status = "Waiting for trigger..."
                continue

            self._bot_stop.wait(delay_ms / 1000.0)

        self._bot_status = "Idle"

    def _poll_loop(self):
        """200ms poll — drain messages, display, check triggers."""
        # Update status label
        self._status_label.configure(text=f"Status: {self._bot_status}")

        # Drain text messages from handler (check text triggers)
        messages = self._backend.message_handler.get_messages()
        for msg in messages:
            text = msg["text"]
            matched = self._check_triggers(text)
            if matched:
                mode = "loop" if matched["loop"] else "once"
                _blog.info("TRIGGER_MATCH: %s (mode=%s sound=%s)",
                           text, mode,
                           "on" if matched.get("sound") else "off")
                self._log(f"MATCH [{matched['pattern']}] ({mode}): {text}", "matched")
                if self._bot_running:
                    self._bot_triggered = True
                    self._bot_loop_mode = matched["loop"]
                    self._bot_sound_enabled = matched.get("sound", False)
                    self._active_trigger_pattern = matched["pattern"]

        # Drain opcode messages from handler
        opcode_msgs = self._backend.message_handler.get_opcode_messages()
        for opc_msg in opcode_msgs:
            # Append to per-category buffers
            for cat in self._opcode_categories(opc_msg.get("opcode", 0)):
                buf = self._opcode_buffers[cat]
                buf.append(opc_msg)
                cap = self._opcode_buf_caps[cat]
                if len(buf) > cap:
                    del buf[:len(buf) - cap]

            # Check opcode triggers
            opc_matched = self._check_opcode_triggers(opc_msg)
            if opc_matched:
                mode = "loop" if opc_matched["loop"] else "once"
                opname = opc_msg.get("opcode_name", f"0x{opc_msg.get('opcode',0):04X}")
                field = opc_matched.get("field", "")
                _blog.info("OPCODE_TRIGGER_MATCH: %s.%s (mode=%s sound=%s)",
                           opname, field, mode,
                           "on" if opc_matched.get("sound") else "off")
                self._log(f"MATCH [{opname}.{field}={opc_matched['pattern']}] ({mode})", "matched")
                if self._bot_running:
                    self._bot_triggered = True
                    self._bot_loop_mode = opc_matched["loop"]
                    self._bot_sound_enabled = opc_matched.get("sound", False)
                    self._active_trigger_pattern = opc_matched["pattern"]

        # Incrementally append new entries to opcode list (no full redraw)
        if opcode_msgs and self._trigger_tab == "opcode" and self._opcode_view == "list":
            self._append_opcode_entries(opcode_msgs)

        self.after(200, self._poll_loop)

    def destroy(self):
        self._stop_bot()
        self._backend.stop()
        super().destroy()


# ===================================================================
# Admin check + main
# ===================================================================

def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def main():
    if not _is_admin():
        if getattr(sys, 'frozen', False):
            ctypes.windll.user32.MessageBoxW(
                0, "ChatParser requires Administrator privileges.\n"
                   "Right-click and 'Run as administrator'.",
                "ChatParser", 0x10)
        else:
            print("ERROR: Run as Administrator (raw socket capture requires elevation)")
        sys.exit(1)

    app = BotApp()
    app.mainloop()


if __name__ == "__main__":
    main()
