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
import random
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
        self._npc_names = {}      # name -> set of eids (entity_type != 0)
        self._pc_names = {}       # name -> set of eids (entity_type == 0)
        self._disc_version = 0    # bumped on each new NPC or PC name
        self._fizzle_event = threading.Event()  # set when "fizzle" detected

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
                if etype is not None:
                    if etype != 0:
                        # Track unique NPC names
                        if name not in self._npc_names:
                            self._npc_names[name] = set()
                            self._disc_version += 1
                        self._npc_names[name].add(eid)
                    else:
                        # Track unique PC names (entity_type == 0)
                        if name not in self._pc_names:
                            self._pc_names[name] = set()
                            self._disc_version += 1
                        self._pc_names[name].add(eid)

        elif msg_id == 0x0040:  # ChatMessage
            channel, off = _r_u32(body, off)
            fields["channel"] = channel
            msg_text, off = _r_str(body, off)
            if msg_text:
                text = msg_text
                fields["text"] = text
                if channel == 1:
                    _blog.debug("CHAT_COMBAT: %s", text)
                else:
                    _blog.debug("CHAT_CH%s: %s", channel, text)

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
                if "fizzle" in text.lower():
                    self._fizzle_event.set()

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
                tmsg = {"text": text, "timestamp": now}
                # Carry entity_name for auto-target (from EndCasting/Die/etc.)
                ename = fields.get("entity_name")
                if ename:
                    tmsg["entity_name"] = ename
                self._messages.append(tmsg)
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

    def get_discovery(self):
        """Return sorted NPC names, sorted PC names, and version counter."""
        with self._lock:
            return (sorted(self._npc_names.keys()),
                    sorted(self._pc_names.keys()),
                    self._disc_version)

    def check_fizzle(self):
        """Check and clear the fizzle flag. Returns True if a fizzle was detected."""
        if self._fizzle_event.is_set():
            self._fizzle_event.clear()
            return True
        return False



# ===================================================================
# Trigger system — persistent pattern matching
# ===================================================================

def _triggers_path():
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), "triggers.json")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "triggers.json")


def _bot_config_path():
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), "bot_config.json")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot_config.json")


def _load_bot_config():
    try:
        with open(_bot_config_path(), "r") as f:
            data = json.loads(f.read())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_bot_config(config):
    try:
        with open(_bot_config_path(), "w") as f:
            f.write(json.dumps(config, indent=2))
    except Exception:
        pass


def _migrate_trigger_mode(t):
    """Migrate old loop/sound bools to mode/sound_name fields."""
    if "mode" in t:
        return t.get("mode", "loop"), t.get("sound_name", "NONE")
    # Legacy: loop=True → "loop", loop=False → "once"; sound=True → keep mode but set sound
    if t.get("sound", False) and not t.get("loop", True):
        return "sound", "SystemExclamation"
    if t.get("loop", True):
        return "loop", "NONE"
    return "once", "NONE"


def _load_triggers():
    # Read bot_config.json for default key_pairs/loop_delay/loop_count
    _bcfg = _load_bot_config()
    _def_kp = _bcfg.get("key_pairs", [{"key": "4", "wait": "1"}])
    _def_ld = str(_bcfg.get("loop_delay", "5000"))
    _def_lc = str(_bcfg.get("loop_count", "3"))
    try:
        with open(_triggers_path(), "r") as f:
            data = json.loads(f.read())
            if isinstance(data, list):
                result = []
                for t in data:
                    if isinstance(t, dict) and "pattern" in t:
                        mode, sound_name = _migrate_trigger_mode(t)
                        ttype = t.get("type", "text")
                        base = {
                            "pattern": t["pattern"],
                            "mode": mode,
                            "sound_name": sound_name,
                            "key_pairs": t.get("key_pairs", list(_def_kp)),
                            "loop_delay": str(t.get("loop_delay", _def_ld)),
                            "loop_count": str(t.get("loop_count", _def_lc)),
                            "auto_target": bool(t.get("auto_target", False)),
                        }
                        if ttype == "opcode":
                            base["type"] = "opcode"
                            base["opcode"] = t.get("opcode", 0)
                            base["field"] = t.get("field", "text")
                        else:
                            base["type"] = "text"
                        result.append(base)
                return result
    except Exception:
        pass
    return [{
        "pattern": "you gain party experience",
        "mode": "once",
        "sound_name": "NONE",
        "key_pairs": [{"key": "x", "wait": "1"}],
        "loop_delay": "5000",
        "loop_count": "3",
        "type": "text",
        "auto_target": False,
    }]


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


def _send_slash_command(cmd):
    """Send a slash command to the game chat: [Enter]cmd[Enter]."""
    _send_vk(VK_RETURN)
    time.sleep(0.05)
    _send_string(cmd)
    time.sleep(0.05)
    _send_vk(VK_RETURN)
    time.sleep(0.15)


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


def send_attack_keys(key_pairs, target_name=None, fizzle_check=None, fizzle_log=None):
    """Send a sequence of attack keys to the game window. Returns True on success.
    key_pairs: list of (key_str, wait_secs) tuples, e.g. [("4", 1.0), ("/cast 1", 1.0)]
    Keys starting with '/' are sent as slash commands: [Enter]cmd[Enter].
    target_name: if set, sends /target <name> before the key sequence.
    fizzle_check: callable returning True if a fizzle was detected (checks & clears).
    fizzle_log: callable(str) for logging fizzle re-casts.
    """
    hwnd = _find_game_window()
    if not hwnd:
        return False
    _force_foreground(hwnd)
    time.sleep(0.15)
    if user32.GetForegroundWindow() != hwnd:
        # Retry once
        _force_foreground(hwnd)
        time.sleep(0.15)
        if user32.GetForegroundWindow() != hwnd:
            return False

    # Auto-target: send /target <name> before keys
    if target_name:
        _send_slash_command(f"/target {target_name}")
        time.sleep(0.3)

    # Clear any stale fizzle flag before starting
    if fizzle_check:
        fizzle_check()

    for i, (key, wait) in enumerate(key_pairs):
        # Re-verify game is still focused before each key
        if user32.GetForegroundWindow() != hwnd:
            _force_foreground(hwnd)
            time.sleep(0.1)
            if user32.GetForegroundWindow() != hwnd:
                return False

        def _send_key():
            if key.startswith("/"):
                _send_slash_command(key)
            else:
                _send_char(key)

        _send_key()

        # Wait period — poll for fizzles and re-send if detected
        if i < len(key_pairs) - 1:
            jitter = wait * random.uniform(0, 0.5)
            deadline = time.time() + wait + jitter
            fizzle_retries = 0
            while time.time() < deadline:
                time.sleep(0.1)
                if fizzle_check and fizzle_retries < 3 and fizzle_check():
                    fizzle_retries += 1
                    if fizzle_log:
                        fizzle_log(f"Fizzle! Re-sending: {key} (retry {fizzle_retries}/3)")
                    # Re-focus and re-send
                    if user32.GetForegroundWindow() != hwnd:
                        _force_foreground(hwnd)
                        time.sleep(0.1)
                    _send_key()
                    # Push back deadline — full wait restarts
                    jitter = wait * random.uniform(0, 0.5)
                    deadline = time.time() + wait + jitter
        else:
            # Last key — still check for fizzle briefly
            if fizzle_check:
                fizzle_retries = 0
                end = time.time() + min(wait, 2.0)
                while time.time() < end and fizzle_retries < 3:
                    time.sleep(0.1)
                    if fizzle_check():
                        fizzle_retries += 1
                        if fizzle_log:
                            fizzle_log(f"Fizzle! Re-sending: {key} (retry {fizzle_retries}/3)")
                        if user32.GetForegroundWindow() != hwnd:
                            _force_foreground(hwnd)
                            time.sleep(0.1)
                        _send_key()
                        end = time.time() + min(wait, 2.0)
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

# Windows system sounds available via winsound.PlaySound(alias, SND_ALIAS)
WINDOWS_SOUNDS = [
    "NONE",
    # Classic system sounds
    "SystemExclamation",
    "SystemHand",
    "SystemAsterisk",
    "SystemNotification",
    ".Default",
    # Notification sounds
    "Notification.Default",
    "Notification.IM",
    "Notification.Mail",
    "Notification.Reminder",
    # Looping alarms
    "Notification.Looping.Alarm",
    "Notification.Looping.Alarm2",
    "Notification.Looping.Alarm3",
    "Notification.Looping.Alarm4",
    "Notification.Looping.Alarm5",
    "Notification.Looping.Alarm6",
    "Notification.Looping.Alarm7",
    "Notification.Looping.Alarm8",
    "Notification.Looping.Alarm9",
    "Notification.Looping.Alarm10",
    # Looping ringtones
    "Notification.Looping.Call",
    "Notification.Looping.Call2",
    "Notification.Looping.Call3",
    "Notification.Looping.Call4",
    "Notification.Looping.Call5",
    "Notification.Looping.Call6",
    "Notification.Looping.Call7",
    "Notification.Looping.Call8",
    "Notification.Looping.Call9",
    "Notification.Looping.Call10",
    # Device / misc
    "DeviceConnect",
    "DeviceDisconnect",
    "DeviceFail",
    "CriticalBatteryAlarm",
    "WindowsUAC",
]


class BotApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ChatParser V2.0")
        self.configure(bg=COLORS["bg"])
        self.geometry("620x900")
        self.minsize(550, 700)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.75)

        # Bot state
        self._bot_running = False
        self._bot_thread = None
        self._bot_stop = threading.Event()
        self._bot_triggered = False
        self._bot_mode = "loop"      # "loop", "once", or "sound"
        self._bot_sound_name = "NONE"  # which Windows sound to play
        self._active_trigger_pattern = None  # pattern of currently active trigger
        self._active_trigger_idx = None      # index of currently active trigger
        self._active_trigger_target = None   # speaker name for auto-target
        self._trigger_last_fired = {}        # idx -> timestamp of last fire
        self._pending_triggers = []          # queue of (mode, sound, pattern, idx, target_name) waiting to fire
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

    def _trigger_cooldown(self, trig):
        """Compute cooldown in seconds for a trigger = sum of key wait times + 1s buffer."""
        total = 0
        for kp in trig.get("key_pairs", []):
            try:
                total += max(float(kp.get("wait", "1")), 0)
            except ValueError:
                total += 1.0
        return total + 1.0

    def _trigger_on_cooldown(self, idx):
        """Return True if trigger idx is still on cooldown from its last fire."""
        last = self._trigger_last_fired.get(idx)
        if last is None:
            return False
        trig = self._triggers[idx] if idx < len(self._triggers) else {}
        cd = self._trigger_cooldown(trig)
        return (time.time() - last) < cd

    def _check_triggers(self, text):
        """Return (trigger_dict, index) for first matching text trigger, or (None, None)."""
        text_lower = text.lower()
        for i, trig in enumerate(self._triggers):
            if trig.get("type", "text") != "text":
                continue
            pat = trig["pattern"]
            if pat == "*" or pat.lower() in text_lower:
                if not self._trigger_on_cooldown(i):
                    return trig, i
        return None, None

    @staticmethod
    def _extract_speaker_name(text):
        """Extract the source entity name from combat/chat text for auto-targeting.
        Returns the name string, or None if not found / local player."""
        if not text:
            return None
        # Local player — no need to target self
        if text.startswith("Your ") or text.startswith("You "):
            return None
        # Chat patterns: "Zanthis tells the party,", "Zanthis says,", etc.
        _chat_verbs = (
            " tells ", " says,", " says ", " shouts,", " shouts ",
            " auctions,", " auctions ",
        )
        for v in _chat_verbs:
            idx = text.find(v)
            if idx > 0:
                return text[:idx]
        # Possessive: "Bannin's Life Draw hits..."
        pos = text.find("'s ")
        if pos > 0:
            return text[:pos]
        # Third-person melee verbs: "Bannin slashes a goblin..."
        _target_verbs = (
            " slashes ", " hits ", " kicks ", " punches ", " bashes ",
            " crushes ", " bites ", " stabs ", " pierces ", " strikes ",
            " claws ", " gores ", " mauls ", " rends ", " smashes ",
        )
        for v in _target_verbs:
            idx = text.find(v)
            if idx > 0:
                return text[:idx]
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

        # Scrollbar (dark trough, black slider)
        sb = tk.Scrollbar(container, orient="vertical",
                          troughcolor=COLORS["bg_dark"],
                          bg=COLORS["bg"], activebackground=COLORS["bg_light"],
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
        # Opacity toggle (sun icon) — top-right corner
        self._opaque = False  # starts at 75%
        _opacity_border = tk.Frame(title_frame, bg=COLORS["gold_dim"],
                                    bd=0, padx=1, pady=1)
        _opacity_border.place(relx=1.0, x=-8, y=4, anchor="ne")
        self._opacity_border = _opacity_border
        self._opacity_btn = tk.Label(
            _opacity_border, text="\u2600", bg=COLORS["bg"],
            fg=COLORS["gold_dim"], font=("Segoe UI Emoji", 12),
            cursor="hand2", bd=0, padx=4, pady=1)
        self._opacity_btn.pack()
        self._opacity_btn.bind("<Button-1>", self._toggle_opacity)

        # ══════════════════════════════════════
        # Section 1: Bot Controls
        # ══════════════════════════════════════
        ctrl_sec = self._deco_section(self, title="Master Control")

        # ON/OFF toggle
        self._toggle_btn = tk.Button(
            ctrl_sec, text="OFF", width=10,
            bg=COLORS["red"], fg=COLORS["bg_dark"],
            activebackground=COLORS["red"],
            font=("Consolas", 14, "bold"),
            relief="flat", cursor="hand2",
            command=self._toggle_bot)
        self._toggle_btn.pack(pady=(0, 6))

        # Bot status line
        self._status_label = tk.Label(
            ctrl_sec, text="Status: Idle", bg=COLORS["bg"],
            fg=COLORS["fg_dim"], font=("Consolas", 10), anchor="w")
        self._status_label.pack(fill="x", pady=(6, 0))

        # ══════════════════════════════════════
        # Section 2: Triggers / Opcode Browser
        # ══════════════════════════════════════
        trig_sec = self._deco_section(self, title="Triggers", expand=True)
        # Fixed height — content scrolls instead of pushing layout
        trig_sec._deco_outer.configure(height=320)
        trig_sec._deco_outer.pack_propagate(False)

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
        self._tab_opcode_btn.pack(side="left", padx=(2, 2))

        # Center divider 2
        tk.Label(tab_inner, text="\u2502", bg=COLORS["bg"], fg=COLORS["gold"],
                 font=("Consolas", 10)).pack(side="left", padx=2)

        self._tab_discovery_btn = tk.Button(
            tab_inner, text="\u25C6 Discovery", font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2", padx=12, pady=3,
            command=lambda: self._switch_trigger_tab("discovery"))
        self._tab_discovery_btn.pack(side="left", padx=(2, 4))

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

        # Trigger table header — widths match trigger row widgets
        hdr_frame = tk.Frame(self._text_trig_frame, bg=COLORS["bg_dark"])
        hdr_frame.pack(fill="x", pady=(4, 0))
        tk.Label(hdr_frame, text="Pattern", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8),
                 anchor="w").pack(side="left", fill="x", expand=True, padx=4)
        tk.Label(hdr_frame, text="Mode", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8),
                 anchor="center", width=9).pack(side="left", padx=2)
        tk.Label(hdr_frame, text="SFX", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8),
                 anchor="center", width=14).pack(side="left", padx=2)
        tk.Label(hdr_frame, text="", bg=COLORS["bg_dark"],
                 width=2).pack(side="left", padx=(2, 4))

        # Scrollable trigger table area
        trig_scroll_frame = tk.Frame(self._text_trig_frame, bg=COLORS["bg_dark"])
        trig_scroll_frame.pack(fill="both", expand=True, pady=(0, 4))

        self._trig_canvas = tk.Canvas(
            trig_scroll_frame, bg=COLORS["bg_dark"], highlightthickness=0)
        trig_sb = tk.Scrollbar(
            trig_scroll_frame, orient="vertical",
            command=self._trig_canvas.yview,
            troughcolor=COLORS["bg_dark"], bg=COLORS["bg"],
            activebackground=COLORS["bg_light"], relief="flat", width=10, bd=0)
        trig_sb.pack(side="right", fill="y")
        self._trig_canvas.pack(side="left", fill="both", expand=True)
        self._trig_canvas.configure(yscrollcommand=trig_sb.set)

        self._trigger_table = tk.Frame(self._trig_canvas, bg=COLORS["bg_dark"])
        self._trig_canvas_window = self._trig_canvas.create_window(
            (0, 0), window=self._trigger_table, anchor="nw")
        self._trigger_table.bind("<Configure>",
            lambda _e: self._trig_canvas.configure(
                scrollregion=self._trig_canvas.bbox("all")))
        self._trig_canvas.bind("<Configure>",
            lambda e: self._trig_canvas.itemconfig(
                self._trig_canvas_window, width=e.width))

        # Mousewheel scroll for trigger table
        def _on_trig_mousewheel(e):
            self._trig_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        self._trig_canvas.bind("<MouseWheel>", _on_trig_mousewheel)
        self._trigger_table.bind("<MouseWheel>", _on_trig_mousewheel)
        def _bind_trig_mw(widget):
            widget.bind("<MouseWheel>", _on_trig_mousewheel)
            for child in widget.winfo_children():
                _bind_trig_mw(child)
        self._bind_trig_mw = _bind_trig_mw

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
            troughcolor=COLORS["bg_dark"], bg=COLORS["bg"],
            activebackground=COLORS["bg_light"], relief="flat", width=10, bd=0)
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

        # ---- Discovery container (hidden by default) ----
        self._discovery_frame = tk.Frame(trig_sec, bg=COLORS["bg"])
        # Not packed yet — shown when tab switches

        # Header row with buttons
        disc_hdr = tk.Frame(self._discovery_frame, bg=COLORS["bg"])
        disc_hdr.pack(fill="x", pady=(4, 2))
        self._disc_count_lbl = tk.Label(
            disc_hdr, text="NPCs: 0  |  PCs: 0", bg=COLORS["bg"],
            fg=COLORS["gold"], font=("Consolas", 9, "bold"), anchor="w")
        self._disc_count_lbl.pack(side="left")
        tk.Button(disc_hdr, text="Reset", bg=COLORS["red"],
                  fg=COLORS["bg_dark"], font=("Consolas", 9, "bold"),
                  relief="flat", cursor="hand2", width=6,
                  command=self._reset_discovery).pack(side="right", padx=(4, 0))
        tk.Button(disc_hdr, text="Copy", bg=COLORS["blue"],
                  fg=COLORS["bg_dark"], font=("Consolas", 9, "bold"),
                  relief="flat", cursor="hand2", width=6,
                  command=self._copy_discovery).pack(side="right")

        # Two-column layout: NPCs left, PCs right
        disc_cols = tk.Frame(self._discovery_frame, bg=COLORS["bg"])
        disc_cols.pack(fill="both", expand=True, pady=(0, 4))
        disc_cols.rowconfigure(0, weight=1)
        disc_cols.columnconfigure(0, weight=1)
        disc_cols.columnconfigure(1, weight=1)

        # NPC column
        npc_col = tk.Frame(disc_cols, bg=COLORS["bg"])
        npc_col.grid(row=0, column=0, sticky="nsew", padx=(0, 2))
        tk.Label(npc_col, text="NPCs", bg=COLORS["bg_dark"],
                 fg=COLORS["gold"], font=("Consolas", 9, "bold")).pack(fill="x")
        npc_list_frame, self._disc_npc_list = self._scrollable_text(
            npc_col, bg=COLORS["bg_dark"], fg=COLORS["fg"],
            font=("Consolas", 9), wrap="none", relief="flat",
            border=0, padx=6, pady=4, cursor="arrow",
            state="disabled", height=12)
        npc_list_frame.pack(fill="both", expand=True)
        self._disc_npc_list.tag_configure("npc", foreground=COLORS["fg"])

        # PC column
        pc_col = tk.Frame(disc_cols, bg=COLORS["bg"])
        pc_col.grid(row=0, column=1, sticky="nsew", padx=(2, 0))
        tk.Label(pc_col, text="Players", bg=COLORS["bg_dark"],
                 fg=COLORS["gold"], font=("Consolas", 9, "bold")).pack(fill="x")
        pc_list_frame, self._disc_pc_list = self._scrollable_text(
            pc_col, bg=COLORS["bg_dark"], fg=COLORS["fg"],
            font=("Consolas", 9), wrap="none", relief="flat",
            border=0, padx=6, pady=4, cursor="arrow",
            state="disabled", height=12)
        pc_list_frame.pack(fill="both", expand=True)
        self._disc_pc_list.tag_configure("pc", foreground=COLORS["fg"])

        self._disc_version_ui = -1  # track when to re-render

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
        """Build one trigger row: [▶ pattern] [Loop/Once] [sound] [X] + hidden detail panel."""
        idx = len(self._trigger_rows)

        # Outer container holds header row + detail frame
        outer = tk.Frame(self._trigger_table, bg=COLORS["bg_light"])
        outer.pack(fill="x", pady=(1, 0))

        row = tk.Frame(outer, bg=COLORS["bg_light"], pady=2)
        row.pack(fill="x")

        # Arrow + Pattern label — clickable to expand
        if trig.get("type") == "opcode":
            op = trig.get("opcode", 0)
            field = trig.get("field", "")
            pat_text = f"[0x{op:04X}.{field}] {trig['pattern']}"
            label_fg = COLORS["fg_dim"]
        else:
            pat_text = trig["pattern"]
            label_fg = COLORS["fg"]
        arrow_lbl = tk.Label(row, text="\u25B6", bg=COLORS["bg_light"],
                             fg=COLORS["gold_dim"], font=("Consolas", 8),
                             cursor="hand2")
        arrow_lbl.pack(side="left", padx=(4, 0))
        pat_lbl = tk.Label(row, text=pat_text, bg=COLORS["bg_light"],
                           fg=label_fg, font=("Consolas", 9),
                           anchor="w", cursor="hand2")
        pat_lbl.pack(side="left", fill="x", expand=True, padx=(2, 4))
        arrow_lbl.bind("<Button-1>", lambda _e, i=idx: self._toggle_trigger_expand(i))
        pat_lbl.bind("<Button-1>", lambda _e, i=idx: self._toggle_trigger_expand(i))

        # Mode cycle button (Loop → Once → Sound → Loop)
        mode = trig.get("mode", "loop")
        mode_labels = {"loop": "Loop", "once": "Once", "sound": "Sound Only"}
        mode_colors = {"loop": COLORS["teal"], "once": COLORS["peach"], "sound": COLORS["yellow"]}
        mode_btn = tk.Button(
            row, text=mode_labels.get(mode, "Loop"),
            bg=mode_colors.get(mode, COLORS["teal"]),
            fg=COLORS["bg_dark"], font=("Consolas", 8, "bold"),
            relief="flat", cursor="hand2", width=9,
            command=lambda i=idx: self._cycle_trigger_mode(i))
        mode_btn.pack(side="left", padx=2)

        # Sound dropdown
        sound_var = tk.StringVar(value=trig.get("sound_name", "NONE"))
        sound_menu = tk.OptionMenu(row, sound_var, *WINDOWS_SOUNDS,
                                   command=lambda _val, i=idx, sv=sound_var: self._set_trigger_sound(i, sv))
        _sfx_active = trig.get("sound_name", "NONE") != "NONE"
        sound_menu.configure(
            bg=COLORS["mauve"] if _sfx_active else COLORS["bg_dark"],
            fg=COLORS["bg_dark"] if _sfx_active else COLORS["fg_dim"],
            font=("Consolas", 7), relief="flat",
            highlightthickness=0, width=12, cursor="hand2")
        sound_menu["menu"].configure(bg=COLORS["bg_light"], fg=COLORS["fg"],
                                     font=("Consolas", 8))
        sound_menu.pack(side="left", padx=2)

        # Red X remove button
        tk.Button(row, text="X",
                  bg=COLORS["red"], fg=COLORS["bg_dark"],
                  font=("Consolas", 8, "bold"),
                  relief="flat", cursor="hand2", width=2,
                  command=lambda i=idx: self._remove_trigger(i)).pack(side="left", padx=(2, 4))

        # Detail frame — hidden until expanded
        detail_frame = tk.Frame(outer, bg=COLORS["bg_dark"])

        self._trigger_rows.append({
            "frame": outer, "mode_btn": mode_btn,
            "sound_var": sound_var, "sound_menu": sound_menu,
            "arrow_lbl": arrow_lbl, "pat_lbl": pat_lbl,
            "detail_frame": detail_frame,
            "expanded": False, "built": False,
            "key_pair_entries": [], "delay_entry": None, "count_entry": None,
            "key_rows_frame": None,
        })
        # Bind mousewheel so scrolling works over trigger rows
        if hasattr(self, "_bind_trig_mw"):
            self._bind_trig_mw(outer)

    def _toggle_trigger_expand(self, idx):
        """Toggle expand/collapse of trigger detail panel."""
        if idx < 0 or idx >= len(self._trigger_rows):
            return
        # Sound Only mode — never expand
        if self._triggers[idx].get("mode", "loop") == "sound":
            return
        info = self._trigger_rows[idx]
        if info["expanded"]:
            info["detail_frame"].pack_forget()
            info["arrow_lbl"].configure(text="\u25B6")
            info["expanded"] = False
        else:
            if not info["built"]:
                self._build_trigger_detail(info, self._triggers[idx], idx)
                info["built"] = True
            info["detail_frame"].pack(fill="x", padx=(12, 4), pady=(0, 4))
            info["arrow_lbl"].configure(text="\u25BC")
            info["expanded"] = True

    def _build_trigger_detail(self, info, trig, idx):
        """Build the inline key sequence / delay / count settings inside detail_frame."""
        df = info["detail_frame"]

        # Keys/settings container — hidden when mode is "sound"
        keys_container = tk.Frame(df, bg=COLORS["bg_dark"])
        info["keys_container"] = keys_container

        # Auto-target checkbox — above keys
        at_row = tk.Frame(keys_container, bg=COLORS["bg_dark"])
        at_row.pack(fill="x", padx=4, pady=(4, 2))
        at_var = tk.BooleanVar(value=trig.get("auto_target", False))
        at_cb = tk.Checkbutton(
            at_row, text="Auto /target speaker",
            variable=at_var, bg=COLORS["bg_dark"], fg=COLORS["teal"],
            selectcolor=COLORS["bg_light"], activebackground=COLORS["bg_dark"],
            activeforeground=COLORS["teal"], font=("Consolas", 8),
            command=lambda i=idx, v=at_var: self._toggle_auto_target(i, v))
        at_cb.pack(side="left")
        info["auto_target_var"] = at_var

        # Header row
        hdr = tk.Frame(keys_container, bg=COLORS["bg_dark"])
        hdr.pack(fill="x", pady=(4, 0), padx=4)
        tk.Label(hdr, text="Key or /cmd", bg=COLORS["bg_dark"], fg=COLORS["gold_dim"],
                 font=("Consolas", 8), width=10, anchor="w").pack(side="left", padx=(0, 4))
        tk.Label(hdr, text="Wait(s)", bg=COLORS["bg_dark"], fg=COLORS["gold_dim"],
                 font=("Consolas", 8), width=7, anchor="w").pack(side="left", padx=(0, 4))
        tk.Label(hdr, text="(+jitter)", bg=COLORS["bg_dark"], fg=COLORS["gold_dim"],
                 font=("Consolas", 7), anchor="w").pack(side="left")

        # Key pair rows container
        key_rows_frame = tk.Frame(keys_container, bg=COLORS["bg_dark"])
        key_rows_frame.pack(fill="x", padx=4)
        info["key_rows_frame"] = key_rows_frame
        self._trig_rebuild_key_rows(idx)

        # Add key pair row
        add_row = tk.Frame(keys_container, bg=COLORS["bg_dark"])
        add_row.pack(fill="x", padx=4, pady=(2, 0))
        add_key_e = tk.Entry(add_row, bg=COLORS["bg_light"], fg=COLORS["fg"],
                             insertbackground=COLORS["fg"],
                             font=("Consolas", 10), width=10, relief="flat", border=2)
        add_key_e.pack(side="left", padx=(0, 4))
        add_wait_e = tk.Entry(add_row, bg=COLORS["bg_light"], fg=COLORS["fg"],
                              insertbackground=COLORS["fg"],
                              font=("Consolas", 10), width=5, relief="flat", border=2)
        add_wait_e.insert(0, "1")
        add_wait_e.pack(side="left", padx=(0, 4))
        tk.Button(add_row, text="Add", bg=COLORS["green"], fg=COLORS["bg_dark"],
                  font=("Consolas", 8, "bold"), relief="flat", cursor="hand2",
                  width=3, command=lambda i=idx, ke=add_key_e, we=add_wait_e: self._trig_add_key_pair(i, ke, we)
                  ).pack(side="left")

        # Loop Delay row
        delay_row = tk.Frame(keys_container, bg=COLORS["bg_dark"])
        delay_row.pack(fill="x", padx=4, pady=(4, 0))
        tk.Label(delay_row, text="Loop Delay ms", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8)).pack(side="left", padx=(0, 2))
        delay_e = tk.Entry(delay_row, bg=COLORS["bg_light"], fg=COLORS["fg"],
                           insertbackground=COLORS["fg"],
                           font=("Consolas", 10), width=6, relief="flat", border=2)
        delay_e.insert(0, trig.get("loop_delay", "5000"))
        delay_e.pack(side="left")
        delay_e.bind("<FocusOut>", lambda _e, i=idx: self._sync_trigger_settings(i))

        # Loop Count row
        count_row = tk.Frame(keys_container, bg=COLORS["bg_dark"])
        count_row.pack(fill="x", padx=4, pady=(2, 4))
        tk.Label(count_row, text="Loops", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8)).pack(side="left", padx=(0, 2))
        count_e = tk.Entry(count_row, bg=COLORS["bg_light"], fg=COLORS["fg"],
                           insertbackground=COLORS["fg"],
                           font=("Consolas", 10), width=4, relief="flat", border=2)
        count_e.insert(0, trig.get("loop_count", "3"))
        count_e.pack(side="left")
        count_e.bind("<FocusOut>", lambda _e, i=idx: self._sync_trigger_settings(i))

        info["delay_entry"] = delay_e
        info["count_entry"] = count_e

        # Pattern edit row — at the bottom, unobtrusive
        pat_row = tk.Frame(keys_container, bg=COLORS["bg_dark"])
        pat_row.pack(fill="x", padx=4, pady=(4, 4))
        tk.Label(pat_row, text="Pattern", bg=COLORS["bg_dark"],
                 fg=COLORS["fg_dim"], font=("Consolas", 8)).pack(side="left", padx=(0, 2))
        pat_e = tk.Entry(pat_row, bg=COLORS["bg_light"], fg=COLORS["fg"],
                         insertbackground=COLORS["fg"],
                         font=("Consolas", 10), relief="flat", border=2)
        pat_e.insert(0, trig.get("pattern", ""))
        pat_e.pack(side="left", fill="x", expand=True)
        pat_e.bind("<KeyRelease>", lambda _e, i=idx: self._sync_trigger_pattern(i))
        pat_e.bind("<FocusOut>", lambda _e, i=idx: self._sync_trigger_pattern(i))
        info["pattern_entry"] = pat_e

        # Show container only if mode is not "sound"
        if trig.get("mode", "loop") != "sound":
            keys_container.pack(fill="x")

        # Bind mousewheel on new detail children
        if hasattr(self, "_bind_trig_mw"):
            self._bind_trig_mw(df)

    def _trig_rebuild_key_rows(self, idx):
        """Rebuild key pair entry rows for trigger idx from its trigger dict."""
        info = self._trigger_rows[idx]
        krf = info["key_rows_frame"]
        for child in krf.winfo_children():
            child.destroy()
        info["key_pair_entries"] = []
        trig = self._triggers[idx]
        for pidx, pair in enumerate(trig.get("key_pairs", [])):
            row = tk.Frame(krf, bg=COLORS["bg_dark"])
            row.pack(fill="x", pady=1)
            ke = tk.Entry(row, bg=COLORS["bg_light"], fg=COLORS["fg"],
                          insertbackground=COLORS["fg"],
                          font=("Consolas", 10), width=10, relief="flat", border=2)
            ke.insert(0, pair.get("key", ""))
            ke.pack(side="left", padx=(0, 4))
            we = tk.Entry(row, bg=COLORS["bg_light"], fg=COLORS["fg"],
                          insertbackground=COLORS["fg"],
                          font=("Consolas", 10), width=5, relief="flat", border=2)
            _wv = pair.get("wait", "1")
            try:
                _wf = float(_wv)
                _wv = str(int(_wf)) if _wf == int(_wf) else _wv
            except ValueError:
                pass
            we.insert(0, _wv)
            we.pack(side="left", padx=(0, 4))
            ke.bind("<FocusOut>", lambda _e, i=idx, p=pidx: self._sync_trig_key_pair(i, p))
            we.bind("<FocusOut>", lambda _e, i=idx, p=pidx: self._sync_trig_key_pair(i, p))
            tk.Button(row, text="X", bg=COLORS["red"], fg=COLORS["bg_dark"],
                      font=("Consolas", 8, "bold"), relief="flat", cursor="hand2",
                      width=2,
                      command=lambda i=idx, p=pidx: self._trig_remove_key_pair(i, p)
                      ).pack(side="left")
            info["key_pair_entries"].append((ke, we))
        # Rebind mousewheel on rebuilt rows
        if hasattr(self, "_bind_trig_mw"):
            self._bind_trig_mw(krf)

    def _sync_trig_key_pair(self, idx, pair_idx):
        """Sync an edited key pair entry back to trigger dict and save."""
        if idx >= len(self._triggers) or idx >= len(self._trigger_rows):
            return
        info = self._trigger_rows[idx]
        entries = info["key_pair_entries"]
        if pair_idx >= len(entries):
            return
        ke, we = entries[pair_idx]
        trig = self._triggers[idx]
        kps = trig.get("key_pairs", [])
        if pair_idx < len(kps):
            kps[pair_idx]["key"] = ke.get().strip()
            kps[pair_idx]["wait"] = we.get().strip()
            _save_triggers(self._triggers)

    def _trig_add_key_pair(self, idx, key_entry, wait_entry):
        """Add a new key pair to trigger idx."""
        key = key_entry.get().strip()
        if not key:
            return
        wait = wait_entry.get().strip() or "1"
        trig = self._triggers[idx]
        if "key_pairs" not in trig:
            trig["key_pairs"] = []
        trig["key_pairs"].append({"key": key, "wait": wait})
        _save_triggers(self._triggers)
        key_entry.delete(0, "end")
        self._trig_rebuild_key_rows(idx)

    def _trig_remove_key_pair(self, idx, pair_idx):
        """Remove a key pair from trigger idx."""
        trig = self._triggers[idx]
        kps = trig.get("key_pairs", [])
        if 0 <= pair_idx < len(kps):
            kps.pop(pair_idx)
            _save_triggers(self._triggers)
            self._trig_rebuild_key_rows(idx)

    def _toggle_auto_target(self, idx, var):
        """Toggle auto_target for trigger idx and save."""
        if idx < 0 or idx >= len(self._triggers):
            return
        self._triggers[idx]["auto_target"] = var.get()
        _save_triggers(self._triggers)

    def _sync_trigger_settings(self, idx):
        """Sync delay/count entries back to trigger dict and save."""
        if idx >= len(self._triggers) or idx >= len(self._trigger_rows):
            return
        info = self._trigger_rows[idx]
        trig = self._triggers[idx]
        if info["delay_entry"]:
            trig["loop_delay"] = info["delay_entry"].get().strip()
        if info["count_entry"]:
            trig["loop_count"] = info["count_entry"].get().strip()
        _save_triggers(self._triggers)

    def _sync_trigger_pattern(self, idx):
        """Sync pattern entry back to trigger dict, update header label, and save."""
        if idx >= len(self._triggers) or idx >= len(self._trigger_rows):
            return
        info = self._trigger_rows[idx]
        pat_e = info.get("pattern_entry")
        if not pat_e:
            return
        new_pat = pat_e.get().strip()
        if not new_pat:
            return
        trig = self._triggers[idx]
        trig["pattern"] = new_pat
        # Update the collapsed header label
        if trig.get("type") == "opcode":
            op = trig.get("opcode", 0)
            field = trig.get("field", "")
            info["pat_lbl"].configure(text=f"[0x{op:04X}.{field}] {new_pat}")
        else:
            info["pat_lbl"].configure(text=new_pat)
        _save_triggers(self._triggers)

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
        trig = {
            "type": "text", "pattern": pattern, "mode": "sound", "sound_name": "NONE",
            "key_pairs": [{"key": "1", "wait": "1"}],
            "loop_delay": "5000",
            "loop_count": "3",
            "auto_target": False,
        }
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

    def _cycle_trigger_mode(self, idx):
        if idx < 0 or idx >= len(self._triggers):
            return
        trig = self._triggers[idx]
        cycle = {"loop": "once", "once": "sound", "sound": "loop"}
        new_mode = cycle.get(trig.get("mode", "loop"), "loop")
        trig["mode"] = new_mode
        _save_triggers(self._triggers)
        # Update button in-place
        mode_labels = {"loop": "Loop", "once": "Once", "sound": "Sound Only"}
        mode_colors = {"loop": COLORS["teal"], "once": COLORS["peach"], "sound": COLORS["yellow"]}
        btn = self._trigger_rows[idx]["mode_btn"]
        btn.configure(text=mode_labels.get(new_mode, "Loop"), bg=mode_colors.get(new_mode, COLORS["teal"]))
        # Sound mode — collapse the entire detail panel and hide keys container
        info = self._trigger_rows[idx]
        if new_mode == "sound":
            if info["expanded"]:
                info["detail_frame"].pack_forget()
                info["arrow_lbl"].configure(text="\u25B6")
                info["expanded"] = False
            kc = info.get("keys_container")
            if kc:
                kc.pack_forget()
        else:
            kc = info.get("keys_container")
            if kc:
                kc.pack(fill="x")
        # Reset active trigger if this one is currently running
        if (self._bot_triggered and
                self._active_trigger_idx == idx):
            self._bot_triggered = False
            self._bot_mode = "loop"
            self._bot_sound_name = "NONE"
            self._active_trigger_pattern = None
            self._active_trigger_idx = None
            self._active_trigger_target = None
            self._bot_status = "Waiting for trigger..."
            self._log(f"Trigger reset: {trig['pattern']}")
        _blog.info("TRIGGER_MODE: %s → %s", trig["pattern"], new_mode)

    def _set_trigger_sound(self, idx, sound_var):
        if idx < 0 or idx >= len(self._triggers):
            return
        trig = self._triggers[idx]
        name = sound_var.get()
        trig["sound_name"] = name
        _save_triggers(self._triggers)
        # Update dropdown color
        menu = self._trigger_rows[idx]["sound_menu"]
        if name != "NONE":
            menu.configure(bg=COLORS["mauve"], fg=COLORS["bg_dark"])
            self._play_sound(name)
        else:
            menu.configure(bg=COLORS["bg_dark"], fg=COLORS["fg_dim"])
        _blog.info("TRIGGER_SOUND: %s → %s", trig["pattern"], name)

    # ----- Tab switching -----

    def _apply_tab_style(self):
        """Style tab buttons based on current _trigger_tab."""
        active = {"bg": COLORS["gold"], "fg": COLORS["bg_dark"]}
        inactive = {"bg": COLORS["bg_light"], "fg": COLORS["fg_dim"]}
        self._tab_text_btn.configure(**(active if self._trigger_tab == "text" else inactive))
        self._tab_opcode_btn.configure(**(active if self._trigger_tab == "opcode" else inactive))
        self._tab_discovery_btn.configure(**(active if self._trigger_tab == "discovery" else inactive))

    def _switch_trigger_tab(self, tab):
        if tab == self._trigger_tab:
            return
        self._trigger_tab = tab
        self._apply_tab_style()
        # Hide all tab frames
        self._text_trig_frame.pack_forget()
        self._opcode_frame.pack_forget()
        self._discovery_frame.pack_forget()
        if tab == "text":
            self._text_trig_frame.pack(fill="both", expand=True)
            # Scroll trigger table to bottom
            self._trig_canvas.update_idletasks()
            self._trig_canvas.yview_moveto(1.0)
        elif tab == "opcode":
            self._opcode_view = "list"
            self._opcode_detail_outer.pack_forget()
            self._opcode_list_frame.pack(fill="both", expand=True)
            self._opcode_frame.pack(fill="both", expand=True)
            # Full rebuild from buffer when switching to this tab
            self._render_opcode_list()
            self._opcode_list.see("end")
        elif tab == "discovery":
            self._discovery_frame.pack(fill="both", expand=True)
            self._render_discovery()
            self._disc_npc_list.see("end")
            self._disc_pc_list.see("end")

    # ----- Opcode Browser -----

    def _opcode_preview(self, msg):
        """Build a short preview string for an opcode message."""
        fields = msg.get("fields", {})
        opcode = msg.get("opcode", 0)
        if "text" in fields and fields["text"]:
            txt = fields["text"]
            return txt[:80] + ("..." if len(txt) > 80 else "")
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
            return preview[:80] + ("..." if len(preview) > 80 else "")
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
                    "mode": "sound",
                    "sound_name": "NONE",
                    "key_pairs": [{"key": "1", "wait": "1"}],
                    "loop_delay": "5000",
                    "loop_count": "3",
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

    # ----- Discovery tab -----

    def _render_discovery(self):
        """Rebuild the discovery lists if data has changed."""
        npcs, pcs, version = self._backend.message_handler.get_discovery()
        if version == self._disc_version_ui:
            return
        self._disc_version_ui = version
        self._disc_count_lbl.configure(text=f"NPCs: {len(npcs)}  |  PCs: {len(pcs)}")
        self._disc_npc_list.configure(state="normal")
        self._disc_npc_list.delete("1.0", "end")
        for name in npcs:
            self._disc_npc_list.insert("end", name + "\n", "npc")
        self._disc_npc_list.configure(state="disabled")
        self._disc_pc_list.configure(state="normal")
        self._disc_pc_list.delete("1.0", "end")
        for name in pcs:
            self._disc_pc_list.insert("end", name + "\n", "pc")
        self._disc_pc_list.configure(state="disabled")

    def _copy_discovery(self):
        """Copy all NPC and PC names to clipboard."""
        npcs, pcs, _ = self._backend.message_handler.get_discovery()
        lines = []
        if npcs:
            lines.append("=== NPCs ===")
            lines.extend(npcs)
        if pcs:
            lines.append("=== Players ===")
            lines.extend(pcs)
        if lines:
            self.clipboard_clear()
            self.clipboard_append("\n".join(lines))

    def _reset_discovery(self):
        """Clear the NPC and PC name lists."""
        handler = self._backend.message_handler
        with handler._lock:
            handler._npc_names.clear()
            handler._pc_names.clear()
            handler._disc_version += 1
        self._render_discovery()

    # ----- Opcode trigger matching -----

    def _check_opcode_triggers(self, opcode_msg):
        """Check opcode log entry against opcode triggers. Returns (trigger, index) or (None, None)."""
        msg_opcode = opcode_msg.get("opcode", -1)
        fields = opcode_msg.get("fields", {})
        for i, trig in enumerate(self._triggers):
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
                if not self._trigger_on_cooldown(i):
                    return trig, i
        return None, None

    # ── Opacity / Bot toggle ─────────────────────────────────────

    def _toggle_opacity(self, _event=None):
        self._opaque = not self._opaque
        if self._opaque:
            self.attributes("-alpha", 1.0)
            self._opacity_btn.configure(fg=COLORS["gold"])
            self._opacity_border.configure(bg=COLORS["gold"])
        else:
            self.attributes("-alpha", 0.75)
            self._opacity_btn.configure(fg=COLORS["gold_dim"])
            self._opacity_border.configure(bg=COLORS["gold_dim"])

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
        self._bot_mode = "loop"
        self._bot_sound_name = "NONE"
        self._active_trigger_pattern = None
        self._active_trigger_idx = None
        self._active_trigger_target = None
        self._pending_triggers.clear()
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
        self._bot_mode = "loop"
        self._bot_sound_name = "NONE"
        self._active_trigger_pattern = None
        self._active_trigger_idx = None
        self._active_trigger_target = None
        self._pending_triggers.clear()
        self._toggle_btn.configure(text="OFF", bg=COLORS["red"])
        self._bot_status = "Idle"
        self._log("Bot OFF")

    def _play_sound(self, sound_name="SystemExclamation"):
        """Play a Windows system sound on the main thread."""
        if not sound_name or sound_name == "NONE":
            return
        def _do():
            try:
                winsound.PlaySound(sound_name,
                                   winsound.SND_ALIAS | winsound.SND_ASYNC)
            except Exception:
                pass
        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

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

    def _get_trigger_settings(self, idx):
        """Read key_pairs, loop_delay, loop_count for trigger idx.
        Prefers live entry widgets if expanded, falls back to trigger dict."""
        trig = self._triggers[idx] if 0 <= idx < len(self._triggers) else {}
        info = self._trigger_rows[idx] if 0 <= idx < len(self._trigger_rows) else {}

        # Key pairs — from entry widgets if expanded & built, else from dict
        pairs = []
        if info and info.get("expanded") and info.get("key_pair_entries"):
            try:
                for ke, we in info["key_pair_entries"]:
                    k = ke.get().strip()
                    try:
                        w = max(float(we.get()), 0)
                    except (ValueError, tk.TclError):
                        w = 1.0
                    if k:
                        pairs.append((k, w))
            except tk.TclError:
                pairs = []
        if not pairs:
            for kp in trig.get("key_pairs", []):
                k = kp.get("key", "").strip()
                try:
                    w = max(float(kp.get("wait", "1")), 0)
                except ValueError:
                    w = 1.0
                if k:
                    pairs.append((k, w))

        # Delay
        delay_ms = 5000
        if info and info.get("expanded") and info.get("delay_entry"):
            try:
                delay_ms = int(info["delay_entry"].get())
            except (ValueError, tk.TclError):
                pass
        else:
            try:
                delay_ms = int(trig.get("loop_delay", "5000"))
            except ValueError:
                pass

        # Count
        max_loops = 0
        if info and info.get("expanded") and info.get("count_entry"):
            try:
                max_loops = int(info["count_entry"].get())
            except (ValueError, tk.TclError):
                pass
        else:
            try:
                max_loops = int(trig.get("loop_count", "3"))
            except ValueError:
                pass

        # Auto-target — from live checkbox if expanded, else from dict
        auto_target = trig.get("auto_target", False)
        if info and info.get("expanded") and info.get("auto_target_var"):
            try:
                auto_target = info["auto_target_var"].get()
            except tk.TclError:
                pass

        return pairs, delay_ms, max_loops, auto_target

    def _activate_next_pending(self):
        """Pop the next pending trigger (if any) and activate it.
        Returns True if a pending trigger was activated."""
        while self._pending_triggers:
            mode, sound_name, pattern, idx, target_name = self._pending_triggers.pop(0)
            # Skip if on cooldown
            if self._trigger_on_cooldown(idx):
                continue
            self._bot_triggered = True
            self._bot_mode = mode
            self._bot_sound_name = sound_name
            self._active_trigger_pattern = pattern
            self._active_trigger_idx = idx
            self._active_trigger_target = target_name
            return True
        return False

    def _bot_loop(self):
        """Bot thread — when triggered + ON, send attack keys or play sound."""
        loops_done = 0
        while not self._bot_stop.is_set():
            if not self._bot_triggered:
                # Check pending queue before sleeping
                if self._activate_next_pending():
                    loops_done = 0
                    continue
                loops_done = 0
                self._bot_stop.wait(0.2)
                continue

            if not self._backend.has_keys:
                self._bot_status = "Waiting for game..."
                self._bot_stop.wait(1)
                continue

            mode = self._bot_mode
            sound_name = self._bot_sound_name
            tidx = self._active_trigger_idx

            # Sound-only mode — play sound and reset, no keys sent
            if mode == "sound":
                self._bot_status = "Sound alert"
                self._play_sound(sound_name)
                self._bot_triggered = False
                self._bot_status = "Waiting for trigger..."
                continue

            # Once / Loop modes — read per-trigger settings
            if tidx is not None:
                pairs, delay_ms, max_loops, _at = self._get_trigger_settings(tidx)
            else:
                pairs, delay_ms, max_loops, _at = [], 5000, 0, False

            # Auto-target: use speaker name captured at match time (first iteration only)
            target_name = self._active_trigger_target if loops_done == 0 else None

            self._bot_status = "Attacking..."
            if pairs:
                keys_display = ", ".join(k for k, _ in pairs)
                if target_name:
                    self._log(f"Targeting: {target_name}")
                fcheck = self._backend.message_handler.check_fizzle
                if send_attack_keys(pairs, target_name=target_name,
                                    fizzle_check=fcheck, fizzle_log=self._log):
                    loops_done += 1
                    # Stamp cooldown so this trigger doesn't re-fire immediately
                    if tidx is not None:
                        self._trigger_last_fired[tidx] = time.time()
                    if max_loops > 0:
                        self._log(f"Sent keys: {keys_display} ({loops_done}/{max_loops})")
                    else:
                        self._log(f"Sent keys: {keys_display}")
                else:
                    self._log("Game window not found")

            # Play sound on each iteration if one is set
            if sound_name and sound_name != "NONE":
                self._play_sound(sound_name)

            if mode == "once":
                self._bot_triggered = False
                loops_done = 0
                self._bot_status = "Waiting for trigger..."
                continue

            # Loop mode — check loop count limit (0 = infinite)
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
            matched, midx = self._check_triggers(text)
            if matched:
                mode = matched.get("mode", "loop")
                sound_name = matched.get("sound_name", "NONE")
                _blog.info("TRIGGER_MATCH: %s (mode=%s sound=%s)",
                           text, mode, sound_name)
                self._log(f"MATCH [{matched['pattern']}] ({mode}): {text}", "matched")
                # Extract speaker name for auto-target
                speaker = None
                if matched.get("auto_target"):
                    speaker = msg.get("entity_name") or self._extract_speaker_name(text)
                    if speaker:
                        self._log(f"Auto-target speaker: {speaker}")
                    else:
                        self._log("Auto-target: no speaker name found in text")
                if self._bot_running:
                    if len(self._pending_triggers) < 10:
                        self._pending_triggers.append(
                            (mode, sound_name, matched["pattern"], midx, speaker))
                else:
                    self._log("Bot is OFF — turn ON to act on triggers")

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
            opc_matched, oidx = self._check_opcode_triggers(opc_msg)
            if opc_matched:
                mode = opc_matched.get("mode", "loop")
                sound_name = opc_matched.get("sound_name", "NONE")
                opname = opc_msg.get("opcode_name", f"0x{opc_msg.get('opcode',0):04X}")
                field = opc_matched.get("field", "")
                _blog.info("OPCODE_TRIGGER_MATCH: %s.%s (mode=%s sound=%s)",
                           opname, field, mode, sound_name)
                self._log(f"MATCH [{opname}.{field}={opc_matched['pattern']}] ({mode})", "matched")
                # Extract entity name for auto-target from opcode fields
                opc_speaker = None
                if opc_matched.get("auto_target"):
                    opc_fields = opc_msg.get("fields", {})
                    opc_speaker = opc_fields.get("entity_name")
                if self._bot_running and len(self._pending_triggers) < 10:
                    self._pending_triggers.append(
                        (mode, sound_name, opc_matched["pattern"], oidx, opc_speaker))

        # Incrementally append new entries to opcode list (no full redraw)
        if opcode_msgs and self._trigger_tab == "opcode" and self._opcode_view == "list":
            self._append_opcode_entries(opcode_msgs)

        # Refresh discovery tab if active
        if self._trigger_tab == "discovery":
            self._render_discovery()

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
