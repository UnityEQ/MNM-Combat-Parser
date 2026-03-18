"""
Read encryption keys from the running game process memory.

Uses Windows API (ReadProcessMemory) via ctypes to extract AES, HMAC,
and XOR keys from Client.ConnectionInfo static fields in the IL2CPP runtime.

IL2CPP layout (from Il2CppDumper analysis):
  GameAssembly.dll + TYPEINFO_RVA  -> Il2CppClass* pointer
  Il2CppClass + 0xB8              -> static_fields pointer
  static_fields + field_offset    -> field value (byte[] pointer for keys)
  byte[] pointer + 0x18           -> array length (int32)
  byte[] pointer + 0x20           -> array data
"""

import ctypes
import ctypes.wintypes as wt
import struct
import threading
import time

from core.logger import get_logger


# --- Windows API Constants ---
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_PATH = 260
MAX_MODULE_NAME32 = 255


# --- IL2CPP Layout Constants (from Il2CppDumper output) ---

# RVA within GameAssembly.dll where Il2CppClass** for Client.ConnectionInfo is stored
# From script.json: Address 88407256 = 0x544FCD8 (pre-patch)
# Post-patch (2026-03-18): 0x5466F20 found via memory scan
CONNECTIONINFO_TYPEINFO_RVA = 0x5466F20

# Il2CppClass_1 is 0xB8 bytes, static_fields is the next member
IL2CPP_STATIC_FIELDS_OFFSET = 0xB8

# Client.ConnectionInfo static field offsets (from dump.cs)
FIELD_HMAC_KEY = 0x38     # byte[]
FIELD_AES_KEY = 0x40      # byte[]
FIELD_XOR_KEY = 0x48      # byte[]
FIELD_TOKEN = 0x50        # string
FIELD_SERVER_NAME = 0x18  # string (for validation)

# IL2CPP array memory layout (64-bit)
# [0x00] Il2CppClass* klass
# [0x08] void* monitor
# [0x10] Il2CppArrayBounds* bounds (null for 1D)
# [0x18] int32 max_length
# [0x20] data bytes...
ARRAY_LENGTH_OFFSET = 0x18
ARRAY_DATA_OFFSET = 0x20

# IL2CPP string memory layout (64-bit)
# [0x00] Il2CppClass* klass
# [0x08] void* monitor
# [0x10] int32 length (char count, not byte count)
# [0x14] char16[] data (UTF-16LE)
STRING_LENGTH_OFFSET = 0x10
STRING_DATA_OFFSET = 0x14


# --- Windows API Structures ---

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", ctypes.c_char * MAX_PATH),
    ]


kernel32 = ctypes.windll.kernel32

kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.Module32First.restype = wt.BOOL
kernel32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
kernel32.Module32Next.restype = wt.BOOL
kernel32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]


# --- Low-level memory read helpers ---

def _read_mem(handle, address, size):
    """Read raw bytes from process memory."""
    buf = ctypes.create_string_buffer(size)
    n_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buf, size, ctypes.byref(n_read)
    )
    if not ok or n_read.value != size:
        raise MemoryError(f"ReadProcessMemory failed at 0x{address:X} (wanted {size}, got {n_read.value})")
    return buf.raw


def _read_ptr(handle, address):
    """Read an 8-byte pointer."""
    return struct.unpack("<Q", _read_mem(handle, address, 8))[0]


def _read_i32(handle, address):
    """Read a 4-byte signed int."""
    return struct.unpack("<i", _read_mem(handle, address, 4))[0]


def _read_u32(handle, address):
    """Read a 4-byte unsigned int."""
    return struct.unpack("<I", _read_mem(handle, address, 4))[0]


def _read_il2cpp_string(handle, ptr):
    """Read an IL2CPP System.String. Returns Python str or None."""
    if ptr == 0:
        return None
    try:
        char_count = _read_i32(handle, ptr + STRING_LENGTH_OFFSET)
        if char_count <= 0 or char_count > 4096:
            return None
        raw = _read_mem(handle, ptr + STRING_DATA_OFFSET, char_count * 2)
        return raw.decode("utf-16-le", errors="replace")
    except MemoryError:
        return None


def _read_il2cpp_byte_array(handle, ptr, log=None):
    """Read an IL2CPP byte[]. Returns bytes or None."""
    if ptr == 0:
        return None
    try:
        # Read the array header for diagnostics
        header = _read_mem(handle, ptr, 0x24)
        length = struct.unpack_from("<i", header, ARRAY_LENGTH_OFFSET)[0]
        if log:
            header_hex = " ".join(f"{b:02x}" for b in header)
            log.debug(f"  Array@0x{ptr:X}: len={length} header=[{header_hex}]")
        if length <= 0 or length > 1024:
            return None
        return _read_mem(handle, ptr + ARRAY_DATA_OFFSET, length)
    except MemoryError as e:
        if log:
            log.debug(f"  Array@0x{ptr:X}: read failed: {e}")
        return None


# --- Module enumeration ---

def find_module_base(pid, module_name="GameAssembly.dll"):
    """Find base address and size of a loaded module in the target process."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == ctypes.c_void_p(-1).value:
        raise OSError(f"CreateToolhelp32Snapshot failed for PID {pid} (error {ctypes.GetLastError()})")

    try:
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        if not kernel32.Module32First(snap, ctypes.byref(entry)):
            raise OSError("Module32First failed")

        while True:
            name = entry.szModule.decode("utf-8", errors="replace").lower()
            if name == module_name.lower():
                base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
                return base, entry.modBaseSize
            if not kernel32.Module32Next(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)

    raise FileNotFoundError(f"Module '{module_name}' not found in PID {pid}")


# --- Class pointer finding ---

# Cache the class pointer so we only search once per session
_cached_class_ptr = None


def _validate_class_ptr(handle, class_ptr, log):
    """Check if a pointer looks like a valid ConnectionInfo Il2CppClass."""
    try:
        name_ptr = _read_ptr(handle, class_ptr + 0x10)
        if name_ptr == 0:
            return False
        name_raw = _read_mem(handle, name_ptr, 32)
        class_name = name_raw.split(b'\x00', 1)[0].decode("utf-8", errors="replace")
        if class_name != "ConnectionInfo":
            return False
        # Also check namespace = "Client"
        ns_ptr = _read_ptr(handle, class_ptr + 0x18)
        if ns_ptr:
            ns_raw = _read_mem(handle, ns_ptr, 32)
            namespace = ns_raw.split(b'\x00', 1)[0].decode("utf-8", errors="replace")
            if namespace == "Client":
                log.info(f"Validated: Client.ConnectionInfo at 0x{class_ptr:X}")
                return True
            log.debug(f"Name matches but namespace='{namespace}', not 'Client'")
            return False
        return True  # No namespace readable, but name matched
    except MemoryError:
        return False


def _find_connectioninfo_class(handle, base, mod_size, log):
    """Find the Il2CppClass* for Client.ConnectionInfo."""
    global _cached_class_ptr
    if _cached_class_ptr is not None:
        return _cached_class_ptr

    # Method 1: Use the known TypeInfo RVA from Il2CppDumper script.json
    typeinfo_addr = base + CONNECTIONINFO_TYPEINFO_RVA
    if CONNECTIONINFO_TYPEINFO_RVA < mod_size:
        try:
            class_ptr = _read_ptr(handle, typeinfo_addr)
            log.debug(f"TypeInfo at 0x{typeinfo_addr:X} -> 0x{class_ptr:X}")
            if class_ptr != 0 and _validate_class_ptr(handle, class_ptr, log):
                _cached_class_ptr = class_ptr
                return class_ptr
            elif class_ptr != 0:
                log.debug(f"TypeInfo RVA returned 0x{class_ptr:X} but validation failed")
        except MemoryError:
            log.debug(f"TypeInfo RVA 0x{CONNECTIONINFO_TYPEINFO_RVA:X} read failed")

    # Method 2: Scan for "ConnectionInfo\0" string in the module, then
    # search for Il2CppClass* pointers that reference it
    log.info("TypeInfo RVA failed — scanning module for ConnectionInfo class...")
    class_ptr = _scan_for_class(handle, base, mod_size, log)
    if class_ptr:
        _cached_class_ptr = class_ptr
        return class_ptr

    log.warning("Could not find ConnectionInfo class in memory")
    return None


def _scan_for_class(handle, base, mod_size, log):
    """
    Scan GameAssembly.dll memory for the C string "ConnectionInfo"
    then search for Il2CppClass* pointers that reference it.
    """
    target = b"ConnectionInfo\x00"
    chunk_size = 1024 * 1024  # 1MB chunks
    string_addrs = []

    # Step 1: Find all occurrences of the name string in the module
    for offset in range(0, mod_size, chunk_size):
        read_size = min(chunk_size + len(target), mod_size - offset)
        if read_size < len(target):
            break
        try:
            chunk = _read_mem(handle, base + offset, read_size)
        except MemoryError:
            continue
        pos = 0
        while True:
            idx = chunk.find(target, pos)
            if idx == -1:
                break
            addr = base + offset + idx
            string_addrs.append(addr)
            pos = idx + 1

    log.debug(f"Found {len(string_addrs)} 'ConnectionInfo' strings in module")

    if not string_addrs:
        return None

    # Step 2: Scan data section for Il2CppClass* pointers.
    # Read in large chunks, extract pointer-like values, validate each.
    # Data sections are typically in the latter part of the module.
    search_start = mod_size // 2
    log.debug(f"Scanning data section (offset 0x{search_start:X}+) for Il2CppClass* pointers...")
    candidates_checked = 0

    for offset in range(search_start, mod_size - chunk_size, chunk_size):
        read_size = min(chunk_size, mod_size - offset)
        if read_size < 8:
            break
        try:
            chunk = _read_mem(handle, base + offset, read_size)
        except MemoryError:
            continue

        # Scan chunk for 8-byte aligned pointer values
        for i in range(0, read_size - 7, 8):
            ptr_val = struct.unpack_from("<Q", chunk, i)[0]

            # Quick filter: valid 64-bit user-space pointer
            if ptr_val < 0x10000 or ptr_val > 0x7FFFFFFFFFFF:
                continue
            # Skip module-internal pointers (Il2CppClass is on the heap)
            if base <= ptr_val < base + mod_size:
                continue

            candidates_checked += 1
            if candidates_checked > 500000:
                log.debug("Scan limit reached")
                return None

            if _validate_class_ptr(handle, ptr_val, log):
                rva = offset + i
                log.info(f"Found ConnectionInfo class via scan at module+0x{rva:X}")
                return ptr_val

    log.debug(f"Scan complete, checked {candidates_checked} pointers, no match")
    return None


# --- Key reading ---

def read_encryption_keys(pid):
    """
    Read AES, HMAC, and XOR encryption keys from the game process.

    Walks the IL2CPP type hierarchy:
      GameAssembly.dll + RVA -> Il2CppClass* -> static_fields -> key byte[]

    Returns dict: {aes_key, hmac_key, xor_key} as bytes (or None if not set).
    Raises on fatal errors (process not accessible, module not found).
    """
    log = get_logger()

    # Find GameAssembly.dll
    base, mod_size = find_module_base(pid)
    log.info(f"GameAssembly.dll base=0x{base:X} size={mod_size / 1024 / 1024:.1f}MB")

    # Open process
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        raise OSError(f"OpenProcess failed for PID {pid} (error {ctypes.GetLastError()})")

    try:
        class_ptr = _find_connectioninfo_class(handle, base, mod_size, log)
        if class_ptr is None or class_ptr == 0:
            return {"aes_key": None, "hmac_key": None, "xor_key": None}

        # Read static_fields pointer
        static_fields = _read_ptr(handle, class_ptr + IL2CPP_STATIC_FIELDS_OFFSET)
        log.debug(f"static_fields = 0x{static_fields:X}")

        if static_fields == 0:
            log.warning("static_fields is null — class not initialized yet")
            return {"aes_key": None, "hmac_key": None, "xor_key": None}

        # Validate: read ServerName string to confirm we're in the right place
        server_name_ptr = _read_ptr(handle, static_fields + FIELD_SERVER_NAME)
        server_name = _read_il2cpp_string(handle, server_name_ptr)
        if server_name:
            log.info(f"Connected to server: '{server_name}'")

        # Read key array pointers
        hmac_ptr = _read_ptr(handle, static_fields + FIELD_HMAC_KEY)
        aes_ptr = _read_ptr(handle, static_fields + FIELD_AES_KEY)
        xor_ptr = _read_ptr(handle, static_fields + FIELD_XOR_KEY)
        log.debug(f"Key pointers — HMAC: 0x{hmac_ptr:X}, AES: 0x{aes_ptr:X}, XOR: 0x{xor_ptr:X}")

        # Dump raw static_fields region around the key offsets for diagnostics
        try:
            raw_region = _read_mem(handle, static_fields, 0x90)
            log.debug(f"static_fields raw dump (0x90 bytes):")
            for row_off in range(0, 0x90, 16):
                hex_part = " ".join(f"{b:02x}" for b in raw_region[row_off:row_off+16])
                log.debug(f"  +0x{row_off:02X}: {hex_part}")
        except MemoryError:
            log.debug("Could not dump static_fields region")

        # Read byte arrays
        hmac_key = _read_il2cpp_byte_array(handle, hmac_ptr, log)
        aes_key = _read_il2cpp_byte_array(handle, aes_ptr, log)
        xor_key = _read_il2cpp_byte_array(handle, xor_ptr, log)

        result = {"aes_key": aes_key, "hmac_key": hmac_key, "xor_key": xor_key}

        for name, val in result.items():
            if val:
                log.info(f"  {name}: {len(val)} bytes = {val.hex()}")
            else:
                log.info(f"  {name}: not available")

        return result

    finally:
        kernel32.CloseHandle(handle)


class KeyWatcher:
    """
    Periodically reads encryption keys from the game process.
    Keys can change on zone transitions (new server connection).
    """

    def __init__(self, pid, poll_interval=5.0):
        self._pid = pid
        self._poll_interval = poll_interval
        self._keys = {"aes_key": None, "hmac_key": None, "xor_key": None}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._has_keys = threading.Event()

    @property
    def keys(self):
        with self._lock:
            return dict(self._keys)

    @property
    def has_keys(self):
        return self._has_keys.is_set()

    def wait_for_keys(self, timeout=None):
        """Block until keys are available. Returns True if keys found."""
        return self._has_keys.wait(timeout=timeout)

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="KeyWatcher")
        self._thread.start()
        get_logger().info("Key watcher started")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _poll_loop(self):
        log = get_logger()
        while not self._stop_event.is_set():
            try:
                new_keys = read_encryption_keys(self._pid)

                with self._lock:
                    old_aes = self._keys.get("aes_key")
                    new_aes = new_keys.get("aes_key")

                    if new_aes and new_aes != old_aes:
                        log.info("Encryption keys updated (new session or zone change)")
                        self._keys = new_keys
                        self._has_keys.set()
                    elif new_aes and not self._has_keys.is_set():
                        self._keys = new_keys
                        self._has_keys.set()
                    elif not new_aes and old_aes:
                        log.warning("Keys became unavailable (disconnect?)")

            except (MemoryError, OSError) as e:
                log.debug(f"Key read failed: {e}")
            except Exception as e:
                log.error(f"Key watcher error: {e}")

            self._stop_event.wait(self._poll_interval)
