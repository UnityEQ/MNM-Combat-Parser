"""
Find game process PID via Windows API (CreateToolhelp32Snapshot).
"""

import ctypes
import ctypes.wintypes as wt
import time

from core.logger import get_logger


# --- Windows API Constants ---
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MAX_PATH = 260


# --- Windows API Structures ---
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


kernel32 = ctypes.windll.kernel32
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Process32First.restype = wt.BOOL
kernel32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype = wt.BOOL
kernel32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]


def find_processes(process_name):
    """
    Find all processes matching the given name (case-insensitive).

    Returns list of (pid, exe_name) tuples.
    """
    results = []
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        get_logger().error("CreateToolhelp32Snapshot failed")
        return results

    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if not kernel32.Process32First(snap, ctypes.byref(entry)):
            return results

        while True:
            exe = entry.szExeFile.decode("utf-8", errors="replace").lower()
            if exe == process_name.lower():
                results.append((entry.th32ProcessID, exe))
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)

    return results


def is_process_alive(pid):
    """Check if a process with the given PID is still running."""
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return False
    kernel32.CloseHandle(handle)
    return True


def find_game_pid(process_name="mnm.exe"):
    """
    Find the game process PID.

    If multiple instances are found, prompts the user to select one.
    Returns the selected PID or None if not found.
    """
    log = get_logger()
    matches = find_processes(process_name)

    if not matches:
        return None

    if len(matches) == 1:
        pid = matches[0][0]
        log.info(f"Found game process: {process_name} (PID {pid})")
        return pid

    # Multiple instances — prompt user
    log.info(f"Found {len(matches)} instances of {process_name}:")
    for i, (pid, name) in enumerate(matches):
        print(f"  [{i + 1}] PID {pid}")

    while True:
        try:
            choice = input(f"Select instance (1-{len(matches)}): ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(matches):
                pid = matches[idx][0]
                log.info(f"Selected PID {pid}")
                return pid
        except (ValueError, EOFError):
            pass
        print(f"Invalid selection. Enter a number 1-{len(matches)}.")


def wait_for_process(process_name="mnm.exe", poll_interval=2.0):
    """
    Block until the game process is found. Polls every poll_interval seconds.

    Returns the PID once found.
    """
    log = get_logger()
    log.info(f"Waiting for {process_name} to start...")

    while True:
        pid = find_game_pid(process_name)
        if pid is not None:
            return pid
        time.sleep(poll_interval)
