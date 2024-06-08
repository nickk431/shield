import ctypes
import os
from ctypes import wintypes

import pefile
import psutil


def check_dlls(process_info, dlls_to_check):
    try:
        process_path = process_info['exe']
        if not process_path or not os.path.exists(process_path):
            return False

        pe = pefile.PE(process_path, fast_load=True)
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            dll_names = [entry.dll.decode('utf-8').lower() for entry in pe.DIRECTORY_ENTRY_IMPORT]
            if any(dll in dll_names for dll in dlls_to_check):
                return True
        except AttributeError:
            pass

    except Exception as e:
        print(f"Error checking DLLs for process {process_info['name']}: {e}")

    return False


def get_window_text(hwnd):
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
    if length > 0:
        buf = ctypes.create_unicode_buffer(length + 1)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
        return buf.value
    return ""


def get_class_name(hwnd):
    buf = ctypes.create_unicode_buffer(256)
    ctypes.windll.user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def enum_window_callback(hwnd, lParam):
    pid = wintypes.DWORD()
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    window_text = get_window_text(hwnd)
    class_name = get_class_name(hwnd)

    processes = ctypes.cast(lParam, ctypes.POINTER(ctypes.py_object)).contents.value

    if pid.value in processes:
        processes[pid.value].append((hwnd, window_text, class_name))
    return True


def gather_windows_info():
    processes = {p.info['pid']: [] for p in psutil.process_iter(['pid', 'name', 'exe'])}

    EnumWindows = ctypes.windll.user32.EnumWindows
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
    enum_proc = EnumWindowsProc(enum_window_callback)
    ctypes.windll.user32.EnumWindows(enum_proc, ctypes.byref(ctypes.py_object(processes)))

    return processes


def gather_process_info():
    processes_info = []
    for process in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if process.info['exe']:
                processes_info.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            print(f"Error gathering process info: {e}")
    return processes_info
