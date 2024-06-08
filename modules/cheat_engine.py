import re

import modules.helpers as helpers

# Known Cheat Engine specific DLLs
cheat_engine_dlls = ['dbk32.dll', 'dbk64.sys', 'cehook.dll', 'cedbghook.dll', 'lua53-64.dll']

# Known Cheat Engine window texts and class names
cheat_engine_window_texts = [
    "Cheat Engine", "Memory View", "Add Address Manually", "Enable Speedhack", "Unrandomizer",
    "Rounded (extreme)", "Rounded (default)", "Truncated", "Lua formula", "Hex", "Undo Scan",
    "Next Scan", "Memory Scan Options"
]

cheat_engine_class_names = [
    "TMainForm", "TMemoryViewForm", "TAddressList"
]

# Cheat engine title pattern
cheat_engine_title_pattern = re.compile(r'^\w{5} \w{6} [A-Za-z0-9]\.[A-Za-z0-9]$', re.IGNORECASE)


def detect():
    processes_info = helpers.gather_process_info()

    # Check based on DLLs
    for process_info in processes_info:
        if helpers.check_dlls(process_info, cheat_engine_dlls):
            print(f"\033[31mCheat Engine detected by DLLs: {process_info['name']}\033[0m")
            return True

            # Check based on window properties
    processes = helpers.gather_windows_info()
    for pid, windows in processes.items():
        for hwnd, window_text, class_name in windows:
            if cheat_engine_title_pattern.match(window_text) or any(text in window_text for text in
                                                                    cheat_engine_window_texts) or class_name in cheat_engine_class_names:
                print(f"Cheat Engine detected: PID={pid}, Window Text={window_text}, Class Name={class_name}")
                return True

    return False
