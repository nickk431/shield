import re

import modules.helpers as helpers

# Known x64dbg specific DLLs
x64dbg_dlls = ['x64dbg.dll', 'x32dbg.dll', 'TitanEngine.dll', 'Scylla.dll']

# Known x64dbg window texts and class names
x64dbg_window_texts = [
    "x64dbg", "QToolBarClassWindow", "MHTabWidgetClassWindow", "statusBarWindow", "menuBarWindow",
    "CidMarshalWnd", "QEventDispatcherWin32_Internal_Widget", "Qt5QWindowIcon", "Qt5ClipboardView"
]

x64dbg_class_names = [
    "Qt5QWindowIcon", "Qt5ClipboardView", "UserAdapterWindowClass", "OleMainThreadWndClass"
]

# x64dbg title pattern (might need???)
x64dbg_title_pattern = re.compile(r'x64dbg', re.IGNORECASE)


def detect():
    processes_info = helpers.gather_process_info()

    # Check based on DLLs
    for process_info in processes_info:
        if helpers.check_dlls(process_info, x64dbg_dlls):
            print(f"\033[31mx64dbg detected by DLLs: {process_info['name']}\033[0m")
            return True

    # Check based on window properties
    processes = helpers.gather_windows_info()
    for pid, windows in processes.items():
        for hwnd, window_text, class_name in windows:
            if x64dbg_title_pattern.match(window_text) or any(
                    text in window_text for text in x64dbg_window_texts) or class_name in x64dbg_class_names:
                print(f"x64dbg detected: PID={pid}, Window Text={window_text}, Class Name={class_name}")
                return True

    return False
