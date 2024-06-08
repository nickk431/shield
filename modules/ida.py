import re

import modules.helpers as helpers

# Known IDA Pro specific DLLs
ida_pro_dlls = [
    'ida.dll'
]

# Known IDA Pro window texts and class names
ida_pro_window_texts = [
    "IDA: Quick start", "Disassemble a new file", "Work on your own", "Load the old disassembly"
]

ida_pro_class_names = [
    "Qt5153QTWindowIcon", "CidMarshalWndClass", "UserAdapterWindowClass",
    "QEventDispatcherWin32_Internal", "Qt5153QTClipboardView", "Qt5153QTPowerDummyWindow",
    "OleMainThreadWndClass"
]

# IDA Pro title pattern
ida_pro_title_pattern = re.compile(r'IDA', re.IGNORECASE)


def detect():
    processes_info = helpers.gather_process_info()

    # Check based on DLLs
    # for process_info in processes_info:
    #     if helpers.check_dlls(process_info, ida_pro_dlls):
    #         print(f"\033[31mIDA Pro detected by DLLs: {process_info['name']}\033[0m")
    #         return True

    # Check based on window properties
    processes = helpers.gather_windows_info()
    for pid, windows in processes.items():
        for hwnd, window_text, class_name in windows:
            if ida_pro_title_pattern.match(window_text) or any(
                    text in window_text for text in ida_pro_window_texts) or class_name in ida_pro_class_names:
                print(f"IDA Pro detected: PID={pid}, Window Text={window_text}, Class Name={class_name}")
                return True

    return False
