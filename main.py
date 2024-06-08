import concurrent.futures
import hashlib
import os
import sys
import time
from functools import lru_cache
from multiprocessing import Pool, cpu_count

import pefile
import psutil

import modules.cheat_engine as cheat_engine
import modules.ida as ida
import modules.x64dbg as dbg

# List of known malicious process names
known_processes = [
    "cheatengine", "reclass", "ida", "ollydbg", "ghidra", "winhex",
    "softice", "hxd", "peid", "scylla", "syser", "lordpe", "immunity debugger",
    "procdump", "procmon", "procexp", "wireshark", "tcpview", "fiddler",
    "charles", "sandboxie", "windbg", "api monitor", "tcpdump", "pestudio",
    "radare2", "binary ninja", "binwalk", "bintext", "reshacker", "resource hacker",
    "ollydbg", "detect it easy", "cutter", "dnspy", "de4dot", "fair use wizard",
    "ghidra", "ida pro", "immunity debugger", "olly debugger", "ollydbg", "ollyice",
    "pestudio", "procdump", "process hacker", "process hacker 2", "process monitor",
    "resource hacker", "scylla", "simple assembly explorer", "spextool", "syser",
    "vbox", "vboxservice", "vmware", "vmwareuser", "vmtoolsd", "vmwaretray",
    "vmtool", "virtualbox", "virtualbox guest additions", "virtualbox guest additions",
    "xvi32", "hex editor", "hex editor neo", "file insight",
    "filemon", "findstrings", "guardicore", "ht editor", "regmon", "reshacker",
    "serienumerics", "snort", "sysinternals", "sysmon", "tcld", "tcpview",
    "apimonitor", "heaventools", "immunity", "paros", "radare2", "unpack",
    "unpacker", "wireshark", "x32dbg", "x64dbg", "xvi32", "binary ninja", "systeminformer"
]


# Function to load known MD5 hashes from a file
def load_known_hashes(filename):
    with open(filename, 'r') as file:
        return set(line.strip() for line in file)


known_hashes = load_known_hashes('hash_list.txt')


@lru_cache(maxsize=128)
def is_signed(file_path):
    def check_signature(path):
        try:
            pe = pefile.PE(path, fast_load=True)
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            is_signed = security_dir.VirtualAddress != 0 and security_dir.Size != 0
            return is_signed
        except Exception:
            return False

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(check_signature, file_path)
        try:
            return future.result(timeout=10)
        except concurrent.futures.TimeoutError:
            return False


def generate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        return None


def check_process(process_info):
    try:
        process_name = process_info['name'].lower()
        process_path = process_info['exe']

        if any(known_name in process_name for known_name in known_processes):
            return False

        if process_path and os.path.exists(process_path):
            md5_hash = generate_md5(process_path)
            if md5_hash in known_hashes:
                return False

    except Exception as e:
        print(f"Error processing: {e}")

    return True


def gather_process_info():
    processes_info = []
    for process in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'create_time']):
        try:
            if process.info['exe'] and process.info['pid'] > 1000:
                processes_info.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            print(f"Error gathering process info: {e}")
    return processes_info


def check_processes():
    processes_info = gather_process_info()

    with Pool(int(cpu_count() / 2)) as pool:
        results = pool.map(check_process, processes_info)

        if any(result is False for result in results):
            return False

    return True


def terminate_protected_process(protected_process_names):
    if protected_process_names:
        for process in psutil.process_iter(['pid', 'name']):
            if process.info['name'].lower() in [name.lower() for name in protected_process_names]:
                print(f"Terminating protected process: {process.info['name']}")
                process.terminate()


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <protected_process_name1>;<protected_process_name2>;...")
        sys.exit(1)

    protected_process_names = sys.argv[1].split(";")

    detection_functions = [
        cheat_engine.detect,
        dbg.detect,
        ida.detect
    ]

    while True:
        if not check_processes():
            terminate_protected_process(protected_process_names)
            continue

        for detect in detection_functions:
            if detect():
                terminate_protected_process(protected_process_names)
                continue

        time.sleep(1)


if __name__ == "__main__":
    main()
