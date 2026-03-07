import os
import ctypes
from collections import Counter

PR_SET_NAME = 15

def get_process_names():
    names = []

    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue

        comm_path = f"/proc/{pid}/comm"

        try:
            with open(comm_path, "r") as f:
                name = f.read().strip()
                names.append(name)
        except:
            # process might have exited or permission denied
            pass

    return names


def most_common_process():
    names = get_process_names()

    if not names:
        return None

    counter = Counter(names)
    name, count = counter.most_common(1)[0]

    print(f"Most common process: {name} ({count} instances)")
    return name


def rename_process(new_name):
    libc = ctypes.CDLL("libc.so.6")
    libc.prctl(PR_SET_NAME, new_name.encode(), 0, 0, 0)


if __name__ == "__main__":
    name = most_common_process()

    if name:
        rename_process(name)
        print(f"Renamed current process to: {name}")

        # keep process alive to observe it
        import time
        while True:
            time.sleep(5)