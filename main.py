import PySide6.QtWidgets as qtw
import PySide6.QtCore as qtc
import PySide6.QtGui as qtg
import psutil
import functools
import win32api
import ctypes
from ctypes import wintypes


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID),
    ]


wintrust = ctypes.WinDLL("wintrust.dll")
winverifytrust = wintrust.WinVerifyTrust
winverifytrust.argtypes = [
    wintypes.HWND,
    ctypes.POINTER(GUID),
    ctypes.POINTER(WINTRUST_DATA),
]
winverifytrust.restype = wintypes.LONG

action_guid = GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


def verify_signature(path):
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO),
        path,
        None,
        None,
    )

    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = 2
    data.fdwRevocationChecks = 0
    data.dwUnionChoice = 1
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 0
    data.dwProvFlags = 0x00000010 | 0x00001000

    return winverifytrust(
        None,
        ctypes.byref(action_guid),
        ctypes.byref(data),
    ) == 0


@functools.lru_cache(maxsize=2048)
def get_publisher(exe_path):
    name = "Unknown"

    try:
        info = win32api.GetFileVersionInfo(exe_path, "\\")
        translations = info.get("VarFileInfo", {}).get(
            "Translation", [(0x0409, 1200)]
        )

        for language, codepage in translations:
            key = f"\\StringFileInfo\\{language:04x}{codepage:04x}\\CompanyName"
            try:
                value = win32api.GetFileVersionInfo(exe_path, key).strip()
                if value:
                    name = value
                    break
            except Exception:
                continue
    except Exception:
        pass

    try:
        status = "verified" if verify_signature(exe_path) else "unverified"
    except (OSError, ValueError):
        status = "unverified"

    return f"{name} ({status})"


class ProcessPoller(qtc.QThread):
    results_ready = qtc.Signal(list)

    def run(self):
        procs = []

        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "cmdline", "status", "memory_info"]
        ):
            try:
                info = proc.info
                procs.append((
                    info["name"] or "",
                    info["pid"],
                    info["ppid"] or 0,
                    " ".join(info["cmdline"] or []),
                    (info["status"] or "unknown").capitalize(),
                    get_publisher(proc.exe()),
                    0.0,
                    info["memory_info"].rss if info["memory_info"] else 0
                ))
            except (psutil.Error, OSError):
                continue

        self.results_ready.emit(procs)


app = qtw.QApplication([])
mw = qtw.QMainWindow()
mw.setWindowTitle("PodExp")
mw.setFixedSize(qtc.QSize(1500, 1000))

tv = qtw.QTreeView(mw)
tv.resize(qtc.QSize(1500, 880))

model = qtg.QStandardItemModel()
model.setHorizontalHeaderLabels([
    "Name", "PID", "PPID", "Command Line",
    "Status", "Publisher", "CPU", "RAM"
])
tv.setModel(model)

tv.header().resizeSection(3, 300)
tv.move(0, 120)


def add_entries(model, entries):
    for entry in entries:
        model.appendRow([
            qtg.QStandardItem(str(value))
            for value in entry
        ])


def update_tv(entries):
    tv.setUpdatesEnabled(False)
    try:
        model.removeRows(0, model.rowCount())
        add_entries(model, entries)
    finally:
        tv.setUpdatesEnabled(True)
        tv.viewport().update()


poller = ProcessPoller(mw)
poller.results_ready.connect(update_tv)

timer = qtc.QTimer(mw)


def start_poll():
    if not poller.isRunning():
        poller.start()


timer.timeout.connect(start_poll)
timer.start(10000)

def shutdown():
    timer.stop()

    if poller.isRunning():
        poller.wait()


app.aboutToQuit.connect(shutdown)

if __name__ == "__main__":
    mw.show()
    start_poll()
    app.exec()