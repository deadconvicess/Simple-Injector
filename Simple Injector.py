# Simple Injector - deadconvicess



import sys, os
import tempfile
import psutil
import ctypes
from ctypes import wintypes
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget,
    QFileDialog, QLabel, QLineEdit, QComboBox, QFrame, QPlainTextEdit, QSplitter, QSpacerItem, QSizePolicy
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QTimer, QProcess
import win32gui, win32process
PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
MEM_COMMIT = 0x1000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll    = ctypes.WinDLL('ntdll',    use_last_error=True)
def setup_api():
    global OpenProcess, VirtualAllocEx, WriteProcessMemory, VirtualFreeEx
    global GetModuleHandleA, GetProcAddress, CreateRemoteThread, NtCreateThreadEx
    global OpenThread, QueueUserAPC
    OpenProcess = kernel32.OpenProcess
    OpenProcess.restype  = wintypes.HANDLE
    OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    VirtualAllocEx = kernel32.VirtualAllocEx
    VirtualAllocEx.restype = wintypes.LPVOID
    VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD)
    WriteProcessMemory = kernel32.WriteProcessMemory
    WriteProcessMemory.restype = wintypes.BOOL
    WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
    VirtualFreeEx = kernel32.VirtualFreeEx
    VirtualFreeEx.restype = wintypes.BOOL
    VirtualFreeEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD)
    GetModuleHandleA = kernel32.GetModuleHandleA
    GetModuleHandleA.restype = wintypes.HANDLE
    GetModuleHandleA.argtypes = (wintypes.LPCSTR,)
    GetProcAddress = kernel32.GetProcAddress
    GetProcAddress.restype = wintypes.LPVOID
    GetProcAddress.argtypes = (wintypes.HANDLE, wintypes.LPCSTR)
    CreateRemoteThread = kernel32.CreateRemoteThread
    CreateRemoteThread.restype = wintypes.HANDLE
    CreateRemoteThread.argtypes = (wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    NtCreateThreadEx = ntdll.NtCreateThreadEx
    NtCreateThreadEx.restype = wintypes.LONG
    NtCreateThreadEx.argtypes = (
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.LPVOID,
        wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.BOOL,
        wintypes.ULONG, wintypes.ULONG, wintypes.ULONG, wintypes.LPVOID
    )
    OpenThread = kernel32.OpenThread
    OpenThread.restype = wintypes.HANDLE
    OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)

    QueueUserAPC = kernel32.QueueUserAPC
    QueueUserAPC.restype = wintypes.DWORD
    QueueUserAPC.argtypes = (wintypes.LPVOID, wintypes.HANDLE, wintypes.LPVOID)
setup_api()
STYLE = """
QWidget {
    background-color: #1f1f1f;
    color: #e0e0e0;
    font-family: "Segoe UI", Consolas, monospace;
    font-size: 10pt;
}
QFrame#TitleBar {
    background-color: #141414;
    border-bottom: 1px solid #333;
}
QLabel#TitleLabel {
    color: #1abc9c;
    font-weight: bold;
    font-size: 16pt;
}
QPushButton {
    background-color: #2a2a2a;
    color: #e0e0e0;
    border: 1px solid #444;
    border-radius: 4px;
    padding: 6px 14px;
}
QPushButton:hover {
    background-color: #333333;
    border: 1px solid #555;
}
QPushButton:pressed {
    background-color: #1f1f1f;
}
QListWidget, QLineEdit, QComboBox, QPlainTextEdit {
    background-color: #2a2a2a;
    border: 1px solid #444;
    border-radius: 4px;
    padding: 4px;
    selection-background-color: #1abc9c;
    selection-color: #1f1f1f;
}
QListWidget::item {
    padding: 6px;
}
QListWidget::item:selected {
    background-color: #16a085;
    color: #ffffff;
}
QComboBox {
    padding: 4px;
}
QSplitter::handle {
    background-color: #141414;
    width: 6px;
}
QLabel#SectionLabel {
    font-size: 12pt;
    color: #1abc9c;
    margin-bottom: 4px;
}
"""
class TitleBar(QFrame):
    def __init__(self, parent=None, title="Simple Injector"):
        super().__init__(parent)
        self.setObjectName("TitleBar")
        self.parent = parent
        self.setFixedHeight(35)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(6)
        self.title = QLabel(title, self)
        self.title.setObjectName("TitleLabel")
        layout.addWidget(self.title)
        layout.addStretch()
        btn_min = QPushButton("-", self)
        btn_min.setFixedSize(38, 38)
        btn_min.clicked.connect(self.parent.showMinimized)
        layout.addWidget(btn_min)
        btn_close = QPushButton("X", self)
        btn_close.setFixedSize(38, 38)
        btn_close.clicked.connect(self.parent.close)
        layout.addWidget(btn_close)
    def mousePressEvent(self, e):
        self.mousePos = e.globalPos()
    def mouseMoveEvent(self, e):
        if hasattr(self, 'mousePos') and self.mousePos:
            self.parent.move(self.parent.pos() + (e.globalPos() - self.mousePos))
            self.mousePos = e.globalPos()
    def mouseReleaseEvent(self, e):
        self.mousePos = None

class InjectorGUI(QWidget):
    GAME_KEYWORDS = [
        'minecraft', 'rainbow six siege', 'r6', 'csgo',
        'valorant', 'fortnite', 'call of duty', 'apex',
    ]
    EXE_NAMES = [
        'minecraft.windows.exe', 'minecraft.exe', 'javaw.exe',
        'rainbowsix.exe', 'r6.exe', 'rainbowsixsiege.exe',
        'csgo.exe', 'valorant.exe', 'fortnite.exe',
        'callofduty.exe', 'apex.exe',
    ]

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAcceptDrops(True)
        self.setFixedSize(920, 520)
        self.setStyleSheet(STYLE)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.titleBar = TitleBar(self, title="Simple Injector")
        main_layout.addWidget(self.titleBar)
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(16, 16, 16, 16)
        left_layout.setSpacing(12)
        lbl_inject = QLabel("Injector Settings")
        lbl_inject.setObjectName("SectionLabel")
        left_layout.addWidget(lbl_inject)
        self.status = QLabel("• Press 'Detect Game' to find Your Game.")
        left_layout.addWidget(self.status)
        self.procList = QListWidget()
        left_layout.addWidget(self.procList, stretch=1)
        btn_row = QHBoxLayout()
        detect_btn = QPushButton("Detect Game")
        detect_btn.setFixedHeight(32)
        detect_btn.clicked.connect(self.detect_game)
        btn_row.addWidget(detect_btn)
        clear_btn = QPushButton("Clear List")
        clear_btn.setFixedHeight(32)
        clear_btn.clicked.connect(lambda: self.procList.clear())
        btn_row.addWidget(clear_btn)
        left_layout.addLayout(btn_row)
        path_row = QHBoxLayout()
        self.dllPath = QLineEdit()
        self.dllPath.setPlaceholderText("Drag & drop DLL here or click Browse")
        path_row.addWidget(self.dllPath, stretch=1)
        browse_btn = QPushButton("Browse DLL")
        browse_btn.setFixedHeight(32)
        browse_btn.clicked.connect(self.browse_dll)
        path_row.addWidget(browse_btn)
        left_layout.addLayout(path_row)
        self.methodCombo = QComboBox()
        self.methodCombo.addItems([
            "NtCreateThreadEx",
            "QueueUserAPC (Advanced)",
            "LoadLibraryA (Standard)",
        ])
        self.methodCombo.setFixedHeight(30)
        left_layout.addWidget(self.methodCombo)
        inject_btn = QPushButton("Inject DLL")
        inject_btn.setFixedHeight(36)
        inject_btn.clicked.connect(self.inject)
        left_layout.addWidget(inject_btn)
        left_layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
        splitter.addWidget(left_panel)
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(16, 16, 16, 16)
        right_layout.setSpacing(12)
        lbl_exec = QLabel("Executor")
        lbl_exec.setObjectName("SectionLabel")
        right_layout.addWidget(lbl_exec)
        self.scriptBox = QPlainTextEdit()
        self.scriptBox.setPlaceholderText("Enter Scripts Here")
        self.scriptBox.setFont(QFont("Consolas", 10))
        right_layout.addWidget(self.scriptBox, stretch=1)
        run_btn = QPushButton("Run Script")
        run_btn.setFixedHeight(36)
        run_btn.clicked.connect(self.run_script)
        right_layout.addWidget(run_btn)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        self.process = QProcess(self)
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    def dropEvent(self, event):
        path = event.mimeData().urls()[0].toLocalFile()
        if path.lower().endswith('.dll'):
            self.dllPath.setText(path)
    def detect_game(self):
        self.procList.clear()
        self.status.setText("• Detecting...")
        self.status.setStyleSheet("color: #e0e0e0;")
        QTimer.singleShot(1000, self.finish_detect)
    def finish_detect(self):
        found_pids = set()
        def enum_windows(hwnd, _):
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            found_pids.add(pid)
        win32gui.EnumWindows(enum_windows, None)
        for p in psutil.process_iter(['pid', 'name']):
            name_lower = p.info['name'].lower()
            if name_lower in self.EXE_NAMES:
                found_pids.add(p.info['pid'])
        added = False
        for pid in found_pids:
            try:
                proc = psutil.Process(pid)
                exe = proc.name().lower()
                if exe in self.EXE_NAMES:
                    self.procList.addItem(f"{proc.name()} [{pid}]")
                    added = True
            except:
                pass
        if added:
            self.status.setText("• Select a process and click 'Inject DLL'.")
            self.status.setStyleSheet("color: #e0e0e0;")
        else:
            self.status.setText("• No game processes found.")
            self.status.setStyleSheet("color: #e74c3c;")
    def browse_dll(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select DLL to Inject", os.getcwd(), "DLL Files (*.dll)")
        if path:
            self.dllPath.setText(path)
    def inject(self):
        item = self.procList.currentItem()
        dll_path = self.dllPath.text().strip()
        if not item or not dll_path or not os.path.isfile(dll_path):
            self.status.setText("• Select a process and a valid DLL file.")
            self.status.setStyleSheet("color: #e74c3c;")
            return
        pid = int(item.text().split('[')[-1].strip(']'))
        method = self.methodCombo.currentText()

        try:
            h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                raise ctypes.WinError(ctypes.get_last_error())
            path_bytes = dll_path.encode('utf-8') + b'\0'
            mem_addr = VirtualAllocEx(h_process, None, len(path_bytes), MEM_COMMIT, PAGE_READWRITE)
            if not mem_addr:
                kernel32.CloseHandle(h_process)
                raise ctypes.WinError(ctypes.get_last_error())
            written = ctypes.c_size_t(0)
            if not WriteProcessMemory(h_process, mem_addr, path_bytes, len(path_bytes), ctypes.byref(written)):
                VirtualFreeEx(h_process, mem_addr, 0, MEM_RELEASE)
                kernel32.CloseHandle(h_process)
                raise ctypes.WinError(ctypes.get_last_error())
            h_kernel32 = GetModuleHandleA(b"kernel32.dll")
            addr_loadlib = GetProcAddress(h_kernel32, b"LoadLibraryA")
            if not addr_loadlib:
                VirtualFreeEx(h_process, mem_addr, 0, MEM_RELEASE)
                kernel32.CloseHandle(h_process)
                raise ctypes.WinError(ctypes.get_last_error())
            if method.startswith("NtCreateThreadEx"):
                h_thread = wintypes.HANDLE()
                status = NtCreateThreadEx(
                    ctypes.byref(h_thread),
                    THREAD_ALL_ACCESS,
                    None,
                    h_process,
                    addr_loadlib,
                    mem_addr,
                    False, 0, 0, 0, None
                )
                if status != 0 or not h_thread:
                    raise ctypes.WinError(ctypes.get_last_error())
                kernel32.CloseHandle(h_thread)
            elif method.startswith("QueueUserAPC"):
                queued = False
                for thread in psutil.Process(pid).threads():
                    tid = thread.id
                    h_thread = OpenThread(THREAD_ALL_ACCESS, False, tid)
                    if h_thread:
                        result = QueueUserAPC(addr_loadlib, h_thread, ctypes.c_void_p(mem_addr))
                        kernel32.CloseHandle(h_thread)
                        if result != 0:
                            queued = True
                            break
                if not queued:
                    raise Exception("Failed to queue APC to any thread.")

            else:
                thread_id = wintypes.DWORD(0)
                h_thread = CreateRemoteThread(h_process, None, 0, addr_loadlib, mem_addr, 0, ctypes.byref(thread_id))
                if not h_thread:
                    raise ctypes.WinError(ctypes.get_last_error())
                kernel32.CloseHandle(h_thread)
            QTimer.singleShot(2000, lambda: VirtualFreeEx(h_process, mem_addr, 0, MEM_RELEASE))
            kernel32.CloseHandle(h_process)
            self.status.setText("✓ Injection successful!")
            self.status.setStyleSheet("color: #2ecc71;")
        except Exception as e:
            try:
                if 'h_process' in locals() and h_process:
                    VirtualFreeEx(h_process, mem_addr, 0, MEM_RELEASE)
                    kernel32.CloseHandle(h_process)
            except:
                pass
            self.status.setText(f"✗ Injection failed: {e}")
            self.status.setStyleSheet("color: #e74c3c;")
    def run_script(self):
        code = self.scriptBox.toPlainText().strip()
        if not code:
            return
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode='w', encoding='utf-8')
        tf.write(code)
        tf.close()
        self.process.start(sys.executable, [tf.name])
        self.scriptBox.clear()
if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = InjectorGUI()
    gui.show()
    sys.exit(app.exec_())
