#!/usr/bin/env python3
"""
Forensic Lab - Digital Forensics File Recovery Tool
Main application entry point.
"""

import sys
import os
import hashlib
import subprocess
from datetime import datetime

# Add src directory to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(project_root, 'src'))

# Import Qt
try:
    from PySide6.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
        QFileDialog, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
        QProgressBar, QCheckBox, QComboBox, QMessageBox
    )
    from PySide6.QtCore import Qt, QThread, Signal
    USE_PYSIDE6 = True
except ImportError:
    print("[!] PySide6 not found. Please install: pip install PySide6")
    sys.exit(1)

# Import local modules
from core.recovery import RecoveryThread
from utils.helpers import format_timestamp

# ------------------ Permission Check ------------------
def check_permissions():
    """Warn if not running as root (for disk access)"""
    if os.name == 'posix' and os.geteuid() != 0:
        print("[!] Warning: Not running as root.")
        print("[*] Some disk operations may require elevated privileges.")
        return False
    return True

# ------------------------ DMG Thread ------------------------
class DMGThread(QThread):
    log_signal = Signal(str)
    finished_signal = Signal()

    def __init__(self, source_dir, dmg_path):
        super().__init__()
        self.source_dir = source_dir
        self.dmg_path = dmg_path
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        try:
            if os.access(os.path.dirname(self.dmg_path) or '.', os.W_OK):
                cmd = ["hdiutil", "create", "-volname", "Recovered",
                       "-srcfolder", self.source_dir, "-ov", "-format", "UDZO", self.dmg_path]
                use_sudo = False
            else:
                cmd = ["sudo", "hdiutil", "create", "-volname", "Recovered",
                       "-srcfolder", self.source_dir, "-ov", "-format", "UDZO", self.dmg_path]
                use_sudo = True
                
            self.log_signal.emit(f"[*] Creating DMG (using sudo: {use_sudo})...")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:
                if self._stop_requested:
                    process.terminate()
                    self.log_signal.emit("[*] DMG creation stopped by user.")
                    break
                output = process.stdout.readline()
                if output:
                    self.log_signal.emit(output.decode().strip())
                elif process.poll() is not None:
                    break
                    
            _, err = process.communicate()
            if err and not self._stop_requested:
                self.log_signal.emit(err.decode())
            if not self._stop_requested:
                self.log_signal.emit("[+] DMG creation completed.")
                
        except Exception as e:
            self.log_signal.emit(f"[!] DMG creation failed: {str(e)}")
        finally:
            self.finished_signal.emit()

# ------------------------ GUI Class ------------------------
class ForensicsGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Forensics Lab v1.0")
        self.resize(1000, 600)
        self.init_ui()
        self.recovery_thread = None
        self.dmg_thread = None

    def init_ui(self):
        layout = QVBoxLayout()

        # Source selection
        hbox1 = QHBoxLayout()
        self.src_input = QLineEdit()
        btn_src = QPushButton("Select Disk Image")
        btn_src.clicked.connect(self.select_source)
        hbox1.addWidget(QLabel("Disk Image:"))
        hbox1.addWidget(self.src_input)
        hbox1.addWidget(btn_src)
        layout.addLayout(hbox1)

        # Output selection
        hbox2 = QHBoxLayout()
        self.dest_input = QLineEdit()
        btn_dest = QPushButton("Select Output Folder")
        btn_dest.clicked.connect(self.select_dest)
        hbox2.addWidget(QLabel("Output Folder:"))
        hbox2.addWidget(self.dest_input)
        hbox2.addWidget(btn_dest)
        layout.addLayout(hbox2)

        # File filters
        hbox3 = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("jpg,png,docx,pdf")
        hbox3.addWidget(QLabel("File Extensions Filter (comma separated):"))
        hbox3.addWidget(self.filter_input)
        layout.addLayout(hbox3)

        # Recovery mode
        hbox_mode = QHBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Deleted Only", "All Files"])
        hbox_mode.addWidget(QLabel("Recovery Mode:"))
        hbox_mode.addWidget(self.mode_combo)
        layout.addLayout(hbox_mode)

        # Hash verification
        self.hash_check = QCheckBox("Verify SHA256 Hash")
        layout.addWidget(self.hash_check)

        # Recovery buttons
        hbox4 = QHBoxLayout()
        self.btn_recover = QPushButton("Start Recovery")
        self.btn_recover.clicked.connect(self.start_recovery)
        self.btn_stop_recovery = QPushButton("Stop Recovery")
        self.btn_stop_recovery.clicked.connect(self.stop_recovery)
        self.btn_stop_recovery.setEnabled(False)
        hbox4.addWidget(self.btn_recover)
        hbox4.addWidget(self.btn_stop_recovery)
        layout.addLayout(hbox4)

        # DMG creation
        hbox5 = QHBoxLayout()
        self.dmg_input = QLineEdit()
        btn_dmg = QPushButton("Select DMG Destination")
        btn_dmg.clicked.connect(self.select_dmg)
        self.btn_dmg_create = QPushButton("Create DMG")
        self.btn_dmg_create.clicked.connect(self.start_dmg)
        self.btn_stop_dmg = QPushButton("Stop DMG")
        self.btn_stop_dmg.clicked.connect(self.stop_dmg)
        self.btn_stop_dmg.setEnabled(False)
        hbox5.addWidget(QLabel("DMG Path:"))
        hbox5.addWidget(self.dmg_input)
        hbox5.addWidget(btn_dmg)
        hbox5.addWidget(self.btn_dmg_create)
        hbox5.addWidget(self.btn_stop_dmg)
        layout.addLayout(hbox5)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        # Results table
        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(7)
        self.table_widget.setHorizontalHeaderLabels(
            ["Name", "Path", "Size", "Hash", "Created", "Modified", "Accessed"]
        )
        self.table_widget.setColumnWidth(0, 150)
        self.table_widget.setColumnWidth(1, 250)
        self.table_widget.setColumnWidth(2, 80)
        layout.addWidget(self.table_widget)

        self.setLayout(layout)

    # GUI helper methods (select_source, select_dest, select_dmg)
    def select_source(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Select Disk Image", "",
            "Disk Images (*.dd *.img *.E01 *.dmg);;All Files (*)"
        )
        if file:
            self.src_input.setText(file)

    def select_dest(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.dest_input.setText(folder)

    def select_dmg(self):
        file, _ = QFileDialog.getSaveFileName(
            self, "Save DMG As", "",
            "Disk Image (*.dmg);;All Files (*)"
        )
        if file:
            if not file.endswith('.dmg'):
                file += '.dmg'
            self.dmg_input.setText(file)

    # Recovery methods (start_recovery, stop_recovery, recovery_finished)
    def start_recovery(self):
        image_path = self.src_input.text()
        output_dir = self.dest_input.text()
        filters = [ext.strip().lower() for ext in self.filter_input.text().split(",") if ext.strip()]
        mode = self.mode_combo.currentText()
        
        if not image_path or not os.path.exists(image_path):
            QMessageBox.warning(self, "Warning", "Please select a valid disk image.")
            return
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output folder.")
            return
            
        os.makedirs(output_dir, exist_ok=True)
        
        self.btn_recover.setEnabled(False)
        self.btn_stop_recovery.setEnabled(True)
        self.progress_bar.setValue(0)
        self.log_area.append(f"[*] Starting recovery from: {image_path}")
        self.log_area.append(f"[*] Output directory: {output_dir}")
        if filters:
            self.log_area.append(f"[*] Filters: {', '.join(filters)}")
        self.log_area.append(f"[*] Mode: {mode}")

        self.recovery_thread = RecoveryThread(
            image_path, output_dir, self.table_widget, 
            filters, self.hash_check.isChecked(), mode
        )
        self.recovery_thread.log_signal.connect(self.log_area.append)
        self.recovery_thread.progress_signal.connect(self.progress_bar.setValue)
        self.recovery_thread.finished_signal.connect(self.recovery_finished)
        self.recovery_thread.start()

    def stop_recovery(self):
        if self.recovery_thread and self.recovery_thread.isRunning():
            self.recovery_thread.stop()
            self.log_area.append("[*] Stop requested for recovery...")

    def recovery_finished(self):
        self.progress_bar.setValue(100)
        self.log_area.append("[*] Recovery finished.")
        self.btn_recover.setEnabled(True)
        self.btn_stop_recovery.setEnabled(False)

    # DMG methods (start_dmg, stop_dmg, dmg_finished)
    def start_dmg(self):
        source = self.dest_input.text()
        dmg_path = self.dmg_input.text()
        
        if not source or not os.path.exists(source):
            QMessageBox.warning(self, "Warning", "Please select a valid source folder.")
            return
        if not dmg_path:
            QMessageBox.warning(self, "Warning", "Please select a DMG destination.")
            return
            
        self.btn_dmg_create.setEnabled(False)
        self.btn_stop_dmg.setEnabled(True)
        self.log_area.append("[*] Starting DMG creation...")

        self.dmg_thread = DMGThread(source, dmg_path)
        self.dmg_thread.log_signal.connect(self.log_area.append)
        self.dmg_thread.finished_signal.connect(self.dmg_finished)
        self.dmg_thread.start()

    def stop_dmg(self):
        if self.dmg_thread and self.dmg_thread.isRunning():
            self.dmg_thread.stop()
            self.log_area.append("[*] Stop requested for DMG creation...")

    def dmg_finished(self):
        self.log_area.append("[*] DMG creation finished.")
        self.btn_dmg_create.setEnabled(True)
        self.btn_stop_dmg.setEnabled(False)

# ------------------------ Main Entry Point ------------------------
if __name__ == "__main__":
    print("[*] Starting Forensic Lab...")
    check_permissions()
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    gui = ForensicsGUI()
    gui.show()
    
    sys.exit(app.exec())
