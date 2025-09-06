import sys
import os
import hashlib
import subprocess

# ------------------ Ensure running as root ------------------
def restart_with_sudo():
    """Restart script with sudo if not run as root"""
    if os.geteuid() != 0:
        print("[*] Not running as root. Restarting with sudo...")
        try:
            subprocess.check_call(["sudo", sys.executable] + sys.argv)
        except subprocess.CalledProcessError:
            print("[!] Failed to restart with sudo. Exiting.")
        sys.exit(0)

restart_with_sudo()

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QProgressBar, QCheckBox, QComboBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import pytsk3
from utils import format_timestamp

# ------------------------ Recovery Thread ------------------------
class RecoveryThread(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()

    def __init__(self, image_path, output_dir, table_widget, filters=None, hash_verify=False, mode="Deleted Only"):
        super().__init__()
        self.image_path = image_path
        self.output_dir = output_dir
        self.table_widget = table_widget
        self.filters = filters or []
        self.hash_verify = hash_verify
        self.mode = mode
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        try:
            img = pytsk3.Img_Info(self.image_path)
            fs = pytsk3.FS_Info(img)
            root_dir = fs.open_dir(path="/")
            self.file_list = []
            self.collect_files(root_dir, "/")
            total_files = len(self.file_list)
            for idx, entry in enumerate(self.file_list):
                if self._stop_requested:
                    self.log_signal.emit("[*] Recovery stopped by user.")
                    break
                self.recover_file(entry)
                progress = int(((idx + 1) / total_files) * 100)
                self.progress_signal.emit(progress)
            if not self._stop_requested:
                self.log_signal.emit("[+] Recovery complete.")
        except Exception as e:
            self.log_signal.emit(f"[!] Recovery failed: {str(e)}")
        finally:
            self.finished_signal.emit()

    def collect_files(self, directory, parent_path="/"):
        for entry in directory:
            if self._stop_requested:
                return
            if not hasattr(entry,"info") or not entry.info.name:
                continue
            try:
                name = entry.info.name.name.decode("utf-8","ignore")
            except:
                name = "unknown"
            if name in [".",".."]:
                continue
            fpath = os.path.join(parent_path, name)

            # Recurse into directories
            if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    subdir = entry.as_directory()
                    self.collect_files(subdir, fpath)
                except:
                    pass

            # Decide if file should be included
            if entry.info.meta:
                if self.filters and not any(name.lower().endswith(ext) for ext in self.filters):
                    continue
                # Bitwise check for Deleted Only mode
                if self.mode == "Deleted Only" and not (entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC):
                    continue
                self.file_list.append((entry, fpath))

    def recover_file(self, entry_tuple):
        entry, fpath = entry_tuple
        name = entry.info.name.name.decode("utf-8","ignore")
        output_file = os.path.join(self.output_dir, name)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        size = entry.info.meta.size
        offset = 0
        chunk_size = 1024*1024

        try:
            # Safe .as_file() handling
            if isinstance(entry, pytsk3.File):
                file_obj = entry
            else:
                file_obj = entry.as_file()

            try:
                with open(output_file,"wb") as out:
                    while offset < size:
                        if self._stop_requested:
                            return
                        to_read = min(chunk_size, size - offset)
                        try:
                            data = file_obj.read_random(offset, to_read)
                            if not data:
                                offset += to_read
                                continue
                            out.write(data)
                            offset += len(data)
                        except IOError as e:
                            self.log_signal.emit(f"[!] Read error at offset {offset} for {fpath}: {e}")
                            offset += to_read
            except PermissionError:
                # Fallback to sudo write
                temp_file = "/tmp/temp_recover_file"
                with open(temp_file,"wb") as tmp:
                    while offset < size:
                        if self._stop_requested:
                            return
                        to_read = min(chunk_size, size - offset)
                        try:
                            data = file_obj.read_random(offset, to_read)
                            if not data:
                                offset += to_read
                                continue
                            tmp.write(data)
                            offset += len(data)
                        except IOError as e:
                            self.log_signal.emit(f"[!] Read error at offset {offset} for {fpath}: {e}")
                            offset += to_read
                subprocess.run(["sudo","mv", temp_file, output_file])
                subprocess.run(["sudo","chmod","644", output_file])

            # Hash verification
            file_hash = ""
            if self.hash_verify:
                try:
                    file_hash = self.calculate_hash(output_file)
                except:
                    file_hash = "Failed"
            else:
                file_hash = self.calculate_hash(output_file)

            ctime = getattr(entry.info.meta,'crtime',None)
            mtime = getattr(entry.info.meta,'mtime',None)
            atime = getattr(entry.info.meta,'atime',None)
            self.log_signal.emit(f"[+] Recovered (partial if errors): {fpath} -> {output_file}")
            self.add_to_table(name, output_file, size, file_hash, ctime, mtime, atime)
        except Exception as e:
            self.log_signal.emit(f"[!] Error recovering {fpath}: {e}")

    def add_to_table(self,name,path,size,hash_val,ctime,mtime,atime):
        row = self.table_widget.rowCount()
        self.table_widget.insertRow(row)
        self.table_widget.setItem(row,0,QTableWidgetItem(name))
        self.table_widget.setItem(row,1,QTableWidgetItem(path))
        self.table_widget.setItem(row,2,QTableWidgetItem(str(size)))
        self.table_widget.setItem(row,3,QTableWidgetItem(hash_val))
        self.table_widget.setItem(row,4,QTableWidgetItem(format_timestamp(ctime)))
        self.table_widget.setItem(row,5,QTableWidgetItem(format_timestamp(mtime)))
        self.table_widget.setItem(row,6,QTableWidgetItem(format_timestamp(atime)))

    @staticmethod
    def calculate_hash(file_path):
        sha256 = hashlib.sha256()
        with open(file_path,"rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                sha256.update(block)
        return sha256.hexdigest()

# ------------------------ DMG Thread ------------------------
class DMGThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, source_dir, dmg_path):
        super().__init__()
        self.source_dir = source_dir
        self.dmg_path = dmg_path
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        try:
            cmd = [
                "sudo", "hdiutil", "create", "-volname", "Recovered",
                "-srcfolder", self.source_dir,
                "-ov", "-format", "UDZO", self.dmg_path
            ]
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

# ------------------------ GUI ------------------------
class ForensicsGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Forensics Lab")
        self.resize(1000,600)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Source
        hbox1 = QHBoxLayout()
        self.src_input = QLineEdit()
        btn_src = QPushButton("Select Disk Image")
        btn_src.clicked.connect(self.select_source)
        hbox1.addWidget(QLabel("Disk Image:"))
        hbox1.addWidget(self.src_input)
        hbox1.addWidget(btn_src)
        layout.addLayout(hbox1)

        # Output
        hbox2 = QHBoxLayout()
        self.dest_input = QLineEdit()
        btn_dest = QPushButton("Select Output Folder")
        btn_dest.clicked.connect(self.select_dest)
        hbox2.addWidget(QLabel("Output Folder:"))
        hbox2.addWidget(self.dest_input)
        hbox2.addWidget(btn_dest)
        layout.addLayout(hbox2)

        # Filters
        hbox3 = QHBoxLayout()
        self.filter_input = QLineEdit()
        hbox3.addWidget(QLabel("File Extensions Filter (comma separated):"))
        hbox3.addWidget(self.filter_input)
        layout.addLayout(hbox3)

        # Recovery mode
        hbox_mode = QHBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Deleted Only","All Files"])
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
        hbox5.addWidget(QLabel("DMG Path:"))
        hbox5.addWidget(self.dmg_input)
        hbox5.addWidget(btn_dmg)
        hbox5.addWidget(self.btn_dmg_create)
        hbox5.addWidget(self.btn_stop_dmg)
        layout.addLayout(hbox5)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Log
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        # Table
        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(7)
        self.table_widget.setHorizontalHeaderLabels(
            ["Name","Path","Size","Hash","Created","Modified","Accessed"]
        )
        layout.addWidget(self.table_widget)

        self.setLayout(layout)

    # ------------------------ GUI Helpers ------------------------
    def select_source(self):
        file,_ = QFileDialog.getOpenFileName(self,"Select Disk Image","","Disk Images (*.dd *.img *.E01 *.dmg)")
        if file:
            self.src_input.setText(file)

    def select_dest(self):
        folder = QFileDialog.getExistingDirectory(self,"Select Output Folder")
        if folder:
            self.dest_input.setText(folder)

    def select_dmg(self):
        file,_ = QFileDialog.getSaveFileName(self,"Save DMG As","","Disk Image (*.dmg)")
        if file:
            self.dmg_input.setText(file)

    # ------------------------ Recovery ------------------------
    def start_recovery(self):
        image_path = self.src_input.text()
        output_dir = self.dest_input.text()
        filters = [ext.strip() for ext in self.filter_input.text().split(",") if ext.strip()]
        mode = self.mode_combo.currentText()
        if not image_path or not output_dir:
            self.log_area.append("[!] Please select both disk image and output folder.")
            return
        self.btn_recover.setEnabled(False)
        self.progress_bar.setValue(0)
        self.log_area.append("[*] Starting recovery...")

        self.thread = RecoveryThread(image_path, output_dir, self.table_widget, filters, self.hash_check.isChecked(), mode=mode)
        self.thread.log_signal.connect(self.log_area.append)
        self.thread.progress_signal.connect(self.progress_bar.setValue)
        self.thread.finished_signal.connect(self.recovery_finished)
        self.thread.start()

    def stop_recovery(self):
        if hasattr(self, 'thread') and self.thread.isRunning():
            self.thread.stop()
            self.log_area.append("[*] Stop requested for recovery...")

    def recovery_finished(self):
        self.progress_bar.setValue(100)
        self.log_area.append("[*] Recovery finished.")
        self.btn_recover.setEnabled(True)

    # ------------------------ DMG ------------------------
    def start_dmg(self):
        source = self.dest_input.text()
        dmg_path = self.dmg_input.text()
        if not source or not dmg_path:
            self.log_area.append("[!] Please select both source folder and DMG path.")
            return
        self.btn_dmg_create.setEnabled(False)
        self.log_area.append("[*] Starting DMG creation...")

        self.dmg_thread = DMGThread(source, dmg_path)
        self.dmg_thread.log_signal.connect(self.log_area.append)
        self.dmg_thread.finished_signal.connect(self.dmg_finished)
        self.dmg_thread.start()

    def stop_dmg(self):
        if hasattr(self, 'dmg_thread') and self.dmg_thread.isRunning():
            self.dmg_thread.stop()
            self.log_area.append("[*] Stop requested for DMG creation...")

    def dmg_finished(self):
        self.log_area.append("[*] DMG creation finished.")
        self.btn_dmg_create.setEnabled(True)


# ------------------------ Run App ------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = ForensicsGUI()
    gui.show()
    sys.exit(app.exec_())
