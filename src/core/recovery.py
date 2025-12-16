import os
import sys
from PySide6.QtWidgets import QMessageBox, QTableWidgetItem
from PySide6.QtCore import QThread, Signal
import pytsk3

# Import from utils
from utils.helpers import calculate_hash, format_timestamp

class RecoveryThread(QThread):
    log_signal = Signal(str)
    progress_signal = Signal(int)
    finished_signal = Signal()

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
                import subprocess
                subprocess.run(["sudo","mv", temp_file, output_file])
                subprocess.run(["sudo","chmod","644", output_file])

            # Hash verification
            file_hash = ""
            if self.hash_verify:
                try:
                    file_hash = calculate_hash(output_file, "sha256")
                except:
                    file_hash = "Failed"
            else:
                file_hash = calculate_hash(output_file, "sha256")

            ctime = getattr(entry.info.meta,'crtime',None)
            mtime = getattr(entry.info.meta,'mtime',None)
            atime = getattr(entry.info.meta,'atime',None)
            self.log_signal.emit(f"[+] Recovered (partial if errors): {fpath} -> {output_file}")
            self.add_to_table(name, output_file, size, file_hash, ctime, mtime, atime)
        except Exception as e:
            self.log_signal.emit(f"[!] Error recovering {fpath}: {e}")

    def add_to_table(self, name, path, size, hash_val, ctime, mtime, atime):
        row = self.table_widget.rowCount()
        self.table_widget.insertRow(row)
        self.table_widget.setItem(row, 0, QTableWidgetItem(name))
        self.table_widget.setItem(row, 1, QTableWidgetItem(path))
        self.table_widget.setItem(row, 2, QTableWidgetItem(str(size)))
        self.table_widget.setItem(row, 3, QTableWidgetItem(hash_val))
        self.table_widget.setItem(row, 4, QTableWidgetItem(format_timestamp(ctime)))
        self.table_widget.setItem(row, 5, QTableWidgetItem(format_timestamp(mtime)))
        self.table_widget.setItem(row, 6, QTableWidgetItem(format_timestamp(atime)))
