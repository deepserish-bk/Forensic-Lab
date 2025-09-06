import os
from PyQt5.QtWidgets import QMessageBox, QTableWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal
import pytsk3
from utils import calculate_hash, format_timestamp

class RecoveryThread(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()

    def __init__(self, image_path, output_dir, table_widget, filters=None):
        super().__init__()
        self.image_path = image_path
        self.output_dir = output_dir
        self.table_widget = table_widget
        self.filters = filters or []

    def run(self):
        try:
            img = pytsk3.Img_Info(self.image_path)
            fs = pytsk3.FS_Info(img)
            root_dir = fs.open_dir(path="/")
            self.process_directory(root_dir, "/")
            self.log_signal.emit("[+] Recovery completed.")
            self.finished_signal.emit()
        except Exception as e:
            self.log_signal.emit(f"[!] Recovery failed: {str(e)}")
            QMessageBox.critical(None, "Error", str(e))

    def process_directory(self, directory, parent_path="/"):
        for entry in directory:
            if not hasattr(entry,"info") or not entry.info.name:
                continue
            try:
                name = entry.info.name.name.decode("utf-8","ignore")
            except:
                name = "unknown"
            if name in [".",".."]:
                continue
            fpath = os.path.join(parent_path,name)

            # Recurse into directories
            if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    subdir = entry.as_directory()
                    self.process_directory(subdir, fpath)
                except Exception as e:
                    self.log_signal.emit(f"[!] Cannot enter directory {fpath}: {e}")

            # Recover deleted files
            if entry.info.meta and entry.info.meta.flags == pytsk3.TSK_FS_META_FLAG_UNALLOC:
                if self.filters and not any(name.lower().endswith(ext) for ext in self.filters):
                    continue
                try:
                    file_obj = entry.as_file()
                    output_file = os.path.join(self.output_dir, name)
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                    size = file_obj.info.meta.size
                    offset = 0
                    chunk_size = 1024*1024  # 1 MB

                    with open(output_file,"wb") as out:
                        while offset < size:
                            to_read = min(chunk_size, size - offset)
                            try:
                                data = file_obj.read_random(offset, to_read)
                                if not data:
                                    offset += to_read  # skip unreadable
                                    continue
                                out.write(data)
                                offset += len(data)
                            except IOError as e:
                                # fallback: skip unreadable block
                                self.log_signal.emit(f"[!] Read error at offset {offset} for {fpath}: {e}")
                                offset += to_read

                    file_hash = calculate_hash(output_file)
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
        self.table_widget.setItem(row,0,QTableWidgetItem(name))
        self.table_widget.setItem(row,1,QTableWidgetItem(path))
        self.table_widget.setItem(row,2,QTableWidgetItem(str(size)))
        self.table_widget.setItem(row,3,QTableWidgetItem(hash_val))
        self.table_widget.setItem(row,4,QTableWidgetItem(format_timestamp(ctime)))
        self.table_widget.setItem(row,5,QTableWidgetItem(format_timestamp(mtime)))
        self.table_widget.setItem(row,6,QTableWidgetItem(format_timestamp(atime)))
