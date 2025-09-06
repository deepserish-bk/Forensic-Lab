import os, glob
from PyQt5.QtWidgets import QTableWidgetItem
from utils import calculate_hash

def compute_hashes(folder, table_widget, sha256=True, md5=True):
    if not folder or not os.path.exists(folder):
        return
    table_widget.setRowCount(0)
    files=glob.glob(os.path.join(folder,"*"))
    for f in files:
        if os.path.isfile(f):
            row=table_widget.rowCount()
            table_widget.insertRow(row)
            table_widget.setItem(row,0,QTableWidgetItem(os.path.basename(f)))
            sha256_val = calculate_hash(f,"sha256") if sha256 else ""
            md5_val = calculate_hash(f,"md5") if md5 else ""
            table_widget.setItem(row,1,QTableWidgetItem(sha256_val))
            table_widget.setItem(row,2,QTableWidgetItem(md5_val))
