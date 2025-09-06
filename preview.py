import os
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QMessageBox

def preview_file(path):
    try:
        preview_win = QWidget()
        preview_win.setWindowTitle(f"Preview: {os.path.basename(path)}")
        layout = QVBoxLayout()
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        with open(path,"rb") as f:
            content = f.read(10240)
        try:
            text_edit.setText(content.decode("utf-8"))
        except:
            text_edit.setText(content.hex())
        layout.addWidget(text_edit)
        preview_win.setLayout(layout)
        preview_win.resize(600,400)
        preview_win.show()
    except Exception as e:
        QMessageBox.critical(None,"Preview Error",str(e))
