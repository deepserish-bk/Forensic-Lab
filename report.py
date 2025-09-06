import csv, json
from PyQt5.QtWidgets import QMessageBox

def export_csv(table_widget, path):
    try:
        with open(path,"w",newline="",encoding="utf-8") as f:
            writer = csv.writer(f)
            headers=[table_widget.horizontalHeaderItem(i).text() for i in range(table_widget.columnCount())]
            writer.writerow(headers)
            for row in range(table_widget.rowCount()):
                writer.writerow([table_widget.item(row,col).text() for col in range(table_widget.columnCount())])
        QMessageBox.information(None,"Success",f"CSV report saved at {path}")
    except Exception as e:
        QMessageBox.critical(None,"Error",str(e))

def export_json(table_widget, path):
    try:
        data=[]
        for row in range(table_widget.rowCount()):
            row_data={table_widget.horizontalHeaderItem(col).text():table_widget.item(row,col).text()
                      for col in range(table_widget.columnCount())}
            data.append(row_data)
        with open(path,"w",encoding="utf-8") as f:
            json.dump(data,f,indent=4)
        QMessageBox.information(None,"Success",f"JSON report saved at {path}")
    except Exception as e:
        QMessageBox.critical(None,"Error",str(e))
