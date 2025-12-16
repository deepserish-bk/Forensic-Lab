"""
Report Generation Module
Provides functions for exporting recovery results to various formats.
"""

import csv
import json
from datetime import datetime
from PySide6.QtWidgets import QMessageBox

def export_to_csv(table_widget, output_path):
    """
    Export table data to CSV file.
    
    Args:
        table_widget: QTableWidget containing data
        output_path: Path where CSV will be saved
    """
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            
            # Write headers
            headers = []
            for col in range(table_widget.columnCount()):
                header_item = table_widget.horizontalHeaderItem(col)
                if header_item:
                    headers.append(header_item.text())
                else:
                    headers.append(f"Column_{col}")
            writer.writerow(headers)
            
            # Write data rows
            for row in range(table_widget.rowCount()):
                row_data = []
                for col in range(table_widget.columnCount()):
                    item = table_widget.item(row, col)
                    row_data.append(item.text() if item else "")
                writer.writerow(row_data)
        
        QMessageBox.information(None, "Export Successful", 
                               f"CSV report saved to:\n{output_path}")
        return True
        
    except Exception as e:
        QMessageBox.critical(None, "Export Error", 
                            f"Failed to save CSV:\n{str(e)}")
        return False

def export_to_json(table_widget, output_path):
    """
    Export table data to JSON file.
    
    Args:
        table_widget: QTableWidget containing data
        output_path: Path where JSON will be saved
    """
    try:
        data = {
            "export_date": datetime.now().isoformat(),
            "total_rows": table_widget.rowCount(),
            "columns": [],
            "rows": []
        }
        
        # Get column headers
        for col in range(table_widget.columnCount()):
            header_item = table_widget.horizontalHeaderItem(col)
            data["columns"].append(header_item.text() if header_item else f"Column_{col}")
        
        # Get row data
        for row in range(table_widget.rowCount()):
            row_data = {}
            for col in range(table_widget.columnCount()):
                header = data["columns"][col]
                item = table_widget.item(row, col)
                row_data[header] = item.text() if item else ""
            data["rows"].append(row_data)
        
        with open(output_path, "w", encoding="utf-8") as jsonfile:
            json.dump(data, jsonfile, indent=2, ensure_ascii=False)
        
        QMessageBox.information(None, "Export Successful",
                               f"JSON report saved to:\n{output_path}")
        return True
        
    except Exception as e:
        QMessageBox.critical(None, "Export Error",
                            f"Failed to save JSON:\n{str(e)}")
        return False
