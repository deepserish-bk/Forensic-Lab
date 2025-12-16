"""
Hash Verification Module
Provides functions for calculating and verifying file hashes.
"""

import os
import glob
import hashlib
from PySide6.QtWidgets import QTableWidgetItem

def calculate_file_hash(file_path, algorithm="sha256"):
    """Calculate hash of a file"""
    hash_func = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def compute_hashes_for_folder(folder_path, table_widget, algorithms=None):
    """
    Compute hashes for all files in a folder and populate table.
    
    Args:
        folder_path: Path to folder containing files
        table_widget: QTableWidget to populate with results
        algorithms: List of algorithms to compute (default: ['sha256', 'md5'])
    """
    if not folder_path or not os.path.exists(folder_path):
        return
    
    if algorithms is None:
        algorithms = ['sha256', 'md5']
    
    table_widget.setRowCount(0)
    files = glob.glob(os.path.join(folder_path, "*"))
    
    for file_path in files:
        if os.path.isfile(file_path):
            row = table_widget.rowCount()
            table_widget.insertRow(row)
            
            # File name
            table_widget.setItem(row, 0, QTableWidgetItem(os.path.basename(file_path)))
            
            # Hashes for each algorithm
            for col, algo in enumerate(algorithms, start=1):
                try:
                    hash_value = calculate_file_hash(file_path, algo)
                    table_widget.setItem(row, col, QTableWidgetItem(hash_value))
                except Exception as e:
                    table_widget.setItem(row, col, QTableWidgetItem(f"Error: {str(e)}"))
