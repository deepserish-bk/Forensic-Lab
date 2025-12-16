"""
File Preview Module
Provides functionality to preview file contents in various formats.
"""

import os
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QMessageBox

def preview_file(file_path, parent=None):
    """
    Open a preview window for a file.
    
    Args:
        file_path: Path to file to preview
        parent: Parent widget (optional)
    """
    try:
        # Create preview window
        preview_window = QWidget(parent)
        preview_window.setWindowTitle(f"Preview: {os.path.basename(file_path)}")
        preview_window.resize(800, 600)
        
        # Create layout and text edit
        layout = QVBoxLayout()
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFontFamily("Monospace")
        
        # Read file content
        try:
            with open(file_path, "rb") as f:
                content = f.read(32768)  # Read up to 32KB for preview
                
                # Try to decode as text
                try:
                    # Try UTF-8 first
                    text_content = content.decode("utf-8")
                    text_edit.setText(text_content)
                    text_edit.append(f"\n\n--- Preview truncated to {len(content)} bytes ---")
                except UnicodeDecodeError:
                    # If not UTF-8, show hex view
                    hex_content = content.hex()
                    # Format hex for readability (16 bytes per line)
                    formatted_hex = ""
                    for i in range(0, min(len(hex_content), 1024), 32):
                        hex_line = hex_content[i:i+32]
                        formatted_hex += ' '.join(hex_line[j:j+2] for j in range(0, len(hex_line), 2)) + '\n'
                    text_edit.setText(f"Binary file - Hex view:\n\n{formatted_hex}")
                    if len(content) > 1024:
                        text_edit.append(f"\n--- Preview truncated to {len(content)} bytes ---")
                        
        except Exception as read_error:
            text_edit.setText(f"Error reading file:\n{str(read_error)}")
        
        layout.addWidget(text_edit)
        preview_window.setLayout(layout)
        
        # Show window
        preview_window.show()
        return preview_window
        
    except Exception as e:
        QMessageBox.critical(parent, "Preview Error", 
                            f"Cannot preview file:\n{str(e)}")
        return None
