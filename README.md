# Forensic Lab - Digital Forensics Tool

## Table of Contents
1. Overview
2. Features  
3. Installation
4. Usage
5. Project Structure
6. Technical Details
7. License

## 1. Overview

Forensic Lab is a Python application for recovering deleted files from disk images. 
It provides a GUI interface for forensic investigations, data recovery, and 
digital evidence collection.

The tool supports common forensic image formats and focuses on maintaining 
evidence integrity through hash verification and proper handling of recovered files.

## 2. Features

- Supports disk images: .dd, .img, .E01, .dmg
- Two recovery modes: Deleted Only and All Files
- Filter by file extension (e.g., jpg, png, docx)
- Hash calculation: MD5, SHA1, SHA256
- Evidence packaging to DMG (macOS only)
- Real-time progress logging
- Export results to CSV/JSON
- File preview functionality
- Automatic permission handling with sudo fallback

## 3. Installation

Requirements: Python 3.9+

```bash
git clone https://github.com/deepserish-bk/Forensic-Lab.git
cd Forensic-Lab
```
# Create virtual environment (recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# On Windows: venv\Scripts\activate
```
pip install -r requirements.txt
Dependencies in requirements.txt:
PySide6 (GUI)
pytsk3 (The Sleuth Kit bindings)
matplotlib (for future features)

4. Usage

Run the application:

```bash
python forensic_gui.py
```
Basic workflow:

Select disk image file (.dd, .img, .E01, .dmg)
Choose output folder for recovered files
Set filters if needed (comma-separated extensions)
Select recovery mode: "Deleted Only" or "All Files"
Click "Start Recovery"
Monitor progress in log area
View results in table, export if needed
Optional: Create DMG from recovered files (macOS only).

5. Project Structure
```bash
forensic-lab/
├── forensic_gui.py          # Main application
├── requirements.txt         # Dependencies
├── README.md               # This file
├── .gitignore              # Git rules
├── LICENSE                 # MIT License
└── src/                    # Source code
    ├── core/               # Core modules
    │   ├── recovery.py     # File recovery
    │   ├── hash_verification.py
    │   ├── preview.py      # File preview
    │   ├── report.py       # Report export
    │   └── timeline.py     # Timeline
    └── utils/              # Utilities
        └── helpers.py      # Helper functions
```
forensic_gui.py: Main GUI and application logic
src/core/recovery.py: File recovery using pytsk3
src/core/report.py: CSV/JSON export functions
src/utils/helpers.py: Hash calculation and formatting

6. Technical Details

Built with PySide6 for the GUI
Uses pytsk3 (The Sleuth Kit) for file system access
Threaded architecture: separate threads for recovery and GUI
Handles permission errors with sudo fallback
Cross-platform: macOS (full features), Linux (recovery only)
Modular design for easy extension
7. License

MIT License. See LICENSE file for details.

Copyright 2024 deepserish-bk