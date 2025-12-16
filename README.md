# Forensic Lab

A professional digital forensics file recovery tool with GUI interface, built with Python and PySide6.

## ✨ Features
- **Disk Image Support** – Works with raw images (.dd, .img), DMG, and EWF (.E01) forensic formats
- **Deleted File Recovery** – Two recovery modes: All Files & Deleted Only
- **Hash Verification** – Optional MD5/SHA1/SHA256 calculation for evidence integrity
- **Evidence Packaging** – Automatically creates DMG disk images from recovered files
- **File Filtering** – Recover specific file types by extension
- **Permission Handling** – Automatic sudo escalation when needed
- **Investigator-Friendly GUI** – Progress bars, real-time logs, recovery table

## 🖥️ Tech Stack
- Python 3.9+
- PySide6 (GUI framework)
- pytsk3 (The Sleuth Kit - file system parsing)
- hashlib (hash generation)
- Cross-platform (macOS focus, portable to Linux)

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/deepserish-bk/Forensic-Lab.git
cd Forensic-Lab

# Install dependencies
pip install -r requirements.txt
🚀 Usage

bash
# Run the application
python forensic_gui.py
Typical Workflow:

Select a disk image (.dd, .img, .E01, .dmg)
Choose an output folder for recovered files
Apply optional filters (file extensions)
Select recovery mode (All Files or Deleted Only)
Click "Start Recovery" – progress and logs update in real time
(Optional) Package recovered files into a DMG
Review recovered files, hashes, and timestamps in results table
🏗️ Project Structure

text
forensic-lab/
├── forensic_gui.py          # Main application entry point
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── .gitignore              # Git ignore rules
└── src/                    # Source code modules
    ├── core/               # Core functionality
    │   ├── recovery.py     # File recovery logic
    │   ├── hash_verification.py
    │   ├── preview.py      # File preview
    │   ├── report.py       # Export reports
    │   └── timeline.py     # Timeline analysis
    └── utils/              # Utilities
        └── helpers.py      # Helper functions
🚨 Use Cases

Digital Forensics – Extract deleted evidence from seized drives
Incident Response – Recover malicious files for malware analysis
Data Recovery – Restore deleted files from damaged media
Research & Training – Teach forensic investigation techniques
📄 License

MIT License - see LICENSE file for details

🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
