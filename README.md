✨ Features
    Disk Image Support – Works with raw images (.dd, .img), DMG, and EWF (.E01) forensic formats.
    Deleted File Recovery – Two recovery modes:
      All Files: extract all accessible files.
      Deleted Only: extract only unallocated (deleted) files.
    Safe File Handling – Intelligent .as_file() handling to avoid errors with different entry types.
    Permission Handling
      Automatic restart with sudo when raw disk access is required.
      PermissionError fallback: writes files via /tmp with elevated permissions if direct write fails.
    Filters – Recover specific file types by extension (e.g., jpg,png,docx).
    Hash Verification – Optional MD5/SHA1/SHA256 calculation for each file to ensure evidence integrity.
    Evidence Packaging – Automatically creates DMG disk images from recovered files, ensuring forensic soundness.
    Investigator-Friendly GUI
      File path input with browse dialogs
      Recovery table showing file name, hash, timestamps
      Progress bars for both recovery and DMG creation
      Real-time logs of all operations
Start/Stop buttons for long operations
🖥️ Tech Stack
    Python 3
    PyQt5 – GUI framework
    pytsk3 (The Sleuth Kit) – File system parsing and recovery
    hashlib – Hash generation (MD5, SHA1, SHA256)
    subprocess – For sudo escalation & DMG creation (hdiutil)
    Cross-platform (macOS focus, but portable to Linux with DMG disabled)
📂 Typical Workflow
    Select a disk image (.dd, .img, .E01, .dmg).
    Choose an output folder for recovered files.
    Apply optional filters (file extensions).
    Select recovery mode (All Files or Deleted Only).
    Click Start Recovery – progress and logs update in real time.
    (Optional) Package recovered files into a DMG.
    Review recovered files, hashes, and timestamps in the results table.
🚨 Use Cases
    Digital Forensics – Extract deleted evidence from seized drives.
    Incident Response – Recover malicious files for malware analysis.
    Data Recovery – Restore deleted files from damaged media.
    Research & Training – Teach forensic investigation techniques.
