# History Parser & Forensic Analysis Tool

A powerful **digital forensic analysis application** built with **Python** and **PyQt5**, designed for system investigators, security researchers, and IT professionals.  
The tool offers **browser history parsing**, **file system scanning**, **metadata extraction**, **file hashing**, **file encryption**, **network & process monitoring**, and more — all within an intuitive GUI.


## Features

### Data Extraction
- **Browser History Parser**: Supports Chrome, Edge, and Firefox (SQLite DB)
- **Notepad Data Recovery**: Retrieves unsaved Notepad and Notepad++ files
- **File System Scanner**: Search directories for specific file extensions
- **Metadata Viewer**: Extract timestamps, NTFS attributes, and MFT records

### Security & Integrity
- **File Hashing**: MD5, SHA-1, SHA-256
- **AES File Encryption / Decryption** (Fernet)
- **File Compression**: ZIP archive creation

### System Monitoring
- **Network Activity Monitor**: Local/remote connections, status, protocol
- **Process Activity Monitor**: PID, name, memory usage, and state
- **System Event Logs Viewer**: Retrieves latest Windows system event logs

### File Management
- Directory listing with search & export
- Export reports for history, metadata, hashes, and directory contents

## Prerequisites

- Python **3.8+**  
- Windows OS (for certain NTFS and WinAPI features)

## Troubleshooting
Database Locked: Close the browser before loading its history DB.
Module Not Found: Install missing libraries using pip install <library>.
Permission Denied: Run as Administrator:

