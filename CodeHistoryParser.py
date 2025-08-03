from ctypes import wintypes
import sys
import os
import ctypes
import sqlite3
import pytsk3
import datetime
import hashlib
import zipfile
import psutil
import subprocess


from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel,
                             QTableWidget, QTableWidgetItem, QFileDialog, QTextEdit, QTabWidget,
                             QStatusBar, QMessageBox, QHBoxLayout, QLineEdit)
from PyQt5.QtGui import QIcon, QColor, QPalette, QFont
from PyQt5.QtCore import Qt

# Constants for file attributes
FILE_ATTRIBUTE_READONLY = 0x01
FILE_ATTRIBUTE_HIDDEN = 0x02

# Load kernel32.dll
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define GetFileAttributesW function
GetFileAttributes = kernel32.GetFileAttributesW
GetFileAttributes.argtypes = [wintypes.LPCWSTR]
GetFileAttributes.restype = wintypes.DWORD

# Generate an encryption key
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

def get_ntfs_attributes(file_path):
    """Retrieve NTFS file attributes using Windows API accurately."""
    attributes = GetFileAttributes(file_path)
    if attributes == -1:
        raise ctypes.WinError(ctypes.get_last_error())

    metadata = {
        'Read-only': 'True' if (attributes & FILE_ATTRIBUTE_READONLY) != 0 else 'False',
        'Hidden': 'True' if (attributes & FILE_ATTRIBUTE_HIDDEN) != 0 else 'False'
    }
    return metadata

def compute_hash(file_path, hash_type='md5'):
    """Compute file hash for MD5, SHA1, and SHA256."""
    try:
        hash_function = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }[hash_type]
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_function.update(chunk)
        return hash_function.hexdigest()
    except Exception as e:
        return f"Error: {e}"

class HistoryParserTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("History Parser Tool")
        self.setGeometry(100, 100, 1000, 800)
        self.setWindowIcon(QIcon('forensic_icon.png'))

        # Set up color scheme with grey and bluish colors
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#2e3b4e"))  # Grey-blue background
        palette.setColor(QPalette.WindowText, QColor("#dfe6f2"))  # Light grey-blue text
        self.setPalette(palette)

        font = QFont("Arial", 16)
        self.setFont(font)

        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("background-color: #3a4c63; color: #dfe6f2;")
        self.setStatusBar(self.status_bar)

        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("QTabBar::tab { background-color: #3a4c63; color: #dfe6f2; padding: 10px; }")
        self.setCentralWidget(self.tab_widget)

        # Define each tab
        self.browser_history_tab = QWidget()
        self.notepad_data_tab = QWidget()
        self.directory_listing_tab = QWidget()
        self.metadata_tab = QWidget()
        self.hashing_tab = QWidget()
        self.encryption_tab = QWidget()
        self.network_activity_tab = QWidget()
        self.process_activity_tab = QWidget()
        self.file_system_scanner_tab = QWidget()
        self.event_logs_tab = QWidget()

        # Add tabs
        self.tab_widget.addTab(self.browser_history_tab, "Browser History")
        self.tab_widget.addTab(self.notepad_data_tab, "Notepad Data")
        self.tab_widget.addTab(self.directory_listing_tab, "Directory Listing")
        self.tab_widget.addTab(self.metadata_tab, "Metadata Viewer")
        self.tab_widget.addTab(self.hashing_tab, "File Hashing")
        self.tab_widget.addTab(self.encryption_tab, "Encrypt/Decrypt")
        self.tab_widget.addTab(self.network_activity_tab, "Network Activity")
        self.tab_widget.addTab(self.process_activity_tab, "Process Activity")
        self.tab_widget.addTab(self.file_system_scanner_tab, "File System Scanner")
        self.tab_widget.addTab(self.event_logs_tab, "System Event Logs")

        # Initialize each tab layout and functionality
        self.init_browser_history_tab()
        self.init_notepad_data_tab()
        self.init_directory_listing_tab()
        self.init_metadata_tab()
        self.init_hashing_tab()
        self.init_encryption_tab()
        self.init_network_activity_tab()
        self.init_process_activity_tab()
        self.init_file_system_scanner_tab()
        self.init_event_logs_tab()



    def init_browser_history_tab(self):
        layout = QVBoxLayout()
        self.browser_history_table = QTableWidget()
        self.browser_history_table.setColumnCount(4)
        self.browser_history_table.setHorizontalHeaderLabels(['URL', 'Title', 'Visit Count', 'Last Visit Time'])
        self.browser_history_table.setStyleSheet("background-color: #4b6078; color: #dfe6f2; font-size: 12px;")

        self.load_history_button = QPushButton("Load History")
        self.load_history_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px; font: bold 12px;")
        self.load_history_button.clicked.connect(self.load_browser_history)

        self.clear_history_button = QPushButton("Clear History Data")
        self.clear_history_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 8px;")
        self.clear_history_button.clicked.connect(lambda: self.browser_history_table.clearContents())

        self.save_history_button = QPushButton("Save History Report")
        self.save_history_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 8px;")
        self.save_history_button.clicked.connect(self.save_browser_history)

        layout.addWidget(self.load_history_button)
        layout.addWidget(self.clear_history_button)
        layout.addWidget(self.save_history_button)
        layout.addWidget(self.browser_history_table)
        self.browser_history_tab.setLayout(layout)

    def load_browser_history(self):
        db_path = QFileDialog.getOpenFileName(self, 'Select Browser History File')[0]
        if db_path:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
            results = cursor.fetchall()
            self.browser_history_table.setRowCount(len(results))

            for row_index, row_data in enumerate(results):
                for col_index, col_data in enumerate(row_data):
                    if col_index == 3:  # Convert timestamp for display
                        col_data = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=col_data)
                    self.browser_history_table.setItem(row_index, col_index, QTableWidgetItem(str(col_data)))
            conn.close()
            self.status_bar.showMessage("Browser history loaded successfully.", 3000)

    def save_browser_history(self):
        save_path, _ = QFileDialog.getSaveFileName(self, "Save History Report", "", "Text Files (*.txt)")
        if save_path:
            with open(save_path, 'w') as file:
                for row in range(self.browser_history_table.rowCount()):
                    line = "\t".join(self.browser_history_table.item(row, col).text() if self.browser_history_table.item(row, col) else ""
                                     for col in range(self.browser_history_table.columnCount()))
                    file.write(line + "\n")
            self.status_bar.showMessage("Browser history report saved successfully.", 3000)

    def init_notepad_data_tab(self):
        layout = QVBoxLayout()
        self.notepad_text = QTextEdit()
        self.notepad_text.setStyleSheet("background-color: #4b6078; color: #dfe6f2; font-size: 12px;")

        self.load_notepad_data_button = QPushButton("Extract Notepad Data")
        self.load_notepad_data_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.load_notepad_data_button.clicked.connect(self.extract_unsaved_notepad_data)

        self.clear_notepad_data_button = QPushButton("Clear Notepad Data")
        self.clear_notepad_data_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 8px;")
        self.clear_notepad_data_button.clicked.connect(self.notepad_text.clear)

        self.save_notepad_data_button = QPushButton("Save Notepad Report")
        self.save_notepad_data_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 8px;")
        self.save_notepad_data_button.clicked.connect(self.save_notepad_data)

        layout.addWidget(self.load_notepad_data_button)
        layout.addWidget(self.clear_notepad_data_button)
        layout.addWidget(self.save_notepad_data_button)
        layout.addWidget(self.notepad_text)
        self.notepad_data_tab.setLayout(layout)

    def extract_unsaved_notepad_data(self):
        possible_paths = [os.getenv("TEMP"), os.path.expandvars(r"%AppData%\Microsoft\Windows\Notepad"), os.path.expandvars(r"%LocalAppData%\Microsoft\Windows\Notepad")]
        data_found = False
        unsaved_data = ""
        
        for path in possible_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith(('.txt', '.bak')):
                            with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                                file_content = f.read()
                                if file_content.strip():
                                    unsaved_data += f"File: {file}\n" + file_content + "\n---\n"
                                    data_found = True

        notepad_plus_plus_backup_path = os.path.expandvars(r"%AppData%\Notepad++\backup")
        if os.path.exists(notepad_plus_plus_backup_path):
            for file_name in os.listdir(notepad_plus_plus_backup_path):
                file_path = os.path.join(notepad_plus_plus_backup_path, file_name)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read()
                    if file_content.strip():
                        unsaved_data += f"Notepad++ Backup File: {file_name}\n" + file_content + "\n---\n"
                        data_found = True

        if data_found:
            self.notepad_text.setPlainText(unsaved_data)
        else:
            self.notepad_text.setPlainText("No unsaved Notepad or Notepad++ data found.")

    def save_notepad_data(self):
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Notepad Report", "", "Text Files (*.txt)")
        if save_path:
            with open(save_path, 'w') as file:
                file.write(self.notepad_text.toPlainText())
            self.status_bar.showMessage("Notepad data report saved successfully.", 3000)

    def init_directory_listing_tab(self):
        layout = QVBoxLayout()
        self.directory_table = QTableWidget()
        self.directory_table.setColumnCount(2)
        self.directory_table.setHorizontalHeaderLabels(['File Name', 'File Path'])
        self.directory_table.setStyleSheet("background-color: #4b6078; color: #dfe6f2; font-size: 12px;")

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search for files...")
        self.search_input.setStyleSheet("background-color: #2e3b4e; color: #dfe6f2; padding: 8px;")
        self.search_input.textChanged.connect(self.filter_directory_listing)

        self.load_directory_button = QPushButton("Load Directory")
        self.load_directory_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.load_directory_button.clicked.connect(self.load_directory_listing)

        self.clear_directory_button = QPushButton("Clear Directory Listing")
        self.clear_directory_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 8px;")
        self.clear_directory_button.clicked.connect(lambda: self.directory_table.clearContents())

        self.save_directory_button = QPushButton("Save Directory Report")
        self.save_directory_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 8px;")
        self.save_directory_button.clicked.connect(self.save_directory_listing)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.load_directory_button)
        button_layout.addWidget(self.clear_directory_button)
        button_layout.addWidget(self.save_directory_button)

        layout.addWidget(self.search_input)
        layout.addLayout(button_layout)
        layout.addWidget(self.directory_table)
        self.directory_listing_tab.setLayout(layout)

    def filter_directory_listing(self):
        filter_text = self.search_input.text().lower()
        for row in range(self.directory_table.rowCount()):
            file_name = self.directory_table.item(row, 0).text().lower()
            if filter_text in file_name:
                self.directory_table.showRow(row)
            else:
                self.directory_table.hideRow(row)

    def load_directory_listing(self):
        directory = QFileDialog.getExistingDirectory(self, 'Select Directory')
        if not directory:
            return
        self.directory_table.setRowCount(0)
        
        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                row = self.directory_table.rowCount()
                self.directory_table.insertRow(row)
                self.directory_table.setItem(row, 0, QTableWidgetItem(file_name))
                self.directory_table.setItem(row, 1, QTableWidgetItem(file_path))
        self.status_bar.showMessage("Directory listing loaded.", 3000)

    def save_directory_listing(self):
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Directory Report", "", "Text Files (*.txt)")
        if save_path:
            with open(save_path, 'w') as file:
                for row in range(self.directory_table.rowCount()):
                    line = "\t".join(self.directory_table.item(row, col).text() if self.directory_table.item(row, col) else ""
                                     for col in range(self.directory_table.columnCount()))
                    file.write(line + "\n")
            self.status_bar.showMessage("Directory report saved successfully.", 3000)

    def init_metadata_tab(self):
        layout = QVBoxLayout()
        self.metadata_table = QTableWidget()
        self.metadata_table.setColumnCount(10)
        self.metadata_table.setHorizontalHeaderLabels([
            'File Name', 'File Path', 'Size', 'Creation Time', 'Modification Time',
            'Access Time', 'Change Time', 'Attributes', 'MFT Record', 'Alternate Data Streams'
        ])
        self.metadata_table.setStyleSheet("background-color: #4b6078; color: #dfe6f2; font-size: 12px;")
        
        self.load_metadata_button = QPushButton("Load Metadata")
        self.load_metadata_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.load_metadata_button.clicked.connect(self.select_metadata_file)

        self.clear_metadata_button = QPushButton("Clear Metadata")
        self.clear_metadata_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 8px;")
        self.clear_metadata_button.clicked.connect(lambda: self.metadata_table.clearContents())

        self.save_metadata_button = QPushButton("Save Metadata Report")
        self.save_metadata_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 8px;")
        self.save_metadata_button.clicked.connect(self.save_metadata)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.load_metadata_button)
        button_layout.addWidget(self.clear_metadata_button)
        button_layout.addWidget(self.save_metadata_button)

        layout.addLayout(button_layout)
        layout.addWidget(self.metadata_table)
        self.metadata_tab.setLayout(layout)

    def select_metadata_file(self):
        file_path = QFileDialog.getOpenFileName(self, "Select Disk Image for Metadata Analysis")[0]
        if file_path:
            self.display_metadata(file_path)

    def display_metadata(self, file_path):
        try:
            img_info = pytsk3.Img_Info(file_path)

            vol_info = pytsk3.Volume_Info(img_info)
            for part in vol_info:
                try:
                    fs_info = pytsk3.FS_Info(img_info, offset=part.start * 512)
                    root_dir = fs_info.open_dir("/")
                    break
                except Exception:
                    continue

            self.metadata_table.setRowCount(0)
            for entry in root_dir:
                if entry.info.meta is None:
                    continue

                row_position = self.metadata_table.rowCount()
                self.metadata_table.insertRow(row_position)

                file_name = entry.info.name.name.decode('utf-8', errors='ignore') if isinstance(entry.info.name.name, bytes) else entry.info.name.name
                file_path = "/" + file_name
                file_size = entry.info.meta.size
                creation_time = datetime.datetime.fromtimestamp(entry.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S') if entry.info.meta.crtime else "N/A"
                modification_time = datetime.datetime.fromtimestamp(entry.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.info.meta.mtime else "N/A"
                access_time = datetime.datetime.fromtimestamp(entry.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S') if entry.info.meta.atime else "N/A"
                change_time = datetime.datetime.fromtimestamp(entry.info.meta.ctime).strftime('%Y-%m-%d %H:%M:%S') if entry.info.meta.ctime else "N/A"

                try:
                    ntfs_attrs = get_ntfs_attributes(file_name)
                    attributes = f"Read-only: {ntfs_attrs.get('Read-only')}, Hidden: {ntfs_attrs.get('Hidden')}"
                except Exception as e:
                    attributes = f"Error retrieving NTFS attributes: {e}"

                mft_record = entry.info.meta.addr
                alt_stream_count = sum(1 for attr in entry if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA and attr.info.name)

                self.metadata_table.setItem(row_position, 0, QTableWidgetItem(file_name))
                self.metadata_table.setItem(row_position, 1, QTableWidgetItem(file_path))
                self.metadata_table.setItem(row_position, 2, QTableWidgetItem(str(file_size)))
                self.metadata_table.setItem(row_position, 3, QTableWidgetItem(creation_time))
                self.metadata_table.setItem(row_position, 4, QTableWidgetItem(modification_time))
                self.metadata_table.setItem(row_position, 5, QTableWidgetItem(access_time))
                self.metadata_table.setItem(row_position, 6, QTableWidgetItem(change_time))
                self.metadata_table.setItem(row_position, 7, QTableWidgetItem(attributes))
                self.metadata_table.setItem(row_position, 8, QTableWidgetItem(str(mft_record)))
                self.metadata_table.setItem(row_position, 9, QTableWidgetItem(str(alt_stream_count)))
            self.status_bar.showMessage("Metadata loaded successfully.", 3000)

        except Exception as e:
            self.status_bar.showMessage(f"Error reading metadata: {e}", 5000)

    def save_metadata(self):
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Metadata Report", "", "Text Files (*.txt)")
        if save_path:
            with open(save_path, 'w') as file:
                for row in range(self.metadata_table.rowCount()):
                    line = "\t".join(self.metadata_table.item(row, col).text() if self.metadata_table.item(row, col) else ""
                                     for col in range(self.metadata_table.columnCount()))
                    file.write(line + "\n")
            self.status_bar.showMessage("Metadata report saved successfully.", 3000)

    def init_hashing_tab(self):
        layout = QVBoxLayout()

        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Select a file to compute its hash...")
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setStyleSheet("background-color: #2e3b4e; color: #dfe6f2; padding: 8px;")

        self.select_file_button = QPushButton("Select File")
        self.select_file_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.select_file_button.clicked.connect(self.select_file_for_hashing)

        self.md5_label = QLabel("MD5: ")
        self.sha1_label = QLabel("SHA-1: ")
        self.sha256_label = QLabel("SHA-256: ")
        # Darken text color for better visibility
        self.md5_label.setStyleSheet("color: #404040;")
        self.sha1_label.setStyleSheet("color: #404040;")
        self.sha256_label.setStyleSheet("color: #404040;")

        self.compute_hash_button = QPushButton("Compute Hash")
        self.compute_hash_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.compute_hash_button.clicked.connect(self.compute_file_hash)

        self.save_hash_report_button = QPushButton("Save Hash Report")
        self.save_hash_report_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.save_hash_report_button.clicked.connect(self.save_hash_report)

        layout.addWidget(self.file_path_input)
        layout.addWidget(self.select_file_button)
        layout.addWidget(self.md5_label)
        layout.addWidget(self.sha1_label)
        layout.addWidget(self.sha256_label)
        layout.addWidget(self.compute_hash_button)
        layout.addWidget(self.save_hash_report_button)
        
        self.hashing_tab.setLayout(layout)

    def select_file_for_hashing(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File for Hashing")
        if file_path:
            self.file_path_input.setText(file_path)
            self.md5_label.setText("MD5: ")
            self.sha1_label.setText("SHA-1: ")
            self.sha256_label.setText("SHA-256: ")

    def compute_file_hash(self):
        file_path = self.file_path_input.text()
        if not file_path:
            QMessageBox.warning(self, "No File Selected", "Please select a file to hash.")
            return

        self.md5_label.setText(f"MD5: {compute_hash(file_path, 'md5')}")
        self.sha1_label.setText(f"SHA-1: {compute_hash(file_path, 'sha1')}")
        self.sha256_label.setText(f"SHA-256: {compute_hash(file_path, 'sha256')}")
        self.status_bar.showMessage("File hashes computed successfully.", 3000)

    def save_hash_report(self):
        file_path = self.file_path_input.text()
        if not file_path:
            QMessageBox.warning(self, "No File Selected", "Please select a file to save the hash report.")
            return

        save_path, _ = QFileDialog.getSaveFileName(self, "Save Hash Report", "", "Text Files (*.txt)")
        if save_path:
            with open(save_path, 'w') as file:
                file.write(f"File: {file_path}\n")
                file.write(f"MD5: {self.md5_label.text().replace('MD5: ', '')}\n")
                file.write(f"SHA-1: {self.sha1_label.text().replace('SHA-1: ', '')}\n")
                file.write(f"SHA-256: {self.sha256_label.text().replace('SHA-256: ', '')}\n")
            self.status_bar.showMessage("Hash report saved successfully.", 3000)

    def init_encryption_tab(self):
        layout = QVBoxLayout()

        self.encryption_file_input = QLineEdit()
        self.encryption_file_input.setPlaceholderText("Select a file to encrypt or decrypt...")
        self.encryption_file_input.setReadOnly(True)
        self.encryption_file_input.setStyleSheet("background-color: #2e3b4e; color: #dfe6f2; padding: 8px;")

        self.select_encryption_file_button = QPushButton("Select File")
        self.select_encryption_file_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.select_encryption_file_button.clicked.connect(self.select_encryption_file)

        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.encrypt_button.clicked.connect(self.encrypt_file)

        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.decrypt_button.clicked.connect(self.decrypt_file)

        self.compress_button = QPushButton("Compress File")
        self.compress_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        self.compress_button.clicked.connect(self.compress_file)

        layout.addWidget(self.encryption_file_input)
        layout.addWidget(self.select_encryption_file_button)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.compress_button)

        self.encryption_tab.setLayout(layout)

    def select_encryption_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File for Encryption/Decryption")
        if file_path:
            self.encryption_file_input.setText(file_path)

    def encrypt_file(self):
        file_path = self.encryption_file_input.text()
        if not file_path:
            QMessageBox.warning(self, "No File Selected", "Please select a file to encrypt.")
            return

        with open(file_path, 'rb') as file:
            encrypted_data = cipher_suite.encrypt(file.read())
        
        with open(file_path + ".enc", 'wb') as file:
            file.write(encrypted_data)
        
        self.status_bar.showMessage("File encrypted successfully.", 3000)

    def decrypt_file(self):
        file_path = self.encryption_file_input.text()
        if not file_path.endswith(".enc"):
            QMessageBox.warning(self, "Invalid File", "Please select an encrypted file to decrypt.")
            return

        with open(file_path, 'rb') as file:
            decrypted_data = cipher_suite.decrypt(file.read())
        
        with open(file_path.replace(".enc", ""), 'wb') as file:
            file.write(decrypted_data)
        
        self.status_bar.showMessage("File decrypted successfully.", 3000)

    def compress_file(self):
        file_path = self.encryption_file_input.text()
        if not file_path:
            QMessageBox.warning(self, "No File Selected", "Please select a file to compress.")
            return

        zip_path = file_path + ".zip"
        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            zip_file.write(file_path, os.path.basename(file_path))
        
        self.status_bar.showMessage("File compressed successfully.", 3000)

    def init_network_activity_tab(self):
        layout = QVBoxLayout()
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(4)
        self.network_table.setHorizontalHeaderLabels(['Local Address', 'Remote Address', 'Status', 'Protocol'])
        self.network_table.setStyleSheet("background-color: #4b6078; color: #dfe6f2; font-size: 12px;")

        self.load_network_button = QPushButton("Load Network Activity")
        self.load_network_button.clicked.connect(self.load_network_activity)
        self.load_network_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")

        layout.addWidget(self.load_network_button)
        layout.addWidget(self.network_table)
        self.network_activity_tab.setLayout(layout)

    def load_network_activity(self):
        self.network_table.setRowCount(0)
        connections = psutil.net_connections()
        for conn in connections:
            row = self.network_table.rowCount()
            self.network_table.insertRow(row)
            self.network_table.setItem(row, 0, QTableWidgetItem(f"{conn.laddr.ip}:{conn.laddr.port}"))
            self.network_table.setItem(row, 1, QTableWidgetItem(f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"))
            self.network_table.setItem(row, 2, QTableWidgetItem(conn.status))
            self.network_table.setItem(row, 3, QTableWidgetItem(conn.type))
        self.status_bar.showMessage("Network activity loaded successfully.", 3000)

    # New feature: Process Activity Tab
    def init_process_activity_tab(self):
        layout = QVBoxLayout()
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(['PID', 'Name', 'Memory Usage', 'Status'])
        self.process_table.setStyleSheet("background-color: #4b6078; color: #dfe6f2; font-size: 12px;")

        self.load_process_button = QPushButton("Load Process Activity")
        self.load_process_button.clicked.connect(self.load_process_activity)
        self.load_process_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")

        layout.addWidget(self.load_process_button)
        layout.addWidget(self.process_table)
        self.process_activity_tab.setLayout(layout)

    def load_process_activity(self):
        self.process_table.setRowCount(0)
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'status']):
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)
            self.process_table.setItem(row, 0, QTableWidgetItem(str(proc.info['pid'])))
            self.process_table.setItem(row, 1, QTableWidgetItem(proc.info['name']))
            self.process_table.setItem(row, 2, QTableWidgetItem(str(proc.info['memory_info'].rss // (1024 * 1024)) + " MB"))
            self.process_table.setItem(row, 3, QTableWidgetItem(proc.info['status']))
        self.status_bar.showMessage("Process activity loaded successfully.", 3000)

    # New feature: File System Scanner Tab
    def init_file_system_scanner_tab(self):
        layout = QVBoxLayout()
        self.scan_input = QLineEdit()
        self.scan_input.setPlaceholderText("Enter file extension (e.g., .txt) to scan...")
        self.scan_input.setStyleSheet("background-color: #2e3b4e; color: #dfe6f2; padding: 8px;")
        
        self.scan_directory_button = QPushButton("Scan Directory")
        self.scan_directory_button.clicked.connect(self.scan_files)
        self.scan_directory_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        
        self.scan_table = QTableWidget()
        self.scan_table.setColumnCount(2)
        self.scan_table.setHorizontalHeaderLabels(['File Name', 'File Path'])
        self.scan_table.setStyleSheet("background-color: #4b6078; color: #dfe6f2; font-size: 12px;")
        
        layout.addWidget(self.scan_input)
        layout.addWidget(self.scan_directory_button)
        layout.addWidget(self.scan_table)
        self.file_system_scanner_tab.setLayout(layout)

    def scan_files(self):
        extension = self.scan_input.text().strip()
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if not directory or not extension:
            QMessageBox.warning(self, "Input Error", "Please select a directory and enter a file extension to scan.")
            return
        
        self.scan_table.setRowCount(0)
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(extension):
                    row = self.scan_table.rowCount()
                    self.scan_table.insertRow(row)
                    self.scan_table.setItem(row, 0, QTableWidgetItem(file))
                    self.scan_table.setItem(row, 1, QTableWidgetItem(os.path.join(root, file)))
        self.status_bar.showMessage("File system scan completed.", 3000)

    # New feature: System Event Logs Viewer Tab
    def init_event_logs_tab(self):
        layout = QVBoxLayout()
        self.event_log_output = QTextEdit()
        self.event_log_output.setReadOnly(True)
        self.event_log_output.setStyleSheet("background-color: #4b6078; color: #dfe6f2; font-size: 12px;")
        
        self.load_event_log_button = QPushButton("Load System Event Logs")
        self.load_event_log_button.clicked.connect(self.load_event_logs)
        self.load_event_log_button.setStyleSheet("background-color: #2e3b4e; color: #ffffff; padding: 10px;")
        
        layout.addWidget(self.load_event_log_button)
        layout.addWidget(self.event_log_output)
        self.event_logs_tab.setLayout(layout)

    def load_event_logs(self):
        log_data = ""
        try:
            logs = subprocess.check_output("wevtutil qe System /f:text /c:10", shell=True).decode()
            log_data += logs
        except Exception as e:
            log_data = f"Error loading event logs: {e}"
        
        self.event_log_output.setPlainText(log_data)
        self.status_bar.showMessage("System event logs loaded successfully.", 3000)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = HistoryParserTool()
    window.show()
    sys.exit(app.exec_())


