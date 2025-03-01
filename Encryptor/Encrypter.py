import os
import sys
import threading
import concurrent.futures
from PyQt5 import QtWidgets, QtCore
from Cryptodome.Cipher import AES, DES3, Blowfish, ChaCha20, PKCS1_OAEP
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
import hmac

MAGIC = b"VALIDATION_OK" + bytes(3)  # 16 bytes marker for validation
SALT_SIZE = 16
ITERATIONS = 100000
CHUNK_SIZE = 65536  # 64KB

CIPHER_PARAMS = {
    'AES': {
        'module': AES,
        'key_len': 32,
        'iv_size': 16,
        'segment_size': 128,
        'type': 'cfb'
    },
    'AES-GCM': {
        'module': AES,
        'key_len': 32,
        'nonce_size': 12,
        'tag_size': 16,
        'type': 'gcm'
    },
    'ChaCha20': {
        'module': ChaCha20,
        'key_len': 32,
        'nonce_size': 8,
        'type': 'chacha20'
    },
    '3DES': {
        'module': DES3,
        'key_len': 24,
        'iv_size': 8,
        'segment_size': 64,
        'type': 'cfb'
    },
    'Blowfish': {
        'module': Blowfish,
        'key_len': 32,
        'iv_size': 8,
        'segment_size': 64,
        'type': 'cfb'
    },
}

def symmetric_encrypt_file(input_path, output_path, password, algorithm):
    password_bytes = password.encode('utf-8')
    salt = os.urandom(SALT_SIZE)
    key_len = CIPHER_PARAMS[algorithm]['key_len']
    key = PBKDF2(password_bytes, salt, dkLen=key_len, count=ITERATIONS,
                 prf=lambda p, s: hmac.new(p, s, SHA256).digest())

    algo_type = CIPHER_PARAMS[algorithm]['type']

    if algo_type == 'cfb':
        params = CIPHER_PARAMS[algorithm]
        iv = os.urandom(params['iv_size'])
        cipher = params['module'].new(key, params['module'].MODE_CFB, iv=iv, segment_size=params['segment_size'])
        encrypted_validation = cipher.encrypt(MAGIC)
        header = iv + salt + encrypted_validation
        with open(output_path, 'wb') as fout, open(input_path, 'rb') as fin:
            fout.write(header)
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(cipher.encrypt(chunk))

    elif algo_type == 'gcm':
        params = CIPHER_PARAMS[algorithm]
        nonce = os.urandom(params['nonce_size'])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        encrypted_validation = cipher.encrypt(MAGIC)
        dummy_tag = b'\0' * params['tag_size']
        header = nonce + salt + dummy_tag + encrypted_validation
        with open(output_path, 'wb') as fout, open(input_path, 'rb') as fin:
            fout.write(header)
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(cipher.encrypt(chunk))
            tag = cipher.digest()

        with open(output_path, 'r+b') as f:
            f.seek(len(nonce) + len(salt))
            f.write(tag)

    elif algo_type == 'chacha20':
        params = CIPHER_PARAMS[algorithm]
        nonce = os.urandom(params['nonce_size'])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted_validation = cipher.encrypt(MAGIC)
        header = nonce + salt + encrypted_validation
        with open(output_path, 'wb') as fout, open(input_path, 'rb') as fin:
            fout.write(header)
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(cipher.encrypt(chunk))
    else:
        raise ValueError("Unsupported algorithm")


def symmetric_decrypt_file(input_path, output_path, password, algorithm):
    password_bytes = password.encode('utf-8')
    algo_type = CIPHER_PARAMS[algorithm]['type']

    if algo_type == 'cfb':
        params = CIPHER_PARAMS[algorithm]
        header_size = params['iv_size'] + SALT_SIZE + len(MAGIC)
        with open(input_path, 'rb') as fin:
            header = fin.read(header_size)
            iv = header[:params['iv_size']]
            salt = header[params['iv_size']:params['iv_size'] + SALT_SIZE]
            encrypted_validation = header[params['iv_size'] + SALT_SIZE:]
            key = PBKDF2(password_bytes, salt, dkLen=params['key_len'], count=ITERATIONS,
                         prf=lambda p, s: hmac.new(p, s, SHA256).digest())
            cipher = params['module'].new(key, params['module'].MODE_CFB, iv=iv, segment_size=params['segment_size'])
            if cipher.decrypt(encrypted_validation) != MAGIC:
                raise ValueError("Incorrect password or corrupted file")
            with open(output_path, 'wb') as fout:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    fout.write(cipher.decrypt(chunk))

    elif algo_type == 'gcm':
        params = CIPHER_PARAMS[algorithm]
        header_size = params['nonce_size'] + SALT_SIZE + params['tag_size'] + len(MAGIC)
        with open(input_path, 'rb') as fin:
            header = fin.read(header_size)
            nonce = header[:params['nonce_size']]
            salt = header[params['nonce_size']:params['nonce_size'] + SALT_SIZE]
            tag = header[params['nonce_size'] + SALT_SIZE:params['nonce_size'] + SALT_SIZE + params['tag_size']]
            encrypted_validation = header[params['nonce_size'] + SALT_SIZE + params['tag_size']:]
            key = PBKDF2(password_bytes, salt, dkLen=params['key_len'], count=ITERATIONS,
                         prf=lambda p, s: hmac.new(p, s, SHA256).digest())
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            decrypted_validation = cipher.decrypt(encrypted_validation)
            if decrypted_validation != MAGIC:
                raise ValueError("Incorrect password or corrupted file (validation failed)")
            with open(output_path, 'wb') as fout:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    fout.write(cipher.decrypt(chunk))
            try:
                cipher.verify(tag)
            except ValueError:
                raise ValueError("Incorrect password or corrupted file (tag mismatch)")

    elif algo_type == 'chacha20':
        params = CIPHER_PARAMS[algorithm]
        header_size = params['nonce_size'] + SALT_SIZE + len(MAGIC)
        with open(input_path, 'rb') as fin:
            header = fin.read(header_size)
            nonce = header[:params['nonce_size']]
            salt = header[params['nonce_size']:params['nonce_size'] + SALT_SIZE]
            encrypted_validation = header[params['nonce_size'] + SALT_SIZE:]
            key = PBKDF2(password_bytes, salt, dkLen=params['key_len'], count=ITERATIONS,
                         prf=lambda p, s: hmac.new(p, s, SHA256).digest())
            cipher = ChaCha20.new(key=key, nonce=nonce)
            if cipher.decrypt(encrypted_validation) != MAGIC:
                raise ValueError("Incorrect password or corrupted file")
            with open(output_path, 'wb') as fout:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    fout.write(cipher.decrypt(chunk))
    else:
        raise ValueError("Unsupported algorithm")

def rsa_encrypt_file(input_path, output_path, public_key_path):
    
    with open(public_key_path, 'rb') as f:
        rsa_key = RSA.import_key(f.read())
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    session_key = os.urandom(32)
    iv = os.urandom(16)
    enc_session_key = rsa_cipher.encrypt(session_key)
    aes_cipher = AES.new(session_key, AES.MODE_CFB, iv=iv, segment_size=128)
    encrypted_validation = aes_cipher.encrypt(MAGIC)
    with open(output_path, 'wb') as fout:
        enc_key_len = len(enc_session_key)
        fout.write(enc_key_len.to_bytes(2, 'big'))
        fout.write(enc_session_key)
        fout.write(iv)
        fout.write(encrypted_validation)
        with open(input_path, 'rb') as fin:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(aes_cipher.encrypt(chunk))


def rsa_decrypt_file(input_path, output_path, private_key_path):
    with open(private_key_path, 'rb') as f:
        rsa_key = RSA.import_key(f.read())
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    with open(input_path, 'rb') as fin:
        enc_key_len_bytes = fin.read(2)
        enc_key_len = int.from_bytes(enc_key_len_bytes, 'big')
        enc_session_key = fin.read(enc_key_len)
        session_key = rsa_cipher.decrypt(enc_session_key)
        iv = fin.read(16)
        encrypted_validation = fin.read(len(MAGIC))
        aes_cipher = AES.new(session_key, AES.MODE_CFB, iv=iv, segment_size=128)
        if aes_cipher.decrypt(encrypted_validation) != MAGIC:
            raise ValueError("Incorrect RSA key or corrupted file")
        with open(output_path, 'wb') as fout:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(aes_cipher.decrypt(chunk))

def generate_rsa_keys(private_key_path, public_key_path, key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open(private_key_path, 'wb') as f:
        f.write(private_key)
    with open(public_key_path, 'wb') as f:
        f.write(public_key)

class FileProcessorThread(QtCore.QThread):
    progress_update = QtCore.pyqtSignal(int, int)  # (processed, total)
    status_update = QtCore.pyqtSignal(str)
    finished_signal = QtCore.pyqtSignal()
    error_signal = QtCore.pyqtSignal(str)

    def __init__(self, input_path, output_dir, password, algorithm, rsa_key_file, mode, parent=None):
        super(FileProcessorThread, self).__init__(parent)
        self.input_path = input_path
        self.output_dir = output_dir
        self.password = password
        self.algorithm = algorithm
        self.rsa_key_file = rsa_key_file
        self.mode = mode  # 'encrypt' or 'decrypt'

    def run(self):
        try:
            if os.path.isfile(self.input_path):
                self.process_single_file(self.input_path)
            else:
                self.process_directory()
            self.status_update.emit("Completed successfully")
        except Exception as e:
            self.error_signal.emit(str(e))
        finally:
            self.finished_signal.emit()

    def process_single_file(self, input_file):
        filename = os.path.basename(input_file)
        if self.mode == 'encrypt':
            if self.algorithm == "RSA Hybrid":
                output_path = os.path.join(self.output_dir, f"{filename}.enc")
                rsa_encrypt_file(input_file, output_path, self.rsa_key_file)
            else:
                output_path = os.path.join(self.output_dir, f"{filename}.enc")
                symmetric_encrypt_file(input_file, output_path, self.password, self.algorithm)
        else:  # decrypt
            if self.algorithm == "RSA Hybrid":
                if not filename.endswith('.enc'):
                    raise ValueError("Selected file does not appear to be RSA Hybrid encrypted")
                output_path = os.path.join(self.output_dir, filename[:-4])
                rsa_decrypt_file(input_file, output_path, self.rsa_key_file)
            else:
                if not filename.endswith('.enc'):
                    raise ValueError("Selected file is not encrypted")
                output_path = os.path.join(self.output_dir, filename[:-4])
                symmetric_decrypt_file(input_file, output_path, self.password, self.algorithm)

    def process_directory(self):
        tasks = []
        for root, dirs, files in os.walk(self.input_path):
            for file in files:
                input_file_path = os.path.join(root, file)
                relative_path = os.path.relpath(input_file_path, self.input_path)
                if self.mode == 'encrypt':
                    output_file_path = os.path.join(self.output_dir, f"{relative_path}.enc")
                else:
                    if not file.endswith('.enc'):
                        continue
                    output_file_path = os.path.join(self.output_dir, relative_path[:-4])
                tasks.append((input_file_path, output_file_path))

        total_files = len(tasks)
        if total_files == 0:
            raise ValueError("No files found to process in the selected directory.")

        processed = [0]
        lock = threading.Lock()

        def process_task(in_path, out_path):
            try:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                if self.mode == 'encrypt':
                    if self.algorithm == "RSA Hybrid":
                        rsa_encrypt_file(in_path, out_path, self.rsa_key_file)
                    else:
                        symmetric_encrypt_file(in_path, out_path, self.password, self.algorithm)
                else:
                    if self.algorithm == "RSA Hybrid":
                        rsa_decrypt_file(in_path, out_path, self.rsa_key_file)
                    else:
                        symmetric_decrypt_file(in_path, out_path, self.password, self.algorithm)
            except Exception as e:
                print(f"Error processing {in_path}: {e}")
            finally:
                with lock:
                    processed[0] += 1
                    current = processed[0]
                self.progress_update.emit(current, total_files)

        with concurrent.futures.ThreadPoolExecutor(max_workers=(os.cpu_count() or 2)) as executor:
            futures = [executor.submit(process_task, in_path, out_path) for in_path, out_path in tasks]
            concurrent.futures.wait(futures)

class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Secure File/Folder Encrypter/Decryptor")
        self.setGeometry(100, 100, 700, 600)
        self.setup_ui()
        self.worker = None

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout()
        type_layout = QtWidgets.QHBoxLayout()
        self.file_radio = QtWidgets.QRadioButton("File")
        self.file_radio.setChecked(True)
        self.folder_radio = QtWidgets.QRadioButton("Folder")
        type_layout.addWidget(QtWidgets.QLabel("Input Type:"))
        type_layout.addWidget(self.file_radio)
        type_layout.addWidget(self.folder_radio)
        layout.addLayout(type_layout)

        path_layout = QtWidgets.QHBoxLayout()
        self.input_path_edit = QtWidgets.QLineEdit()
        self.input_path_edit.setPlaceholderText("Select file or folder")
        browse_button = QtWidgets.QPushButton("Browse")
        browse_button.clicked.connect(self.browse_input)
        path_layout.addWidget(self.input_path_edit)
        path_layout.addWidget(browse_button)
        layout.addLayout(path_layout)

        mode_layout = QtWidgets.QHBoxLayout()
        self.encrypt_radio = QtWidgets.QRadioButton("Encrypt")
        self.encrypt_radio.setChecked(True)
        self.decrypt_radio = QtWidgets.QRadioButton("Decrypt")
        self.encrypt_radio.toggled.connect(self.update_ui_for_mode)
        mode_layout.addWidget(QtWidgets.QLabel("Mode:"))
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addWidget(self.decrypt_radio)
        layout.addLayout(mode_layout)

        algo_layout = QtWidgets.QHBoxLayout()
        algo_label = QtWidgets.QLabel("Algorithm:")
        self.algorithm_combo = QtWidgets.QComboBox()
        self.algorithm_combo.addItems(["AES", "AES-GCM", "ChaCha20", "3DES", "Blowfish", "RSA Hybrid"])
        self.algorithm_combo.currentIndexChanged.connect(self.update_ui_for_algorithm)
        algo_layout.addWidget(algo_label)
        algo_layout.addWidget(self.algorithm_combo)
        layout.addLayout(algo_layout)

        self.rsa_key_layout = QtWidgets.QHBoxLayout()
        self.rsa_key_label = QtWidgets.QLabel("RSA Key File:")
        self.rsa_key_edit = QtWidgets.QLineEdit()
        self.rsa_key_edit.setPlaceholderText("Select RSA public key (for encryption) or private key (for decryption)")
        self.rsa_key_button = QtWidgets.QPushButton("Browse")
        self.rsa_key_button.clicked.connect(self.browse_rsa_key)
        self.rsa_key_layout.addWidget(self.rsa_key_label)
        self.rsa_key_layout.addWidget(self.rsa_key_edit)
        self.rsa_key_layout.addWidget(self.rsa_key_button)
        layout.addLayout(self.rsa_key_layout)

        self.gen_rsa_button = QtWidgets.QPushButton("Generate RSA Key Pair")
        self.gen_rsa_button.clicked.connect(self.generate_rsa_keys_ui)
        layout.addWidget(self.gen_rsa_button)

        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_edit.setPlaceholderText("Enter password (for symmetric encryption)")
        layout.addWidget(self.password_edit)

        self.process_button = QtWidgets.QPushButton("Process")
        self.process_button.clicked.connect(self.process)
        layout.addWidget(self.process_button)

        self.status_label = QtWidgets.QLabel("")
        layout.addWidget(self.status_label)

        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(0)  # Start with indeterminate progress
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)
        self.update_ui_for_algorithm()

    def browse_input(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.ReadOnly
        if self.folder_radio.isChecked():
            folder_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder", options=options)
            if folder_path:
                self.input_path_edit.setText(folder_path)
        else:
            file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)", options=options)
            if file_path:
                self.input_path_edit.setText(file_path)

    def browse_rsa_key(self):
        key_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select RSA Key File", "", "PEM Files (*.pem *.key);;All Files (*)")
        if key_path:
            self.rsa_key_edit.setText(key_path)

    def generate_rsa_keys_ui(self):
        private_key_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Private Key", "private.pem", "PEM Files (*.pem);;All Files (*)")
        if not private_key_path:
            return
        public_key_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Public Key", "public.pem", "PEM Files (*.pem);;All Files (*)")
        if not public_key_path:
            return
        try:
            generate_rsa_keys(private_key_path, public_key_path)
            QtWidgets.QMessageBox.information(self, "RSA Key Generation", "RSA key pair generated successfully.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error generating RSA keys: {e}")

    def update_ui_for_algorithm(self):
        algo = self.algorithm_combo.currentText()
        if algo == "RSA Hybrid":
            self.rsa_key_label.show()
            self.rsa_key_edit.show()
            self.rsa_key_button.show()
            self.password_edit.setEnabled(False)
        else:
            self.rsa_key_label.hide()
            self.rsa_key_edit.hide()
            self.rsa_key_button.hide()
            self.password_edit.setEnabled(True)

    def update_ui_for_mode(self):
        if self.encrypt_radio.isChecked():
            if self.algorithm_combo.currentText() == "RSA Hybrid":
                self.rsa_key_edit.setPlaceholderText("Select RSA public key for encryption")
        else:
            if self.algorithm_combo.currentText() == "RSA Hybrid":
                self.rsa_key_edit.setPlaceholderText("Select RSA private key for decryption")

    def process(self):
        input_path = self.input_path_edit.text().strip()
        if not input_path:
            QtWidgets.QMessageBox.critical(self, "Error", "Please select an input file or folder")
            return

        mode = "encrypt" if self.encrypt_radio.isChecked() else "decrypt"
        algorithm = self.algorithm_combo.currentText()
        password = self.password_edit.text().strip()
        if algorithm != "RSA Hybrid" and not password:
            QtWidgets.QMessageBox.critical(self, "Error", "Please enter a password")
            return
        rsa_key_file = self.rsa_key_edit.text().strip() if algorithm == "RSA Hybrid" else ""
        if algorithm == "RSA Hybrid" and not rsa_key_file:
            QtWidgets.QMessageBox.critical(self, "Error", "Please select an RSA key file")
            return

        if os.path.isfile(input_path):
            base_dir = os.path.dirname(input_path)
        else:
            base_dir = input_path
        suffix = "_encrypted" if mode == "encrypt" else "_decrypted"
        output_dir = f"{input_path}{suffix}" if os.path.isdir(input_path) else os.path.join(base_dir, suffix)
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Could not create output directory: {e}")
            return

        self.progress_bar.setMaximum(0)
        self.status_label.setText("Processing...")
        self.process_button.setEnabled(False)

        self.worker = FileProcessorThread(input_path, output_dir, password, algorithm, rsa_key_file, mode)
        self.worker.progress_update.connect(self.on_progress_update)
        self.worker.status_update.connect(self.on_status_update)
        self.worker.error_signal.connect(self.on_error)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def on_progress_update(self, processed, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(processed)
        self.status_label.setText(f"Processed {processed} of {total} files")

    def on_status_update(self, message):
        self.status_label.setText(message)

    def on_error(self, error_message):
        QtWidgets.QMessageBox.critical(self, "Error", error_message)

    def on_finished(self):
        self.process_button.setEnabled(True)
        self.progress_bar.setValue(self.progress_bar.maximum())
        QtWidgets.QMessageBox.information(self, "Success", "Processing completed successfully.")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
