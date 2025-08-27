import os
import sys
import errno
import zlib
from fuse import FUSE, Operations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

class EncryptedCompressedPassthrough(Operations):
    def __init__(self, root, password):
        self.root = root
        self.backend = default_backend()

        # Derive AES key from password
        salt = b'salt_'  # In production, use a unique salt per file/user
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        self.key = kdf.derive(password.encode())

    def _full_path(self, partial):
        return os.path.join(self.root, partial.lstrip("/"))

    # -------------------
    # Compression Helpers
    # -------------------
    def _compress(self, data):
        return zlib.compress(data, level=9)  # Max compression

    def _decompress(self, data):
        try:
            return zlib.decompress(data)
        except:
            return b""  # In case of invalid data

    # -------------------
    # Encryption Helpers
    # -------------------
    def _encrypt(self, data):
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        # Pad data to multiple of block size (16 bytes)
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext  # Prepend IV

    def _decrypt(self, data):
        if len(data) < 16:
            return b""
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]

    # -------------------
    # Filesystem Methods
    # -------------------
    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode',
            'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        return ['.', '..'] + os.listdir(full_path)

    def open(self, path, flags):
        return os.open(self._full_path(path), flags)

    def create(self, path, mode):
        return os.open(self._full_path(path), os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, size, offset, fh):
        os.lseek(fh, 0, os.SEEK_SET)
        encrypted_data = os.read(fh, size + 16 + 16)
        if not encrypted_data:
            return b""
        decrypted_data = self._decrypt(encrypted_data)
        return self._decompress(decrypted_data)[:size]

    def write(self, path, data, offset, fh):
        compressed = self._compress(data)
        encrypted = self._encrypt(compressed)
        os.lseek(fh, 0, os.SEEK_SET)
        return os.write(fh, encrypted)

    def unlink(self, path):
        return os.unlink(self._full_path(path))

# -------------------
# Main Function
# -------------------
if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    backend = os.path.join(base_dir, "fuse_backend")
    mount = os.path.join(base_dir, "passthrough_mount")

    if not os.path.exists(backend):
        print(f"Backend directory not found: {backend}")
        sys.exit(1)
    if not os.path.exists(mount):
        os.makedirs(mount, exist_ok=True)

    password = "your_secure_password"
    FUSE(EncryptedCompressedPassthrough(backend, password), mount, nothreads=True, foreground=True)
