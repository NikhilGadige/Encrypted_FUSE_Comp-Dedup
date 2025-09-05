#!/usr/bin/env python3
import os, sys, zlib, secrets, json, errno
from fuse import FUSE, Operations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class EncryptedCompressedPassthrough(Operations):
    def __init__(self, root, password):
        self.root = root
        self.backend = default_backend()
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        self.key = kdf.derive(password.encode())
        self.buffers = {}

    def _full_path(self, partial):
        return os.path.join(self.root, partial.lstrip("/"))

    # --- AES helpers ---
    def _encrypt(self, data: bytes) -> bytes:
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        pad_len = 16 - (len(data) % 16)
        padded = data + bytes([pad_len] * pad_len)
        return iv + encryptor.update(padded) + encryptor.finalize()

    def _decrypt(self, data: bytes) -> bytes:
        if len(data) < 16:
            return b""
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        return padded[:-padded[-1]]

    # --- Compression helpers ---
    def _compress(self, data: bytes) -> bytes:
        return zlib.compress(data, level=9)

    def _decompress(self, data: bytes) -> bytes:
        try:
            return zlib.decompress(data)
        except zlib.error:
            return b""

    # --- Metadata helpers ---
    def _meta_path(self, path): return self._full_path(path) + ".meta"

    def _save_meta(self, path, size):
        with open(self._meta_path(path), "w") as f:
            json.dump({"size": size}, f)

    def _load_meta(self, path):
        try:
            with open(self._meta_path(path)) as f:
                return json.load(f)["size"]
        except Exception:
            return 0

    # --- FS methods ---
    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        if not os.path.exists(full_path):
            raise OSError(errno.ENOENT, "")
        st = os.lstat(full_path)
        d = {k: getattr(st, k) for k in (
            'st_atime','st_ctime','st_gid','st_mode','st_mtime','st_nlink','st_size','st_uid')}
        if os.path.isfile(full_path):
            d["st_size"] = self._load_meta(path)
        return d

    def readdir(self, path, fh):
        return ['.', '..'] + [f for f in os.listdir(self._full_path(path)) if not f.endswith(".meta")]

    def mknod(self, path, mode, dev):
        open(self._full_path(path), "wb").close()
        self._save_meta(path, 0)

    def create(self, path, mode):
        full_path = self._full_path(path)
        fd = os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
        self._save_meta(path, 0)
        self.buffers[fd] = bytearray()
        return fd

    def open(self, path, flags):
        return os.open(self._full_path(path), flags)

    def read(self, path, size, offset, fh):
        with open(self._full_path(path), "rb") as f:
            enc = f.read()
        dec = self._decrypt(enc)
        data = self._decompress(dec)
        return data[offset:offset+size]

    def write(self, path, data, offset, fh):
        if fh not in self.buffers:
            self.buffers[fh] = bytearray()
        buf = self.buffers[fh]
        if offset > len(buf):
            buf.extend(b"\x00" * (offset - len(buf)))
        buf[offset:offset+len(data)] = data
        return len(data)

    def flush(self, path, fh):
        if fh in self.buffers:
            data = bytes(self.buffers[fh])
            compressed = self._compress(data)
            encrypted = self._encrypt(compressed)
            with open(self._full_path(path), "wb") as f:
                f.write(encrypted)
            self._save_meta(path, len(data))
            del self.buffers[fh]
        return 0

    def release(self, path, fh):
        self.flush(path, fh)
        return os.close(fh)

    def unlink(self, path):
        os.unlink(self._full_path(path))
        try: os.unlink(self._meta_path(path))
        except FileNotFoundError: pass
        return 0


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    backend = os.path.join(base_dir, "fuse_backend")
    mount = os.path.join(base_dir, "passthrough_mount")
    if not os.path.exists(backend):
        sys.exit("Backend not found")
    os.makedirs(mount, exist_ok=True)
    password = "your_secure_password"
    FUSE(EncryptedCompressedPassthrough(backend, password), mount, nothreads=True, foreground=True, nonempty=True)