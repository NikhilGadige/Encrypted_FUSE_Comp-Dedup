from fuse import FUSE, Operations

class SimpleFS(Operations):
    def __init__(self):
        self.files = {'/hello.txt': b'Hello, FUSE World!\n'}

    def readdir(self, path, fh):
        return ['.', '..'] + [f[1:] for f in self.files.keys()]

    def getattr(self, path, fh=None):
        import os, time
        if path == '/':
            return dict(st_mode=(0o40755), st_nlink=2)
        elif path in self.files:
            return dict(st_mode=(0o100644), st_nlink=1,
                        st_size=len(self.files[path]),
                        st_ctime=time.time(),
                        st_mtime=time.time(),
                        st_atime=time.time())
        else:
            raise FileNotFoundError

    def read(self, path, size, offset, fh):
        if path in self.files:
            return self.files[path][offset:offset+size]
        raise FileNotFoundError

if __name__ == '__main__':
    mountpoint = "mountdir"
    FUSE(SimpleFS(), mountpoint, foreground=True)
