import tempfile
from Crypto.PublicKey import RSA
import os

class FileLock:
    FORMAT = "PEM"
    KEY = RSA.generate(2048)

    def __init__(self, dir_name):
        if not isinstance(dir_name, str):
            raise ValueError('path must be a string')
        self.dir_name = dir_name
        self.temp_dir = tempfile.TemporaryDirectory(prefix=dir_name, dir="keys")

    def create_pub_key(self, path=None):
        if path is None:
            path = self.temp_dir.name
        if not os.path.exists(path):
            raise FileNotFoundError(f"The specified path does not exist: {path}")

        pub_key = self.KEY.publickey().export_key(format=self.FORMAT)
        with open(f"{path}/public_key.{self.FORMAT}", "wb") as key:
            key.write(pub_key)

    def create_priv_key(self, path=None):
        if path is None:
            path = self.temp_dir.name
        if not os.path.exists(path):
            raise FileNotFoundError(f"The specified path does not exist: {path}")

        priv_key = self.KEY.export_key(format=self.FORMAT)
        with open(f"{path}/private_key.{self.FORMAT}", "wb") as key:
            key.write(priv_key)

    def cleanup(self):
        """
        Cleans up the temporary directory and all files within it.
        This method should be called when the FileLock instance is no longer needed.
        """
        try:
            self.temp_dir.cleanup()
            return True
        except Exception as e:
            print(f"Error cleaning up temporary directory: {e}")
            return False
