import os
import pytest
import tempfile
import shutil
from server.locking_mechanism import FileLock
from Crypto.PublicKey import RSA


class TestFileLock:
    """Test suite for the FileLock class."""

    @pytest.fixture
    def lock(self):
        """Fixture to create and clean up a FileLock instance."""
        lock_instance = FileLock("test_dir")
        yield lock_instance
        # Cleanup after test
        lock_instance.temp_dir.cleanup()

    @pytest.fixture
    def custom_path(self):
        """Fixture to create and clean up a custom directory."""
        path = os.path.join(tempfile.gettempdir(), "test_custom_dir")
        os.makedirs(path, exist_ok=True)
        yield path
        # Cleanup after test
        if os.path.exists(path):
            shutil.rmtree(path)

    def test_initialization(self, lock):
        """Test that FileLock initializes correctly with a temporary directory."""
        assert os.path.exists(lock.temp_dir.name)
        assert os.path.basename(lock.temp_dir.name).startswith("test_dir")

    def test_initialization_with_invalid_type(self):
        """Test that initializing FileLock with a non-string raises ValueError."""
        with pytest.raises(ValueError, match="path must be a string"):
            FileLock(123)

    def test_create_pub_key_default_path(self, lock):
        """Test creating a public key in the default path."""
        lock.create_pub_key()
        key_path = os.path.join(lock.temp_dir.name, f"public_key.{lock.FORMAT}")

        assert os.path.exists(key_path)
        assert os.path.getsize(key_path) > 0

        # Verify it's a valid public key
        with open(key_path, 'rb') as key_file:
            key = RSA.import_key(key_file.read())
            assert not key.has_private()
            assert key.export_key().startswith(b'-----BEGIN PUBLIC KEY-----')

    def test_create_priv_key_default_path(self, lock):
        """Test creating a private key in the default path."""
        lock.create_priv_key()
        key_path = os.path.join(lock.temp_dir.name, f"private_key.{lock.FORMAT}")

        assert os.path.exists(key_path)
        assert os.path.getsize(key_path) > 0

        # Verify it's a valid private key
        with open(key_path, 'rb') as key_file:
            key = RSA.import_key(key_file.read())
            assert key.has_private()
            assert key.export_key().startswith(b'-----BEGIN RSA PRIVATE KEY-----')

    def test_create_keys_custom_path(self, lock, custom_path):
        """Test creating keys in a custom path."""
        lock.create_pub_key(path=custom_path)
        lock.create_priv_key(path=custom_path)

        pub_key_path = os.path.join(custom_path, f"public_key.{lock.FORMAT}")
        priv_key_path = os.path.join(custom_path, f"private_key.{lock.FORMAT}")

        assert os.path.exists(pub_key_path)
        assert os.path.exists(priv_key_path)

    def test_create_keys_nonexistent_path(self, lock):
        """Test that creating keys in a nonexistent path raises FileNotFoundError."""
        nonexistent_path = "/path/that/does/not/exist"

        with pytest.raises(FileNotFoundError, match=f"The specified path does not exist: {nonexistent_path}"):
            lock.create_pub_key(path=nonexistent_path)

        with pytest.raises(FileNotFoundError, match=f"The specified path does not exist: {nonexistent_path}"):
            lock.create_priv_key(path=nonexistent_path)

    def test_key_pair_compatibility(self, lock):
        """Test that the generated key pair is compatible."""
        lock.create_pub_key()
        lock.create_priv_key()

        pub_key_path = os.path.join(lock.temp_dir.name, f"public_key.{lock.FORMAT}")
        priv_key_path = os.path.join(lock.temp_dir.name, f"private_key.{lock.FORMAT}")

        with open(pub_key_path, 'rb') as pub_file, open(priv_key_path, 'rb') as priv_file:
            pub_key = RSA.import_key(pub_file.read())
            priv_key = RSA.import_key(priv_file.read())

            # Verify the public key is derived from the private key
            assert pub_key.n == priv_key.n
            assert pub_key.e == priv_key.e