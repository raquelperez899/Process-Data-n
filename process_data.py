"""Data processing application with SOLID principles, security, and best practices.

Provides user authentication, data management, and persistent JSON storage
with security features like rate limiting and secure password hashing.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json
import os
from pathlib import Path
import hmac
import hashlib
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_ITEMS = 10000
MAX_VALUE_LENGTH = 1000
MAX_LOGIN_ATTEMPTS = 5
LOCK_TIMEOUT_MINUTES = 15


class Configuration:
    """Loads and provides application configuration from environment variables."""
    
    def __init__(self):
        self._load_env_file()
    
    def _load_env_file(self) -> None:
        """Load environment variables from .env file with security validation."""
        env_file = Path(__file__).parent / '.env'
        
        if not env_file.exists():
            logger.info("No .env file found. Using default values.")
            return
        
        try:
            if not self._validate_env_file_permissions(env_file):
                logger.warning("⚠️  .env file has insecure permissions. Only owner should have access.")
            
            with open(env_file, 'r', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        try:
                            key, value = line.split('=', 1)
                            os.environ[key.strip()] = value.strip()
                        except ValueError:
                            logger.warning(f"Invalid line format in .env: {line}")
                            continue
        except PermissionError:
            logger.error("Permission denied reading .env file.")
        except IOError as error:
            logger.error(f"Error reading .env file: {error}")
    
    @staticmethod
    def _validate_env_file_permissions(env_file: Path) -> bool:
        """Validate that .env file has secure permissions."""
        try:
            stat_info = env_file.stat()
            mode = stat_info.st_mode & 0o777
            return mode <= 0o600
        except Exception:
            return False
    
    @property
    def username(self) -> str:
        return os.getenv('APP_USERNAME', 'admin')
    
    @property
    def password(self) -> str:
        return os.getenv('APP_PASSWORD', 'password')
    
    @property
    def data_file_path(self) -> str:
        return os.getenv('DATA_FILE_PATH', 'data.json')


@dataclass
class DataItem:
    """Immutable data item with id, value, and timestamp."""
    item_id: int
    value: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            'id': self.item_id,
            'value': self.value,
            'timestamp': self.timestamp
        }


class IAuthenticator(ABC):
    """Interface for authentication services."""
    
    @abstractmethod
    def authenticate(self, username: str, password: str) -> bool:
        pass


class IDataStorage(ABC):
    """Interface for data storage operations."""
    
    @abstractmethod
    def save(self, data: List[DataItem]) -> None:
        pass
    
    @abstractmethod
    def load(self) -> List[DataItem]:
        pass


class DataSerializer:
    """Handles serialization and deserialization between DataItem objects and dictionaries."""
    
    @staticmethod
    def serialize(items: List[DataItem]) -> List[dict]:
        try:
            return [item.to_dict() for item in items]
        except AttributeError as error:
            raise ValueError(f"Invalid DataItem structure: {error}")
    
    @staticmethod
    def deserialize(data: List[dict]) -> List[DataItem]:
        items = []
        for index, item in enumerate(data):
            try:
                if not isinstance(item, dict):
                    raise TypeError(f"Expected dict, got {type(item).__name__}")
                
                if 'id' not in item or 'value' not in item or 'timestamp' not in item:
                    missing = [k for k in ['id', 'value', 'timestamp'] if k not in item]
                    raise ValueError(f"Missing required fields: {missing}")
                
                if not isinstance(item['id'], int):
                    raise TypeError(f"Item id must be int, got {type(item['id']).__name__}")
                
                new_item = DataItem(
                    item_id=item['id'],
                    value=item['value'],
                    timestamp=item['timestamp']
                )
                items.append(new_item)
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"Error deserializing item at index {index}: {error}")
        
        return items


class SimpleAuthenticator(IAuthenticator):
    """Authenticator with rate limiting and timing-safe comparison."""
    
    def __init__(self, valid_username: str, valid_password: str):
        self._valid_username = valid_username
        self._password_hash = self._hash_password(valid_password)
        self._failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password using PBKDF2."""
        salt = os.urandom(32)
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt.hex() + ':' + pw_hash.hex()
    
    @staticmethod
    def _verify_password(stored_hash: str, provided_password: str) -> bool:
        """Verify password using timing-safe comparison."""
        try:
            salt_hex, hash_hex = stored_hash.split(':')
            salt = bytes.fromhex(salt_hex)
            stored_pw_hash = bytes.fromhex(hash_hex)
            provided_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt, 100000)
            return hmac.compare_digest(provided_hash, stored_pw_hash)
        except (ValueError, AttributeError):
            return False
    
    def _is_locked_out(self, username: str) -> bool:
        """Check if account is temporarily locked due to failed attempts."""
        if username not in self._failed_attempts or not self._failed_attempts[username]:
            return False
        
        recent_attempts = [
            attempt for attempt in self._failed_attempts[username]
            if datetime.now() - attempt < timedelta(minutes=LOCK_TIMEOUT_MINUTES)
        ]
        self._failed_attempts[username] = recent_attempts
        
        return len(recent_attempts) >= MAX_LOGIN_ATTEMPTS
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with rate limiting and timing-safe comparison."""
        if not username or not password:
            logger.warning("Authentication attempt with empty credentials")
            return False
        
        if self._is_locked_out(username):
            logger.warning(f"Account {username} temporarily locked due to failed attempts")
            return False
        
        username_match = hmac.compare_digest(username, self._valid_username)
        password_match = self._verify_password(self._password_hash, password) if username_match else False
        
        if not (username_match and password_match):
            self._failed_attempts[username].append(datetime.now())
            logger.warning(f"Failed authentication attempt for {username}")
            return False
        
        self._failed_attempts[username].clear()
        logger.info(f"Successful authentication for {username}")
        return True


class FileDataStorage(IDataStorage):
    """Persists data to JSON files with security validation and error handling."""
    
    def __init__(self, file_path: str, serializer: DataSerializer):
        self._file_path = self._validate_file_path(file_path)
        self._serializer = serializer
    
    @staticmethod
    def _validate_file_path(file_path: str) -> str:
        """Validate file path to prevent directory traversal attacks."""
        path = Path(file_path).resolve()
        base_dir = Path.cwd().resolve()
        
        try:
            path.relative_to(base_dir)
        except ValueError:
            raise ValueError(f"File path {file_path} is outside of allowed directory")
        
        if path.suffix.lower() not in {'.json', '.txt'}:
            raise ValueError(f"File type {path.suffix} not allowed")
        
        return str(path)
    
    def save(self, data: List[DataItem]) -> None:
        """Save data to file with comprehensive error handling."""
        try:
            serialized_data = self._serializer.serialize(data)
        except ValueError as error:
            raise ValueError(f"Failed to serialize data: {error}")
        
        try:
            with open(self._file_path, 'w', encoding='utf-8') as file:
                json.dump(serialized_data, file, indent=2)
        except FileNotFoundError:
            raise IOError(f"Directory not found for file path: {self._file_path}")
        except PermissionError:
            raise PermissionError(f"No write permission for file: {self._file_path}")
        except json.JSONDecodeError as error:
            raise ValueError(f"JSON serialization failed: {error}")
        except TypeError as error:
            raise ValueError(f"Data contains non-serializable objects: {error}")
        except IOError as error:
            raise IOError(f"Failed to write file {self._file_path}: {error}")
    
    def load(self) -> List[DataItem]:
        try:
            with open(self._file_path, 'r', encoding='utf-8') as file:
                data_list = json.load(file)
        except FileNotFoundError:
            return []
        except PermissionError:
            raise PermissionError(f"No read permission for file: {self._file_path}")
        except json.JSONDecodeError as error:
            raise ValueError(f"File contains invalid JSON: {error}")
        except IOError as error:
            raise IOError(f"Failed to read file {self._file_path}: {error}")
        
        try:
            return self._serializer.deserialize(data_list)
        except ValueError as error:
            raise ValueError(f"Failed to deserialize data: {error}")


class DataManager:
    """Manages in-memory data collection with validation and performance optimization."""
    
    def __init__(self):
        self._items: List[DataItem] = []
        self._next_id: int = 1
    
    def add_item(self, value: str) -> DataItem:
        """Add item with security validation and performance optimization."""
        if not value or not value.strip():
            raise ValueError("Item value cannot be empty")
        
        if len(self._items) >= MAX_ITEMS:
            raise ValueError(f"Maximum items limit ({MAX_ITEMS}) reached")
        
        sanitized_value = value.strip()
        if len(sanitized_value) > MAX_VALUE_LENGTH:
            raise ValueError(f"Item value exceeds maximum length ({MAX_VALUE_LENGTH} characters)")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_item = DataItem(item_id=self._next_id, value=sanitized_value, timestamp=timestamp)
        self._next_id += 1
        self._items.append(new_item)
        
        logger.debug(f"Item added: ID={new_item.item_id}")
        return new_item
    
    def get_all_items(self) -> List[DataItem]:
        return self._items.copy()
    
    def set_items(self, items: List[DataItem]) -> None:
        """Set items and rebuild ID counter."""
        if len(items) > MAX_ITEMS:
            raise ValueError(f"Cannot load more than {MAX_ITEMS} items")
        
        self._items = items
        self._next_id = max((item.item_id for item in items), default=0) + 1


class DataDisplayService:
    """Formats and displays data items to console."""
    
    @staticmethod
    def display_items(items: List[DataItem]) -> None:
        if not items:
            print("No items to display.")
            return
        
        print("\n" + "=" * 60)
        print("DATA ITEMS")
        print("=" * 60)
        for item in items:
            print(f"Item {item.item_id}: {item.value}")
            print(f"  Created at: {item.timestamp}")
            print("-" * 60)


class DataProcessingApplication:
    """Coordinates authentication, data management, and storage operations."""
    
    def __init__(
        self,
        authenticator: IAuthenticator,
        data_manager: DataManager,
        storage: IDataStorage,
        display_service: DataDisplayService
    ):
        self._authenticator = authenticator
        self._data_manager = data_manager
        self._storage = storage
        self._display_service = display_service
    
    def authenticate_user(self, username: str, password: str) -> bool:
        return self._authenticator.authenticate(username, password)
    
    def add_item(self, value: str) -> None:
        try:
            item = self._data_manager.add_item(value)
            print(f"✓ Item added successfully (ID: {item.item_id})")
        except ValueError as error:
            print(f"✗ Error: {error}")
    
    def show_items(self) -> None:
        items = self._data_manager.get_all_items()
        self._display_service.display_items(items)
    
    def save_data(self) -> None:
        try:
            items = self._data_manager.get_all_items()
            self._storage.save(items)
            logger.info(f"Data saved successfully ({len(items)} items)")
            print("✓ Data saved successfully.")
        except PermissionError as error:
            logger.error(f"Permission denied: {error}")
            print(f"✗ Permission denied: {error}")
        except ValueError as error:
            logger.error(f"Invalid data format: {error}")
            print(f"✗ Invalid data format: {error}")
        except IOError as error:
            logger.error(f"File operation failed: {error}")
            print(f"✗ File operation failed: {error}")
        except Exception as error:
            logger.error(f"Unexpected error saving data: {error}")
            print(f"✗ Unexpected error saving data: {error}")
    
    def load_data(self) -> None:
        try:
            items = self._storage.load()
            self._data_manager.set_items(items)
            logger.info(f"Data loaded successfully ({len(items)} items)")
            print(f"✓ Loaded {len(items)} items from storage.")
        except PermissionError as error:
            logger.error(f"Permission denied: {error}")
            print(f"✗ Permission denied: {error}")
        except ValueError as error:
            logger.error(f"Data format error: {error}")
            print(f"✗ Data format error: {error}")
        except IOError as error:
            logger.error(f"File operation failed: {error}")
            print(f"✗ File operation failed: {error}")
        except Exception as error:
            logger.error(f"Unexpected error loading data: {error}")
            print(f"✗ Unexpected error loading data: {error}")


class ConsoleInterface:
    """Provides command-line interface for user interaction."""
    
    def __init__(self, application: DataProcessingApplication):
        self._application = application
    
    def run(self) -> None:
        print("=" * 60)
        print("DATA PROCESSING APPLICATION")
        print("=" * 60)
        
        username = input("Username: ").strip()
        password = input("Password: ")
        
        if not username or not password:
            logger.warning("Authentication attempt with empty credentials")
            print("✗ Username and password cannot be empty.")
            return
        
        if not self._application.authenticate_user(username, password):
            logger.warning(f"Authentication failed for user {username}")
            print("✗ Authentication failed. Invalid credentials.")
            return
        
        print("✓ Welcome! Authentication successful.\n")
        self._application.load_data()
        
        self._run_command_loop()
    
    def _run_command_loop(self) -> None:
        commands = {
            'add': self._handle_add_command,
            'show': self._handle_show_command,
            'save': self._handle_save_command,
            'exit': self._handle_exit_command
        }
        
        while True:
            print("\nAvailable commands: add, show, save, exit")
            command = input("Enter command: ").strip().lower()
            
            handler = commands.get(command)
            if handler:
                should_exit = handler()
                if should_exit:
                    break
            else:
                print(f"✗ Unknown command: '{command}'")
    
    def _handle_add_command(self) -> bool:
        value = input("Enter value: ")
        self._application.add_item(value)
        return False
    
    def _handle_show_command(self) -> bool:
        self._application.show_items()
        return False
    
    def _handle_save_command(self) -> bool:
        self._application.save_data()
        return False
    
    def _handle_exit_command(self) -> bool:
        print("Goodbye!")
        return True


def main() -> None:
    """Initialize application components and start the console interface."""
    config = Configuration()
    
    authenticator = SimpleAuthenticator(
        valid_username=config.username,
        valid_password=config.password
    )
    data_manager = DataManager()
    serializer = DataSerializer()
    storage = FileDataStorage(file_path=config.data_file_path, serializer=serializer)
    display_service = DataDisplayService()
    
    application = DataProcessingApplication(
        authenticator=authenticator,
        data_manager=data_manager,
        storage=storage,
        display_service=display_service
    )
    
    console = ConsoleInterface(application)
    console.run()


if __name__ == "__main__":
    main()
