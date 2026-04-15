# Process-Data

A clean, well-structured data processing application following SOLID principles.

## Features

- ✅ User authentication
- ✅ Add, view, and save data items
- ✅ Persistent JSON storage
- ✅ Environment-based configuration
- ✅ Clean architecture with dependency injection

## Setup

1. **Copy the environment template:**

   ```bash
   cp .env.example .env
   ```

2. **Configure your credentials:**
   Edit the `.env` file with your desired settings:

   ```
   APP_USERNAME=your_username
   APP_PASSWORD=your_password
   DATA_FILE_PATH=data.json
   ```

3. **Run the application:**
   ```bash
   python process_data.py
   ```

## Configuration

The application uses environment variables for configuration. If no `.env` file is present, it will use default values:

| Variable         | Default     | Description               |
| ---------------- | ----------- | ------------------------- |
| `APP_USERNAME`   | `admin`     | Authentication username   |
| `APP_PASSWORD`   | `12345`     | Authentication password   |
| `DATA_FILE_PATH` | `data.json` | Path to data storage file |

## Architecture

The code follows SOLID principles with clear separation of concerns:

- **DataItem**: Immutable data model using dataclass
- **IAuthenticator**: Interface for authentication services
- **IDataStorage**: Interface for data persistence
- **Configuration**: Environment-based configuration management
- **DataManager**: Business logic for data operations
- **FileDataStorage**: File-based persistence implementation
- **DataDisplayService**: UI presentation logic
- **DataProcessingApplication**: Main application coordinator
- **ConsoleInterface**: User interaction handler

## Security Note

⚠️ **Never commit the `.env` file to version control!** It's already in `.gitignore` for protection.
