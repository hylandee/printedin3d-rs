# Integration Tests for Rust Auth API

This folder contains Python-based integration tests for the Rust authentication API.

## Setup with uv

`uv` is a fast Python package installer and resolver. Follow these steps to set up the test environment:

### 1. Install uv

If you don't have `uv` installed:

```bash
# On macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or with pip (if you prefer)
pip install uv
```

### 2. Create Virtual Environment

```bash
cd integration_test
uv venv
```

This creates a `.venv` folder with the virtual environment.

### 3. Activate Virtual Environment

```bash
# On macOS/Linux
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
uv pip install -r requirements.txt
```

### 5. Run the Tests

Make sure the Rust server is running on `http://127.0.0.1:3000`, then:

```bash
pytest test_auth.py -v
```

## Dependencies

- `requests` - For making HTTP requests
- `pytest` - For running tests

## Test Coverage

The tests cover:
- User signup
- Duplicate signup conflict
- Login with valid credentials
- Accessing protected `/me` endpoint
- Logout
- Unauthorized access after logout
- Login with invalid credentials

## Notes

- Tests use a unique username per run to avoid conflicts
- Database cleanup happens automatically after tests
- Make sure the Rust server is running before executing tests