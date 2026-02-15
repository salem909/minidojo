# Changelog

## Version 1.1 - Windows Compatibility Fix (2026-02-12)

### 🐛 Bug Fixes

**Fixed Docker Python SDK compatibility issue on Windows**
- **Issue**: `docker.errors.DockerException: Error while fetching server API version: Not supported URL scheme http+docker`
- **Root Cause**: The Docker Python SDK on Windows requires special handling for named pipes (`npipe://`)
- **Solution**: Implemented intelligent Docker client initialization with fallback support

### 📝 Changes Made

#### 1. Updated `web/requirements.txt`
- Added `pywin32==306` for Windows named pipe support (conditional install)
- Added explicit `requests==2.31.0` dependency
- Ensures compatibility across Linux, macOS, and Windows

#### 2. Updated `web/app.py`
- Replaced simple `docker.from_env()` with intelligent initialization
- Added connection fallback chain:
  1. Try Unix socket (Linux/macOS): `unix://var/run/docker.sock`
  2. Try Windows named pipe: `npipe:////./pipe/docker_engine`
  3. Fallback to `docker.from_env()` for other configurations
- Added `docker_client.ping()` to verify connection before proceeding

#### 3. Updated `cleanup/requirements.txt`
- Added `pywin32==306` for Windows compatibility
- Added explicit `requests==2.31.0` dependency

#### 4. Updated `cleanup/cleanup.py`
- Created `get_docker_client()` helper function
- Implemented same fallback logic as web service
- Both cleanup functions now use the robust client initialization

#### 5. Added `WINDOWS.md`
- Comprehensive Windows setup guide
- Common issues and solutions
- Docker Desktop configuration recommendations
- Troubleshooting commands
- Performance tips for Windows users

### ✅ Testing

The fix has been tested and verified to work on:
- ✅ Linux (Ubuntu 22.04) with Docker Engine
- ✅ Windows 10/11 with Docker Desktop
- ✅ macOS with Docker Desktop (expected to work)

### 🚀 How to Apply the Fix

If you already have the project:

1. **Stop running containers**:
   ```bash
   docker compose down
   ```

2. **Update the files**:
   - Replace `web/requirements.txt`
   - Replace `web/app.py`
   - Replace `cleanup/requirements.txt`
   - Replace `cleanup/cleanup.py`
   - Add `WINDOWS.md`

3. **Rebuild and restart**:
   ```bash
   docker compose up --build
   ```

### 📋 Verification

After applying the fix, you should see:
```
web-1  | ✓ Database initialized
web-1  | ✓ Seeded challenge: dojo1-ret2win
web-1  | INFO: Uvicorn running on http://0.0.0.0:8080
```

No more `URLSchemeUnknown` or `http+docker` errors!

### 🔍 Technical Details

The issue occurred because:
1. Docker Desktop on Windows uses named pipes for communication
2. The default `docker.from_env()` doesn't always detect the correct connection method
3. The `requests` library needs special handling for `npipe://` URLs
4. The `pywin32` package provides Windows-specific support

Our solution:
1. Explicitly tries each connection method in order
2. Verifies the connection with `ping()` before use
3. Falls back gracefully if one method fails
4. Works across all platforms without breaking existing functionality

### 🎯 Future Improvements

Potential enhancements for future versions:
- Add connection retry logic with exponential backoff
- Add health check endpoint for monitoring
- Add Docker daemon status to web UI
- Support for remote Docker hosts
- Connection pooling for better performance

---

**Previous Version**: 1.0 (Initial Release)
**Current Version**: 1.1 (Windows Compatibility Fix)
