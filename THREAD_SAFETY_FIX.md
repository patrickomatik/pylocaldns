# SQLite Thread Safety Fix

This document explains the changes made to fix the SQLite thread safety issue in the PyLocalDNS project.

## Issue Summary

The application was experiencing a SQLite thread safety error when looking up MAC address vendors from different threads:

```
SQLite objects created in a thread can only be used in that same thread. The object was created in thread id 8581844800 and this is thread id 6237941760.
```

This error occurred because SQLite connections created in one thread were being accessed from another thread, which SQLite doesn't allow by default.

## Solution Implemented

1. Modified `vendor_db.py` to use thread-local storage for SQLite connections:
   - Added threading.local() to store thread-specific database connections
   - Implemented a _get_connection() method that provides thread-specific connections
   - Added proper locking for database operations to prevent race conditions
   - Updated all database operations to use the thread-local connection

2. Updated `app.py` to acknowledge the thread-safety improvements:
   - Updated logging messages to indicate thread-safety features

## Technical Details

### Thread-Local Storage

The core of the fix uses Python's `threading.local()` to maintain separate database connections for each thread:

```python
self.local_storage = threading.local()  # Thread-local storage for connections

def _get_connection(self):
    """Get a thread-specific SQLite connection."""
    if not hasattr(self.local_storage, 'conn') or self.local_storage.conn is None:
        self.local_storage.conn = sqlite3.connect(self.db_path)
    return self.local_storage.conn
```

This ensures that each thread gets its own SQLite connection, preventing cross-thread access errors.

### Proper Locking

To prevent race conditions when multiple threads try to access the database simultaneously, we added a recursive lock:

```python
self.lock = threading.RLock()  # Thread lock for database access

with self.lock:
    conn = self._get_connection()
    # Perform database operations...
```

The recursive lock (RLock) allows the same thread to acquire the lock multiple times, which prevents deadlocks when database operations call other functions that also try to acquire the lock.

### Connection Closing

The `close()` method was updated to properly close connections based on thread-local storage:

```python
def close(self) -> None:
    """Close the database connection."""
    with self.lock:
        if hasattr(self.local_storage, 'conn') and self.local_storage.conn:
            self.local_storage.conn.close()
            self.local_storage.conn = None
```

## Benefits

1. **Thread Safety**: The application can now safely use the vendor database from multiple threads without errors.
2. **Better Performance**: By maintaining connections per thread rather than creating new ones for each lookup, the application will perform faster.
3. **Robustness**: The addition of proper locking prevents race conditions and database corruption.

## Testing

The changes were tested by ensuring that the application can handle concurrent requests from multiple clients without experiencing thread-related SQLite errors.

The primary test was checking if the MAC vendor information displays correctly in the web UI when multiple users are browsing the dashboard simultaneously.
