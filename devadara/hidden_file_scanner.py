"""
hidden_file_scanner.py

Detects hidden files and folders on Windows.
"""
import ctypes

def is_hidden(file_path):
    try:
        # GetFileAttributesW returns -1 (INVALID_FILE_ATTRIBUTES) on failure
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
        if attrs != -1:
            return bool(attrs & 2) # FILE_ATTRIBUTE_HIDDEN
    except Exception:
        pass
    return False
