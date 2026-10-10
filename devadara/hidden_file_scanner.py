"""
hidden_file_scanner.py

Detects hidden files and folders on Windows.
"""
import ctypes

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


def get_attributes(file_path):
    """The file's Windows attribute bits, or None if they can't be read."""
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
    except Exception:
        return None
    attrs &= 0xFFFFFFFF
    return None if attrs == INVALID_FILE_ATTRIBUTES else attrs


def is_hidden(file_path):
    try:
        # GetFileAttributesW returns -1 (INVALID_FILE_ATTRIBUTES) on failure
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
        if attrs != -1:
            return bool(attrs & 2) # FILE_ATTRIBUTE_HIDDEN
    except Exception:
        pass
    return False


def describe_attributes(file_path):
    """Human-readable: "Hidden", "Hidden, System", "Not hidden", or
    "Missing" if the file can't be read any more."""
    attrs = get_attributes(file_path)
    if attrs is None:
        return "Missing"
    parts = []
    if attrs & FILE_ATTRIBUTE_HIDDEN:
        parts.append("Hidden")
    if attrs & FILE_ATTRIBUTE_SYSTEM:
        parts.append("System")
    if not attrs & FILE_ATTRIBUTE_HIDDEN:
        parts.insert(0, "Not hidden")
    return ", ".join(parts)
