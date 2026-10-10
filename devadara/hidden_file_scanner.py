"""
hidden_file_scanner.py

Detects hidden files and folders on Windows.
"""
import ctypes
import os

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


FILE_ATTRIBUTE_NORMAL = 0x80


def unhide_refusal_reason(file_path):
    """Why this file must not be unhidden, or None if it may be (after the
    user confirmed). Windows' own hidden files stay hidden: anything under
    %SystemRoot%, and anything also marked System (desktop.ini, thumbnail
    caches, ...) - unhiding those only clutters folders or confuses
    Windows, and they're not what a hidden-file check is looking for."""
    attrs = get_attributes(file_path)
    if attrs is None:
        return "the file no longer exists"
    if not attrs & FILE_ATTRIBUTE_HIDDEN:
        return "it's already visible"
    system_root = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))
    if os.path.normcase(os.path.abspath(file_path)).startswith(system_root + os.sep):
        return "it's a Windows component"
    if attrs & FILE_ATTRIBUTE_SYSTEM:
        return "it's a Windows system file (Hidden + System)"
    return None


def unhide(file_path):
    """Clear ONLY the Hidden attribute (every other attribute is kept).
    Doesn't touch the file's contents. Returns True on success. Callers
    check unhide_refusal_reason() first and confirm with the user."""
    attrs = get_attributes(file_path)
    if attrs is None or not attrs & FILE_ATTRIBUTE_HIDDEN:
        return False
    new_attrs = attrs & ~FILE_ATTRIBUTE_HIDDEN
    try:
        ok = ctypes.windll.kernel32.SetFileAttributesW(str(file_path), new_attrs or FILE_ATTRIBUTE_NORMAL)
    except Exception:
        return False
    return bool(ok) and not is_hidden(file_path)
