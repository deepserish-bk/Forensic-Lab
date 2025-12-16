import hashlib
from datetime import datetime

def calculate_hash(file_path, algorithm="sha256"):
    """Calculate hash of a file using specified algorithm"""
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def format_timestamp(ts):
    """Format Unix timestamp to readable string"""
    if ts:
        try:
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            return str(ts)
    return "N/A"
