import hashlib
from datetime import datetime

def calculate_hash(file_path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with open(file_path,"rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def format_timestamp(ts):
    if ts:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    return "N/A"
