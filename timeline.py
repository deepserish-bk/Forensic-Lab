from datetime import datetime

def parse_timestamp(val):
    try:
        return datetime.strptime(val,"%Y-%m-%d %H:%M:%S")
    except:
        return None
