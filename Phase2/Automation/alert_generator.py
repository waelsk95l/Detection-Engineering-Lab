from log_parser import load_logs
from detection_engine import detect_lsass_access

log = load_logs("../Case9_LSASS_Access_Detection/sample-log.json")

if detect_lsass_access(log):
    print("[ALERT] Suspicious LSASS access detected!")
else:
    print("[OK] No suspicious activity.")
