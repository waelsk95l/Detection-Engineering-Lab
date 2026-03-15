def detect_lsass_access(log):
    if "lsass.exe" in log.get("TargetImage", "").lower():
        if log.get("GrantedAccess") in ["0x1fffff", "0x1010", "0x1410"]:
            return True
    return False
