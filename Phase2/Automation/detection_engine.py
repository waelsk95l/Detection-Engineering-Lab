def detect_lsass_access(event: dict) -> bool:
    target = str(event.get("TargetImage", "")).lower()
    granted = str(event.get("GrantedAccess", "")).lower()

    suspicious_masks = {"0x1fffff", "0x1010", "0x1410"}

    return "lsass.exe" in target and granted in suspicious_masks
