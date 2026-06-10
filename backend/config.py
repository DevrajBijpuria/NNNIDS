import os

CAPTURE_MODE      = os.getenv("NNNIDS_CAPTURE_MODE", "live")
RESPONSE_MODE     = os.getenv("NNNIDS_RESPONSE_MODE", "live")

CAPTURE_INTERFACE = os.getenv(
    "NNNIDS_INTERFACE",
    r"\Device\NPF_{94C4A30E-2F09-423C-B2BF-D1BCB2FDD6B0}"
)

MONITOR_WINDOW    = int(os.getenv("NNNIDS_MONITOR_WINDOW", "10"))
MONITOR_INTERVAL  = float(os.getenv("NNNIDS_MONITOR_INTERVAL", "2"))
AUTO_START        = os.getenv("NNNIDS_AUTO_START", "true").lower() == "true"
