"""
Run this once (as Administrator) to unblock any IPs that are now
in the expanded trusted whitelist but were previously blocked.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threat_intel import ThreatIntelFeed
from response_engine import ResponseEngine

ti = ThreatIntelFeed()
re = ResponseEngine(mode="live")

print(f"Currently blocked IPs: {len(re.blocked_ips)}")
print()

to_unblock = []
for ip in list(re.blocked_ips):
    trusted, reason = ti.is_trusted(ip)
    if trusted:
        to_unblock.append((ip, reason))

print(f"IPs to unblock (now trusted): {len(to_unblock)}")
for ip, reason in to_unblock:
    print(f"  Unblocking {ip} — {reason}")
    result = re.unblock(ip)
    print(f"    → {result['message']}")

print()
print(f"Remaining blocked IPs: {len(re.blocked_ips)}")
print("Done.")
