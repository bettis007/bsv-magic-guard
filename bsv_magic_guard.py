#!/usr/bin/env python3
"""
bsv_magic_guard.py

Monitors BOTH IPv4 and IPv6 TCP traffic on Bitcoin SV's P2P port (8333),
and immediately drops any connection that:
  1) Does NOT begin with the correct 4-byte "BSV magic" (E8 F3 E1 E3), OR
  2) Does NOT contain exactly "/Bitcoin SV:1.1.0/" or "/Bitcoin SV:1.0.16/"
     within the first 160 bytes (to catch the version banner in full).

Any offending IP (v4 or v6) is instantly banished via iptables/ip6tables DROP.
We whitelist one IPv4 (10.1.0.7) and one IPv6 (2600:1900:4000:ebb2:0:5::).
"""

import subprocess
import threading
import logging
import sys
import json
import time
from typing import Tuple

from scapy.all import sniff, IP, IPv6, TCP, Raw

# ────── CONFIG ──────────────────────────────────────────────────────────────────

NETWORK_INTERFACE = "ens3"

#: Watch only Bitcoin SV's P2P port:
CLIENT_PORT = 8333

#: Known BSV "magic" (4 bytes)
MAGIC_HEADERS = { b"\xE8\xF3\xE1\xE3" }

#: Allowed version banners
ALLOWED_SUBVERS = {
    b"/Bitcoin SV:1.1.0/",
    b"/Bitcoin SV:1.0.16/",
}

#: Number of payload bytes to scan for the version banner. 160 bytes is
#  large enough to include the entire version message in the first packet.
HEAD_CHECK_BYTES = 160


#: How often to poll ``bsv-cli`` for peer and block info (in seconds)
SYNC_CHECK_INTERVAL = 60

#: Optional datadir for bsv-cli. Leave empty string to omit.
DATADIR = ""

#: Whitelist IP v4/v6 (trusted peers)
WHITELIST_V4 = "10.1.0.7"
WHITELIST_V6 = "2600:1900:4000:ebb2:0:5::"


LOGFILE  = "/var/log/bsv_magic_guard.log"
LOG_LEVEL = logging.INFO

# BPF: only capture TCP packets destined for port 8333, excluding our whitelisted IPs
BPF_FILTER = (
    f"(tcp and dst port {CLIENT_PORT} and not src host {WHITELIST_V4}) "
    f"or (ip6 and tcp and dst port {CLIENT_PORT} and not src host {WHITELIST_V6})"
)

# ────── GLOBAL STATE ─────────────────────────────────────────────────────────────

#: Track already-blocked addresses to avoid duplicate iptables calls
blocked = set()
state_lock = threading.Lock()

# ────── LOGGER SETUP ──────────────────────────────────────────────────────────────

logger = logging.getLogger("BSVMagicVersionGuard")
logger.setLevel(LOG_LEVEL)

fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

fh = logging.FileHandler(LOGFILE)
fh.setFormatter(fmt)
logger.addHandler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(LOG_LEVEL)
ch.setFormatter(fmt)
logger.addHandler(ch)

# ────── HELPERS ──────────────────────────────────────────────────────────────────

def is_invalid_payload(payload: bytes) -> bool:
    """
    Returns True if:
      - payload is < 4 bytes, OR
      - first 4 bytes are NOT one of our MAGIC_HEADERS, OR
      - within the first ``HEAD_CHECK_BYTES`` bytes, there is NO exact match for
        either "/Bitcoin SV:1.1.0/" or "/Bitcoin SV:1.0.16/".
    """
    # 1) Must be at least 4 bytes
    if len(payload) < 4:
        return True

    # 2) First 4 bytes must match a known BSV magic header
    if payload[:4] not in MAGIC_HEADERS:
        return True

    # 3) Within the first HEAD_CHECK_BYTES, must find an allowed version banner
    head = payload[:HEAD_CHECK_BYTES]
    for sv in ALLOWED_SUBVERS:
        if sv in head:
            return False

    # If none of the allowed banners are found, it's invalid
    return True

def install_block(src_addr: str, dst_port: int, is_ipv6: bool):
    """
    Add a DROP rule (iptables for v4, ip6tables for v6), but only if not yet installed.
    Uses "-C" to check for duplication first.
    """
    key = (src_addr, dst_port, is_ipv6)
    with state_lock:
        if key in blocked:
            return
        blocked.add(key)
        logger.warning(f"🔒 Blocking {src_addr} → port {dst_port} ({'v6' if is_ipv6 else 'v4'}) due to invalid payload")

    table_cmd = "ip6tables" if is_ipv6 else "iptables"
    base = [
        table_cmd,
        "-A", "INPUT",
        "-s", src_addr,
        "-p", "tcp",
        "--dport", str(dst_port),
        "-j", "DROP"
    ]

    # 1) Check for an existing identical rule
    check = base.copy()
    check[1] = "-C"
    try:
        subprocess.check_call(check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info(f"↪ Already blocked {src_addr} → {dst_port}. Skipping additional rule.")
        return
    except subprocess.CalledProcessError:
        # -C returned nonzero ⇒ rule not found ⇒ proceed to append
        pass

    # 2) Append the DROP rule
    try:
        subprocess.check_call(base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info(f"✅ Successfully blocked {src_addr} → {dst_port}")
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to run {table_cmd} for {src_addr}:{dst_port}: {e}")


def _parse_peer_ip(addr: str) -> Tuple[str, bool]:
    """Return (ip, is_ipv6) parsed from getpeerinfo's addr field."""
    if addr.startswith('['):
        ip = addr[1:addr.index(']')]
    else:
        ip = addr.rsplit(':', 1)[0]
    is_v6 = ':' in ip
    return ip, is_v6


def check_peer_sync():
    """Poll ``bsv-cli`` and block peers that are behind the local node."""
    base_cmd = ['bsv-cli']
    if DATADIR:
        base_cmd.extend(['-datadir', DATADIR])

    peer_cmd = base_cmd + ['getpeerinfo']
    height_cmd = base_cmd + ['getblockcount']

    while True:
        try:
            local_height = int(subprocess.check_output(height_cmd, text=True).strip())
        except Exception as e:
            logger.error(f"Failed to get block height: {e}")
            time.sleep(SYNC_CHECK_INTERVAL)
            continue

        try:
            output = subprocess.check_output(peer_cmd, text=True)
            peers = json.loads(output)
        except Exception as e:
            logger.error(f"Failed to run bsv-cli: {e}")
            time.sleep(SYNC_CHECK_INTERVAL)
            continue

        for p in peers:
            addr = p.get('addr')
            if not addr:
                continue
            ip, is_v6 = _parse_peer_ip(addr)
            if ip in (WHITELIST_V4, WHITELIST_V6):
                continue

            headers = p.get('synced_headers')
            blocks = p.get('synced_blocks')
            if (
                headers is None or blocks is None or
                headers < local_height or blocks < local_height
            ):
                install_block(ip, CLIENT_PORT, is_v6)

        time.sleep(SYNC_CHECK_INTERVAL)

# ────── PACKET HANDLER / SNIFF LOOP ────────────────────────────────────────────────

def packet_callback(pkt):
    """
    Called for each sniffed packet (BPF ensures only v4-TCP or v6-TCP destined for port 8333).
    We check whether it's IPv4 or IPv6, extract src → dst_port, then test the magic + version.

    """
    # ─── IPv4 path ─────────────────────────────────────────────────────────────────
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        src = pkt[IP].src
        dport = pkt[TCP].dport
        key = (src, dport, False)

        # Skip our IPv4 whitelist
        if src == WHITELIST_V4:
            return

        with state_lock:
            if key in blocked:
                return

        payload = bytes(pkt[Raw].load)
        if is_invalid_payload(payload):
            snippet = payload[:32].decode("utf-8", "ignore").replace("\n", "\\n").replace("\r", "\\r")
            logger.info(f"🔥 Invalid payload from {src}:{dport} (v4) \u2192 \"{snippet}\" ; auto-blocking.")
            install_block(src, dport, False)

        return

    # ─── IPv6 path ─────────────────────────────────────────────────────────────────
    if pkt.haslayer(IPv6) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        src6 = pkt[IPv6].src
        dport = pkt[TCP].dport
        key6 = (src6, dport, True)

        # Skip our IPv6 whitelist
        if src6 == WHITELIST_V6:
            return

        with state_lock:
            if key6 in blocked:
                return

        payload = bytes(pkt[Raw].load)
        if is_invalid_payload(payload):
            snippet = payload[:32].decode("utf-8", "ignore").replace("\n", "\\n").replace("\r", "\\r")
            logger.info(f"🔥 Invalid payload from {src6}:{dport} (v6) \u2192 \"{snippet}\" ; auto-blocking.")
            install_block(src6, dport, True)

def main():
    logger.info(
        f"Starting BSV Magic+Version Guard on {NETWORK_INTERFACE}, port={CLIENT_PORT}, "
        f"v4-whitelist={WHITELIST_V4}, v6-whitelist={WHITELIST_V6}"
    )

    # Start background thread to enforce sync status
    sync_thread = threading.Thread(target=check_peer_sync, daemon=True)
    sync_thread.start()

    # Ensure SSH remains unblocked:
    # - sudo iptables  -I INPUT 1 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    # - sudo iptables  -I INPUT 2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    # - sudo ip6tables -I INPUT 1 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    # - sudo ip6tables -I INPUT 2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    try:
        sniff(
            iface   = NETWORK_INTERFACE,
            prn     = packet_callback,
            store   = 0,
            filter  = BPF_FILTER
        )
    except PermissionError:
        logger.error("Permission denied: run as root (sudo).")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
