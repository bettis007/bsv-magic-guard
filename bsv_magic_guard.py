#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bsv_magic_guard.py

Monitors BOTH IPv4 and IPv6 TCP traffic on Bitcoin SV's P2P port (8333),
and immediately drops any connection that:
  1) Does NOT begin with the correct 4-byte "BSV magic" (E8 F3 E1 E3), OR
  2) Does NOT contain exactly "/Bitcoin SV:1.1.0/" or "/Bitcoin SV:1.0.16/"
     within the first 160 bytes.

Also polls your node via RPC:
  - Blocks & disconnects any peer whose synced_headers OR synced_blocks
    are below your local block height.

Whitelist: IPv4 10.1.0.7 and IPv6 2600:1900:4000:ebb2:0:5::.
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess

import requests
from requests.auth import HTTPBasicAuth
from typing import Tuple
from scapy.all import sniff, IP, IPv6, TCP, Raw

# ────── CONFIG ──────────────────────────────────────────────────────────────────

NETWORK_INTERFACE   = "ens3"
CLIENT_PORT         = 5333

MAGIC_HEADERS       = { b"\xE8\xF3\xE1\xE3" }
ALLOWED_SUBVERS     = { b"/Bitcoin SV:1.1.0/", b"/Bitcoin SV:1.0.16/" }
HEAD_CHECK_BYTES    = 160

SYNC_CHECK_INTERVAL = 10  # seconds
PING_THRESHOLD      = 0.3  # seconds; peers slower than this get the boot

# RPC connection to your bsvd
RPC_USER     = "bsv"
RPC_PASSWORD = "kctwU11SFGYCBgJZc77Kc2DbyuBF5bvZ"
RPC_HOST     = "127.0.0.1"
RPC_PORT     = 5332
RPC_URL      = f"http://{RPC_HOST}:{RPC_PORT}/"

WHITELIST_V4 = "10.1.0.7"
WHITELIST_V6 = "2600:1900:4000:ebb2:0:5::"

LOGFILE   = "/var/log/bsv_magic_guard.log"
LOG_LEVEL = logging.INFO

BPF_FILTER = (
    f"(tcp and dst port {CLIENT_PORT} and not src host {WHITELIST_V4}) "
    f"or (ip6 and tcp and dst port {CLIENT_PORT} and not src host {WHITELIST_V6})"
)

blocked    = set()
state_lock = threading.Lock()

# ────── LOGGER SETUP ──────────────────────────────────────────────────────────────

logger = logging.getLogger("BSVMagicGuard")
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

def is_invalid_payload(data: bytes) -> bool:
    if len(data) < 4 or data[:4] not in MAGIC_HEADERS:
        return True
    head = data[:HEAD_CHECK_BYTES]
    return not any(sv in head for sv in ALLOWED_SUBVERS)

def install_block(src: str, port: int, ipv6: bool):
    key = (src, port, ipv6)
    with state_lock:
        if key in blocked:
            return
        blocked.add(key)
        logger.warning(f"🔒 Blocking {src} → port {port} ({'v6' if ipv6 else 'v4'})")

    table = "ip6tables" if ipv6 else "iptables"
    rule  = [table, "-A", "INPUT", "-s", src, "-p", "tcp", "--dport", str(port), "-j", "DROP"]
    check = rule.copy(); check[1] = "-C"
    try:
        subprocess.check_call(check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return  # already in place
    except subprocess.CalledProcessError:
        pass

    try:
        subprocess.check_call(rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info(f"✅ Drop rule added for {src}:{port}")
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to add drop rule: {e}")

def _parse_peer_ip(addr: str) -> Tuple[str, bool]:
    if addr.startswith("["):
        ip = addr[1:addr.index("]")]
    else:
        ip = addr.rsplit(":", 1)[0]
    return ip, ":" in ip

def rpc_request(method: str, params=None):
    payload = {
        "jsonrpc": "1.0",
        "id": "bsv_magic_guard",
        "method": method,
        "params": params or []
    }
    try:
        r = requests.post(RPC_URL,
                          auth=HTTPBasicAuth(RPC_USER, RPC_PASSWORD),
                          headers={"Content-Type": "application/json"},
                          json=payload, timeout=10)
        r.raise_for_status()
        res = r.json()
        if res.get("error"):
            raise RuntimeError(res["error"])
        return res["result"]
    except Exception as e:
        logger.error(f"RPC `{method}` failed: {e}")
        return None


def check_peer_sync():
    """Every SYNC_CHECK_INTERVAL, block & disconnect any lagging or slow peers."""
    while True:
        local_h = rpc_request("getblockcount")
        if local_h is None:
            time.sleep(SYNC_CHECK_INTERVAL)
            continue

        peers = rpc_request("getpeerinfo")
        if not isinstance(peers, list):
            time.sleep(SYNC_CHECK_INTERVAL)
            continue

        for p in peers:
            addr = p.get("addr")
            if not addr:
                continue
            ip, ipv6 = _parse_peer_ip(addr)
            if ip in (WHITELIST_V4, WHITELIST_V6):
                continue

            # ─── NEW: Latency check ─────────────────────
            ping = p.get("pingtime")
            if ping is not None and ping > PING_THRESHOLD:
                logger.info(f"🐢 Slow peer {addr} ping={ping:.3f}s > {PING_THRESHOLD}s, blocking…")
                install_block(ip, CLIENT_PORT, ipv6)
                rpc_request("disconnectnode", [addr])
                continue
            # ───────────────────────────────────────────────

            hdrs = p.get("synced_headers")
            blks = p.get("synced_blocks")
            if hdrs is None or blks is None or hdrs < local_h or blks < local_h:
                logger.info(f"🚫 Unsynced peer {addr} ({hdrs}/{blks} < {local_h}), dropping…")
                install_block(ip, CLIENT_PORT, ipv6)
                rpc_request("disconnectnode", [addr])

        time.sleep(SYNC_CHECK_INTERVAL)

# ────── PACKET HANDLER & SNIFF LOOP ───────────────────────────────────────────────

def packet_callback(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        src, dport = pkt[IP].src, pkt[TCP].dport
        if src != WHITELIST_V4 and (src, dport, False) not in blocked:
            data = bytes(pkt[Raw].load)
            if is_invalid_payload(data):
                snippet = data[:32].decode("utf-8","ignore").replace("\n","\\n")
                logger.info(f"🔥 Bad v4 payload from {src}:{dport}: “{snippet}”")
                install_block(src, dport, False)
        return

    if pkt.haslayer(IPv6) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        src6, dport = pkt[IPv6].src, pkt[TCP].dport
        if src6 != WHITELIST_V6 and (src6, dport, True) not in blocked:
            data = bytes(pkt[Raw].load)
            if is_invalid_payload(data):
                snippet = data[:32].decode("utf-8","ignore").replace("\n","\\n")
                logger.info(f"🔥 Bad v6 payload from {src6}:{dport}: “{snippet}”")
                install_block(src6, dport, True)


def main():
    logger.info(f"Starting BSV Magic Guard on {NETWORK_INTERFACE}:{CLIENT_PORT}  "
                f"whitelists v4={WHITELIST_V4}, v6={WHITELIST_V6}")
    threading.Thread(target=check_peer_sync, daemon=True).start()

    try:
        sniff(iface=NETWORK_INTERFACE, prn=packet_callback, store=0, filter=BPF_FILTER)
    except PermissionError:
        logger.error("Permission denied: run as root."); sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted. Exiting.");   sys.exit(0)

if __name__ == "__main__":
    main()
