#!/usr/bin/env python3
"""
Simple SYN port scanner (Scapy)

Notes:
- Requires Npcap on Windows (WinPcap compatibility mode).
- Run as Administrator.
- Use a real LAN IP (e.g. 10.27.93.202), not 127.0.0.1.
"""

from scapy.all import IP, TCP, sr1, conf
import time
import sys

conf.verb = 0  # quiet Scapy

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]

def auto_set_interface(target):
    """Try to pick the outgoing interface name Scapy will use to reach target."""
    try:
        iface_name = conf.route.route(target)[0]  # returns (iface_name, gw, addr)
        if iface_name:
            conf.iface = iface_name
            return iface_name
    except Exception:
        pass
    return None

def scan_port(target, port, timeout=1):
    """Send a SYN and interpret the response. Returns (port, status)."""
    pkt = IP(dst=target) / TCP(dport=port, flags="S")
    try:
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except Exception as e:
        return (port, f"error: {e}")

    if resp is None:
        return (port, 'filtered/no response')
    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags == 0x12:  # SYN-ACK -> open
            # send RST to close
            try:
                sr1(IP(dst=target)/TCP(dport=port, flags='R'), timeout=1, verbose=0)
            except Exception:
                pass
            return (port, 'open')
        elif flags == 0x14:  # RST-ACK -> closed
            return (port, 'closed')
    return (port, 'unknown')

def port_scanner(target, ports):
    print(f"\nScanning target: {target}\n")
    iface = auto_set_interface(target)
    if iface:
        print(f"Using interface: {iface}\n")
    else:
        print("Warning: couldn't auto-select interface. If you see interface errors, set conf.iface manually.\n")

    open_ports = []
    for port in ports:
        port, status = scan_port(target, port)
        if status == 'open':
            print(f"[+] Port {port:5} : OPEN")
            open_ports.append(port)
        elif status == 'closed':
            print(f"[-] Port {port:5} : closed")
        elif status.startswith('error:'):
            print(f"[!] Port {port:5} : {status}")
        else:
            print(f"[?] Port {port:5} : {status}")
        time.sleep(0.05)  # small delay

    print("\n--- Summary ---")
    if open_ports:
        for p in open_ports:
            print(f" - {p} OPEN")
    else:
        print("No open ports found (in the tested list).")

if __name__ == "__main__":
    try:
        target = input("Enter target IP (e.g. 10.27.93.202): ").strip()
        if not target:
            print("No target provided. Exiting.")
            sys.exit(1)
        ports = COMMON_PORTS
        port_scanner(target, ports)
    except KeyboardInterrupt:
        print("\nUser aborted.")
        sys.exit(0)
