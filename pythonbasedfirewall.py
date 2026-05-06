
# SIMPLE ADAPTIVE FIREWALL
# PURPOSE:
# 1. Capture TCP packets using Scapy
# 2. Detect simple port scanning
# 3. Detect NULL / FIN / XMAS scans
# 4. Dynamically block attacker IP using iptables
# Python 2 compatible version
# IMPORTS
from scapy.all import *
import os


# ============================================================
# DATA STORAGE
# ============================================================

# Dictionary:
# Stores which ports each IP touched
#
# Example:
# {
#   "192.168.1.10": [22, 80, 443]
# }
#
scan_tracker = {}


# List:
# Stores blocked IPs
#
# Example:
# [
#   "192.168.1.10",
#   "192.168.1.20"
# ]
#
blacklist = []


# ============================================================
# SETTINGS
# ============================================================

# Maximum number of ports before considered scanning
PORT_LIMIT = 5


# ============================================================
# BLOCK FUNCTION
# ============================================================

def block_ip(ip):

    # Avoid duplicate blocking
    if ip in blacklist:
        return

    print "[BLOCKED] " + ip

    # Add DROP rule to iptables
    os.system(
        "iptables -A INPUT -s " + ip + " -j DROP"
    )

    # Save blocked IP
    blacklist.append(ip)


# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================

def detect(pkt):

    # --------------------------------------------------------
    # Ensure packet contains IP layer
    # --------------------------------------------------------

    if not pkt.haslayer(IP):
        return


    # --------------------------------------------------------
    # Ensure packet contains TCP layer
    # --------------------------------------------------------

    if not pkt.haslayer(TCP):
        return


    # --------------------------------------------------------
    # Extract packet information
    # --------------------------------------------------------

    src_ip = pkt[IP].src

    dst_port = pkt[TCP].dport

    flags = pkt[TCP].flags


    # --------------------------------------------------------
    # Ignore already blocked IPs
    # --------------------------------------------------------

    if src_ip in blacklist:
        return


    # --------------------------------------------------------
    # Print packet information
    # --------------------------------------------------------

    print src_ip + " -> Port " + str(dst_port)


    # ========================================================
    # NULL SCAN DETECTION
    # ========================================================
    #
    # Nmap:
    # nmap -sN
    #
    # flags == 0
    #
    # ========================================================

    if flags == 0:

        print "[NULL SCAN DETECTED] " + src_ip

        block_ip(src_ip)

        return


    # ========================================================
    # FIN SCAN DETECTION
    # ========================================================
    #
    # Nmap:
    # nmap -sF
    #
    # FIN = 1
    #
    # ========================================================

    if flags == 1:

        print "[FIN SCAN DETECTED] " + src_ip

        block_ip(src_ip)

        return


    # ========================================================
    # XMAS SCAN DETECTION
    # ========================================================
    #
    # Nmap:
    # nmap -sX
    #
    # FIN + PSH + URG = 41
    #
    # ========================================================

    if flags == 41:

        print "[XMAS SCAN DETECTED] " + src_ip

        block_ip(src_ip)

        return


    # ========================================================
    # SYN SCAN / PORT SCAN TRACKING
    # ========================================================
    #
    # SYN flag = 2
    #
    # Nmap:
    # nmap -sS
    #
    # ========================================================

    if flags == 2:

        # ----------------------------------------------------
        # Create new list for new IP
        # ----------------------------------------------------

        if src_ip not in scan_tracker:

            scan_tracker[src_ip] = []


        # ----------------------------------------------------
        # Save touched port
        # ----------------------------------------------------

        scan_tracker[src_ip].append(dst_port)


        # ----------------------------------------------------
        # Remove duplicate ports
        # ----------------------------------------------------

        unique_ports = []

        for port in scan_tracker[src_ip]:

            if port not in unique_ports:
                unique_ports.append(port)


        # ----------------------------------------------------
        # Print unique ports
        # ----------------------------------------------------

        print "Ports touched:", unique_ports


        # ----------------------------------------------------
        # Detect scanning behavior
        # ----------------------------------------------------

        if len(unique_ports) > PORT_LIMIT:

            print "[PORT SCAN DETECTED] " + src_ip

            block_ip(src_ip)

            return


# ============================================================
# START PACKET SNIFFER
# ============================================================

print "[*] Firewall running..."


# sniff():
#
# filter="tcp"
# Capture only TCP traffic
#
# prn=detect
# Send each packet to detect()
#
# store=0
# Do not store packets in RAM
#
sniff(
    filter="tcp",
    prn=detect,
    store=0
)
