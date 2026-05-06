# Python-Based Adaptive Host Firewall

## Project Description

This project is a Python-based adaptive host firewall that detects suspicious TCP scanning activity using Scapy and dynamically updates iptables rules to block attackers. The firewall monitors incoming TCP packets, identifies suspicious scan patterns, and automatically blocks attacker IP addresses.

The project was tested in a lab environment using Kali Linux and Metasploitable3.

---

## Features

* TCP packet sniffing
* NULL scan detection
* FIN scan detection
* XMAS scan detection
* SYN scan monitoring
* Dynamic attacker blocking using iptables
* Real-time packet monitoring
* Tested on Metasploitable3

---

## Technologies Used

* Python
* Scapy
* iptables
* Kali Linux
* Metasploitable3
* Nmap

---

## Architecture


Nmap Scanner
      ↓
Scapy Packet Sniffer
      ↓
Python Detection Engine
      ↓
iptables Rule Update
      ↓
Attacker Blocked


---

## Setup Instructions

### 1. Install Scapy


sudo apt-get install python-scapy


---

### 2. Configure iptables

Flush existing rules:

 
sudo iptables -F
 

Set default INPUT policy:

 
sudo iptables -P INPUT DROP
 

Allow established connections:


sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
 

Allow SSH access:

 
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
 

(Optional) Allow HTTP traffic:

 
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
 

---

### 3. Run the Firewall

 
sudo python pythonbasedfirewall.py
 

---

## Testing

The firewall was tested using Nmap scans from Kali Linux.

Example scans:

 
nmap -sS <target-ip>
nmap -sN <target-ip>
nmap -sF <target-ip>
nmap -sX <target-ip>
 

The firewall detects suspicious scanning behavior and dynamically blocks the attacker IP using iptables rules.

---

## Future Improvements

* UDP scan detection
* Logging system
* Temporary blacklist timers
* GUI dashboard
* Advanced anomaly detection
* Multi-threaded packet processing

---

## Disclaimer

This project was developed for educational and defensive cybersecurity learning purposes in a controlled lab environment.

 
