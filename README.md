# Mini SIEM + IDS

A lightweight threat detection tool built in Python and tested in my own VM lab (Kali Linux as the attacker, Ubuntu as the victim).

## Features
- Detects Nmap SYN port scans using Scapy
- Detects SSH brute-force attacks by reading /var/log/auth.log
- Automatically blocks the attacker's IP using iptables
- Live Flask dashboard showing total events, blocked IPs, top attackers and recent events

## Tech
Python, Scapy, Flask, iptables, Linux, Kali Linux, Nmap

## How it works
1. `scan_detector.py` sniffs TCP SYN packets and alerts when one IP hits many ports in a short time
2. `siem.py` watches failed SSH logins, saves events to `alerts.log` and blocks the attacker
3. `dashboard.py` reads `alerts.log` and shows it on a web page

## Lab setup
- Attacker: Kali Linux VM
- Victim: Ubuntu VM running the detector
- Both VMs on the same network

## Run
```
sudo apt install python3-scapy python3-flask
sudo python3 scan_detector.py
sudo python3 siem.py
python3 dashboard.py
```
Then open http://127.0.0.1:5000 in a browser.

## Screenshots
(add the dashboard image here)

## What I learned
(write 2 or 3 lines in your own words)

## Disclaimer
Built for learning. Only test on machines you own.<img width="1840" height="880" alt="Screenshot From 2026-11-11 16-47-19" src="https://github.com/user-attachments/assets/65757a33-ef59-4b23-a9c7-6135b5ccccd1" />
I created the mini siem+ids using python and ssh ant the virtual mission are ubuntu and kali ,i am used as kali as attacker and ubuntu as a protect sysytem.successfully i completed the project with the help of claude

