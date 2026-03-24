This a simple Python reconnaisance automation tool created as a learning project while studying basic cybersecurity concepts and Python scripting. It is designed to perform a threaded scan for open ports in a selected range, passive banner grabbing on open ports and a check for common security headers.

This tool is created for educational purposes only. Only scan systems you own or have explicit permission to scan.

Project goals:

This project was created to practice:

- Python scripting
- Network programming with sockets
- Concurrent execution using ThreadPoolExecutor
- Command-line interface design with argparse
- Building small security tools

Installation:

1. Clone the repository
2. Install depencencies:
pip install -r requirements.txt

Python 3.8+ recommended

Usage:

Example input:

Basic scan:

python recon.py scanme.nmap.org

Scan with additional options:

python recon.py scanme.nmap.org --mode well-known --workers 200 --timeout 0.3 --output scan_report.txt

Disable banner grabbing:

python recon.py scanme.nmap.org --no-banners

Disable header checks:

python recon.py scanme.nmap.org --no-headers

Save results to a report:

python recon.py scanme.nmap.org --output report.txt

Example output:

Target: scanme.nmap.org
Scan mode: well-known
IP address: 45.33.32.156

Open ports:
21
22
25
80
110
119
143
465
563
587
993
995

Banner grabbing:
Port 21: No banner
Port 22: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
Port 25: No banner
Port 80: No banner
Port 110: No banner
Port 119: No banner
Port 143: No banner
Port 465: No banner
Port 563: No banner
Port 993: No banner
Port 995: No banner

Security headers check:
[-] Content-Security-Policy: Missing
[-] X-Frame-Options: Missing
[-] Strict-Transport-Security: Missing
[-] X-Content-Type-Options: Missing






