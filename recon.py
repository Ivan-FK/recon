# Dependencies

import argparse
import socket
import requests
from concurrent.futures import ThreadPoolExecutor

# Configuration

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080]

HEADERS_TO_CHECK = [
	"Content-Security-Policy",
	"X-Frame-Options",
	"Strict-Transport-Security",
	"X-Content-Type-Options"]

DEFAULT_TIMEOUT = 0.2
DEFAULT_HTTP_TIMEOUT = 10
DEFAULT_WORKERS = 100
DEFAULT_BANNER_TIMEOUT = 2

# CLI parser

def build_parser():
	parser = argparse.ArgumentParser(description = "Simple recon automation tool")

	parser.add_argument("target", help = "Target domain to scan")

	parser.add_argument(
		"--mode",
		choices = ["common", "well-known", "registered", "full"],
		default = "common",
		help = "Port scanning mode (default: common)")
	
	parser.add_argument(
		"--timeout",
		type = float,
		default = DEFAULT_TIMEOUT,
		help = f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})"
	)

	parser.add_argument(
		"--workers",
		type = int,
		default = DEFAULT_WORKERS,
		help = f"Number of worker threads for port scanning (default: {DEFAULT_WORKERS})"

	)

	parser.add_argument(
		"--no-banners",
		action = "store_true",
		help = "Skip banner grabbing"
	)

	parser.add_argument(
		"--no-headers",
		action = "store_true",
		help = "Skip security headers check"
	)

	parser.add_argument(
		"--output",
		help = "Save results to a text report file"
	)
	
	return parser

# Range of ports to scan

def get_ports_to_scan(mode):
	if mode == "common":
		return COMMON_PORTS
	elif mode == "well-known":
		return range(1, 1024)
	elif mode == "registered":
		return range(1, 49152)
	elif mode == "full":
		return range(1, 65536)

# Domain name to IP resolution

def resolve_domain(domain):
	try:
		return socket.gethostbyname(domain)
	except socket.gaierror:
		return None

# Single port scanner

def scan_port(ip, port, timeout):	
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)

		try:
			s.connect((ip, port))
			return port
		except:
			return None
		finally:
			s.close()

# Thread pool port scanner

def scan_ports_threaded(ip, ports_to_scan, timeout, workers):
	open_ports = []

	with ThreadPoolExecutor(max_workers = workers) as executor:
		futures = [executor.submit(scan_port, ip, port, timeout) for port in ports_to_scan]

		for future in futures:
			result = future.result()
			if result is not None:
				open_ports.append(result)

	return sorted(open_ports)

# Banner grabbing

def grab_banner(ip, port, timeout = DEFAULT_BANNER_TIMEOUT):
	s = socket.socket()
	s.settimeout(timeout)

	try:
		s.connect((ip, port))	
		banner = s.recv(1024).decode(errors = "ignore").strip()

		if banner:
			return banner
		else:
			return None
		
	except:
		return None
	finally:
		s.close()

def grab_banners(ip, open_ports, timeout = DEFAULT_BANNER_TIMEOUT):
	banners = {}

	for port in open_ports:
		banner = grab_banner(ip, port, timeout)
		banners[port] = banner if banner else "No banner"
	
	return banners

# Security headers check

def check_headers(domain, timeout = DEFAULT_HTTP_TIMEOUT):
	results = {}

	urls = [f"https://{domain}", f"http://{domain}"]

	for url in urls:
		try:
			response = requests.get(url, timeout = timeout)
			break
		except requests.RequestException:
			response = None
	
	if not response:
		results["error"] = "Could not connect to web server"
		return results

	for header in HEADERS_TO_CHECK:
		if header in response.headers:
			results[header] = response.headers[header]
		else:
			results[header] = "Missing"

	return results

# Results output

def print_results(target, ip, mode, open_ports, banners = None, headers = None):
	print(f"Target: {target}")
	print(f"Scan mode: {mode}")
	print(f"IP address: {ip}")

	print("\nOpen ports:")
	if open_ports:
		for port in open_ports:
			print(port)
	else:
		print("No open ports found in selected range")

	if banners is not None:
		print("\nBanner grabbing:")
		if open_ports:
			for port in open_ports:
				print(f"Port {port}: {banners[port]}")
		else:
			print("No open ports to grab banners from")
	
	if headers is not None:
		print("\nSecurity headers check:")
		if "error" in headers:
			print(headers["error"])
		else:
			for header, value in headers.items():
				if value == "Missing":
					print(f"[-] {header}: Missing")
				else:
					print(f"[+] {header}: {value}")

def save_report(filename, target, ip, mode, open_ports, banners = None, headers = None):
	with open(filename, "w", encoding = "utf-8") as f:
		f.write("Recon report\n")
		f.write("============\n\n")

		f.write(f"Target: {target}\n")
		f.write(f"Scan mode: {mode}\n")
		f.write(f"IP address: {ip}\n\n")

		f.write("Open ports:\n")
		if open_ports:
			for port in open_ports:
				f.write(f"{port}\n")
		else:
			f.write("No open ports found in selected range\n")

		if banners is not None:
			f.write("\nBanner grabbing:\n")
			if open_ports:
				for port in open_ports:
					f.write(f"Port {port}: {banners[port]}\n")
			else:
				f.write("No open ports to grab banners from\n")

		if headers is not None:
			f.write("\nSecurity headers check:\n")
			if "error" in headers:
				f.write(headers["error"] + "\n")
			else:
				for header, value in headers.items():
					f.write(f"{header}: {value}\n")

# Main

def main():
	parser = build_parser()
	args = parser.parse_args()

	target = args.target
	mode = args.mode
	timeout = args.timeout
	workers = args.workers
	output_file = args.output
	
	ip = resolve_domain(target)

	if not ip:
		raise SystemExit("Could not resolve domain")
	
	ports_to_scan = get_ports_to_scan(mode)
	open_ports = scan_ports_threaded(ip, ports_to_scan, timeout, workers)

	banners = None
	if not args.no_banners:
		banners = grab_banners(ip, open_ports)

	headers = None
	if not args.no_headers:
		headers = check_headers(target)

	print_results(target, ip, mode, open_ports, banners, headers)

	if output_file:
		save_report(output_file, target, ip, mode, open_ports, banners, headers)
		print(f"\nReport saved to: {output_file}")	

if __name__ == "__main__":
	main()