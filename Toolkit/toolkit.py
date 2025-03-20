#!/usr/bin/env python3
"""
Penetration Testing Toolkit
============================

This toolkit contains three modules:

1. Port Scanner
   - Scans a specified range of ports.
   - Supports “silent” mode (minimal output) or “noisy” mode (detailed logging).
   - Prints service names (where available) for open ports.
2. Brute Forcer
   - Supports brute forcing login credentials for SSH, FTP, and SFTP.
   - Uses multi-threading to speed up attempts.
   - Similar in function to Hydra.
3. Directory Enumerator
   - Enumerates directories on a given web server URL using a wordlist.
   - Multi-threaded to perform fast enumeration.

**Usage Example:**

    python pen_toolkit.py --module portscan --target 192.168.1.1 --start 20 --end 1024 --mode noisy --threads 50

    python pen_toolkit.py --module brute --protocol ssh --target 192.168.1.1 --port 22 \
           --user admin --userlist users.txt --passlist passwords.txt --threads 10

    python pen_toolkit.py --module enum --url http://example.com --wordlist directories.txt --threads 20

**Note:** Dependencies:
    - For SSH and SFTP brute forcing: Install paramiko (`pip install paramiko`)
    - For FTP brute forcing: Uses built-in ftplib.
    - For directory enumeration: Uses requests (`pip install requests`)

Remember, use this toolkit only for ethical and authorized security testing.

"""

import argparse
import socket
import threading
import queue


try:
    import paramiko  # for SSH and SFTP
except ImportError:
    paramiko = None

import ftplib 
import requests 

# --------------------------------------------
# Helper: Service lookup (simple version)
# --------------------------------------------
def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


# --------------------------------------------
# Module 1: Multi-threaded Port Scanner
# --------------------------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, mode="silent", threads=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.mode = mode.lower()
        self.threads = threads
        self.open_ports = []
        self.port_queue = queue.Queue()

    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = get_service_name(port)
                self.open_ports.append((port, service))
                if self.mode == "noisy":
                    print(f"[OPEN] Port {port} ({service}) is open.")
            elif self.mode == "noisy":
                print(f"[CLOSED] Port {port} is closed.")
            s.close()
        except Exception as e:
            if self.mode == "noisy":
                print(f"[ERROR] Scanning port {port}: {e}")

    def worker(self):
        while not self.port_queue.empty():
            port = self.port_queue.get()
            self.scan_port(port)
            self.port_queue.task_done()

    def run(self):
        print(f"Starting port scan on {self.target} from {self.start_port} to {self.end_port}")
        for port in range(self.start_port, self.end_port + 1):
            self.port_queue.put(port)

        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        self.port_queue.join()
        print("Port scanning complete. Open ports:")
        for port, service in sorted(self.open_ports):
            print(f"Port {port}: Service {service}")


class BruteForcer:
    def __init__(self, protocol, target, port, username, userlist, passlist, threads=10):
        self.protocol = protocol.lower()
        self.target = target
        self.port = port
        self.username = username  
        self.userlist = userlist  
        self.passlist = passlist
        self.threads = threads
        self.queue = queue.Queue()
        self.found_credentials = []

    def load_credentials(self):
        passwords = []
        usernames = []
        if self.passlist:
            with open(self.passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        if self.userlist:
            with open(self.userlist, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
        else:
            usernames = [self.username]
        
        for user in usernames:
            for pwd in passwords:
                self.queue.put((user, pwd))

    def try_ssh(self, username, password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.target, port=self.port, username=username, password=password, timeout=3)
            client.close()
            return True
        except Exception:
            return False

    def try_ftp(self, username, password):
        try:
            ftp = ftplib.FTP(timeout=3)
            ftp.connect(self.target, self.port)
            ftp.login(username, password)
            ftp.quit()
            return True
        except Exception:
            return False

    def try_sftp(self, username, password):
        
        return self.try_ssh(username, password)

    def worker(self):
        while not self.queue.empty():
            username, password = self.queue.get()
            success = False
            if self.protocol == "ssh":
                success = self.try_ssh(username, password)
            elif self.protocol == "ftp":
                success = self.try_ftp(username, password)
            elif self.protocol == "sftp":
                success = self.try_sftp(username, password)
            else:
                print(f"Unsupported protocol: {self.protocol}")
                self.queue.task_done()
                continue
            if success:
                print(f"[SUCCESS] {self.protocol.upper()} login succeeded: {username} : {password}")
                self.found_credentials.append((username, password))
            else:
                print(f"[FAIL] {self.protocol.upper()} login failed: {username} : {password}")
            self.queue.task_done()

    def run(self):
        if self.protocol in ["ssh", "sftp"] and paramiko is None:
            print("Paramiko is required for SSH/SFTP brute forcing. Please install it (pip install paramiko).")
            return
        print(f"Starting brute force for {self.protocol.upper()} on {self.target}:{self.port}")
        self.load_credentials()
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        self.queue.join()
        if self.found_credentials:
            print("Valid credentials found:")
            for user, pwd in self.found_credentials:
                print(f"Username: {user} | Password: {pwd}")
        else:
            print("No valid credentials found.")

class DirectoryEnumerator:
    def __init__(self, url, wordlist, threads=20):
        self.url = url.rstrip('/')
        self.wordlist = wordlist  # file with directory names (one per line)
        self.threads = threads
        self.queue = queue.Queue()
        self.found_directories = []

    def load_wordlist(self):
        with open(self.wordlist, 'r') as f:
            for line in f:
                directory = line.strip()
                if directory:
                    self.queue.put(directory)

    def worker(self):
        while not self.queue.empty():
            directory = self.queue.get()
            full_url = f"{self.url}/{directory}"
            try:
                response = requests.get(full_url, timeout=3)
                if response.status_code < 400:
                    print(f"[FOUND] {full_url} - Status: {response.status_code}")
                    self.found_directories.append((full_url, response.status_code))
                else:
                    print(f"[NOT FOUND] {full_url} - Status: {response.status_code}")
            except Exception as e:
                print(f"[ERROR] Accessing {full_url}: {e}")
            self.queue.task_done()

    def run(self):
        print(f"Starting directory enumeration on {self.url}")
        self.load_wordlist()
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        self.queue.join()
        print("Directory enumeration complete. Found directories:")
        for url, status in self.found_directories:
            print(f"{url} - Status: {status}")

def main():
    parser = argparse.ArgumentParser(description="Modular Penetration Testing Toolkit")
    subparsers = parser.add_subparsers(dest="module", help="Module to run")

    parser_port = subparsers.add_parser("portscan", help="Run port scanner")
    parser_port.add_argument("--target", required=True, help="Target IP address")
    parser_port.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser_port.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser_port.add_argument("--mode", choices=["silent", "noisy"], default="silent", help="Scan mode")
    parser_port.add_argument("--threads", type=int, default=100, help="Number of threads to use")

    parser_brute = subparsers.add_parser("brute", help="Run brute forcer")
    parser_brute.add_argument("--protocol", required=True, choices=["ssh", "ftp", "sftp"], help="Protocol to brute force")
    parser_brute.add_argument("--target", required=True, help="Target IP address")
    parser_brute.add_argument("--port", type=int, required=True, help="Target port")
    parser_brute.add_argument("--user", default="", help="Single username (if not using userlist)")
    parser_brute.add_argument("--userlist", help="File containing list of usernames")
    parser_brute.add_argument("--passlist", required=True, help="File containing list of passwords")
    parser_brute.add_argument("--threads", type=int, default=10, help="Number of threads to use")

    parser_enum = subparsers.add_parser("enum", help="Run directory enumerator")
    parser_enum.add_argument("--url", required=True, help="Target URL (e.g., http://example.com)")
    parser_enum.add_argument("--wordlist", required=True, help="File containing directory names to check")
    parser_enum.add_argument("--threads", type=int, default=20, help="Number of threads to use")

    args = parser.parse_args()

    if args.module == "portscan":
        scanner = PortScanner(args.target, args.start, args.end, args.mode, args.threads)
        scanner.run()
    elif args.module == "brute":
        brute = BruteForcer(
            protocol=args.protocol,
            target=args.target,
            port=args.port,
            username=args.user,
            userlist=args.userlist,
            passlist=args.passlist,
            threads=args.threads
        )
        brute.run()
    elif args.module == "enum":
        enumerator = DirectoryEnumerator(args.url, args.wordlist, args.threads)
        enumerator.run()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
