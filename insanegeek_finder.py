import requests
import urllib3
import sys
import os
import re
from urllib.parse import urljoin
from colorama import Fore, Style, init

# Initialize colorama for Windows support
init()

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Banner
def print_banner():
    print(Fore.RED + "[+] Insanefinder - Insanegeek Framework" + Style.RESET_ALL)

# Handle request with error handling
def request_url(url, headers={}):
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL)
        return None

# Get server information
def check_server_info(url):
    response = request_url(url)
    if response:
        server = response.headers.get("Server", "Unknown")
        powered_by = response.headers.get("X-Powered-By", "Unknown")
        print(Fore.GREEN + f"[+] Server: {server}, X-Powered-By: {powered_by}" + Style.RESET_ALL)
        if "wordpress" in response.text.lower():
            print(Fore.YELLOW + "[!] WordPress Detected!" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[+] Not a WordPress site." + Style.RESET_ALL)

# Check for robots.txt
def check_robots_txt(url):
    robots_url = urljoin(url, "/robots.txt")
    response = request_url(robots_url)
    if response and response.status_code == 200:
        print(Fore.YELLOW + "[!] robots.txt found" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] robots.txt not found." + Style.RESET_ALL)

# Check for clickjacking
def check_clickjacking(url):
    response = request_url(url)
    if response and 'X-Frame-Options' not in response.headers:
        print(Fore.RED + "[!] Vulnerable to Clickjacking!" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] Not vulnerable to Clickjacking." + Style.RESET_ALL)

# Check for host header injection
def check_host_header_injection(url):
    headers = {"Host": "evil.com"}
    response = request_url(url, headers)
    if response and "evil.com" in response.text:
        print(Fore.RED + "[!] Host Header Injection possible!" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] Not vulnerable to Host Header Injection." + Style.RESET_ALL)

# Check CORS policy
def check_cors(url):
    headers = {"Origin": "https://evil.com"}
    response = request_url(url, headers)
    if response and "Access-Control-Allow-Origin" in response.headers:
        print(Fore.RED + "[!] CORS misconfiguration detected!" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] No CORS misconfiguration detected." + Style.RESET_ALL)

# Check insecure HTTP methods
def check_http_methods(url):
    methods = ["OPTIONS", "TRACE", "DELETE", "PUT"]
    vulnerable = False
    for method in methods:
        response = requests.request(method, url, verify=False)
        if response.status_code < 405:
            print(Fore.RED + f"[!] {method} is enabled! Potential risk!" + Style.RESET_ALL)
            vulnerable = True
    if not vulnerable:
        print(Fore.GREEN + "[+] No insecure HTTP methods enabled." + Style.RESET_ALL)

# Check open redirect
def check_open_redirect(url):
    test_url = url + "/?next=http://evil.com"
    response = request_url(test_url)
    if response and "http://evil.com" in response.headers.get("Location", ""):
        print(Fore.RED + "[!] Open Redirect detected!" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] No Open Redirect detected." + Style.RESET_ALL)

# Check missing security headers
def check_security_headers(url):
    response = request_url(url)
    headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
    if response:
        for header in headers:
            if header not in response.headers:
                print(Fore.RED + f"[!] Missing security header: {header}" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + f"[+] Security header present: {header}" + Style.RESET_ALL)

# Check directory listing
def check_directory_listing(url):
    response = request_url(url)
    if response and re.search(r'<title>Index of', response.text, re.IGNORECASE):
        print(Fore.RED + "[!] Directory Listing Enabled!" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[+] Directory Listing not enabled." + Style.RESET_ALL)

# Main function
def main():
    print_banner()
    urls = []
    user_input = input("Enter target URL or path to file with URLs: ")
    if os.path.isfile(user_input):
        with open(user_input, 'r') as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
    else:
        urls.append(user_input)
    
    for url in urls:
        print(Fore.BLUE + f"[+] Scanning {url}..." + Style.RESET_ALL)
        check_server_info(url)
        check_robots_txt(url)
        check_clickjacking(url)
        check_host_header_injection(url)
        check_cors(url)
        check_http_methods(url)
        check_open_redirect(url)
        check_security_headers(url)
        check_directory_listing(url)
        print(Fore.GREEN + f"[+] Scan completed for {url}\n" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
