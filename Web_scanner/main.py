import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs

session = requests.Session()
session.headers['User-Agent'] = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/58.0.3029.110 Safari/537.36'
)

def get_all_forms(url):
    """Fetch and parse all HTML forms from a URL."""
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except Exception as e:
        print(f"Error fetching forms: {e}")
        return []

def get_form_details(form):
    """Extract form attributes and input fields."""
    details = {
        'action': form.attrs.get('action', '').lower(),
        'method': form.attrs.get('method', 'get').lower(),
        'inputs': []
    }
    for tag in form.find_all(['input', 'textarea']):
        input_details = {
            'type': tag.attrs.get('type', 'text'),
            'name': tag.attrs.get('name'),
            'value': tag.attrs.get('value', '')
        }
        details['inputs'].append(input_details)
    return details

def submit_form(form_details, base_url, payload):
    """Submit a form with an injected payload."""
    target_url = urljoin(base_url, form_details['action'])
    data = {}
    for input_field in form_details['inputs']:
        if input_field['name'] is None:
            continue
        if input_field['type'] in ('text', 'textarea'):
            data[input_field['name']] = payload
        else:
            data[input_field['name']] = input_field['value']
    try:
        if form_details['method'] == 'post':
            return session.post(target_url, data=data, timeout=10)
        else:
            return session.get(target_url, params=data, timeout=10)
    except Exception as e:
        print(f"Error submitting form: {e}")
        return None

def is_sqli_vulnerable(response):
    """Check response for SQL error patterns."""
    if response is None:
        return False
    sql_errors = [
        'sql syntax', 'mysql server', 'syntax error',
        'unclosed quotation', 'ora-'
    ]
    return any(error in response.text.lower() for error in sql_errors)

def is_xss_vulnerable(response, payload):
    """Check if payload is reflected unsanitized."""
    if response is None:
        return False
    return payload in response.text

def is_cmd_injection_vulnerable(response, payload):
    """Check for signs of command injection vulnerabilities."""
    if response is None:
        return False
    cmd_errors = [
        'command not found', 
        'not recognized as an internal or external command',
        'syntax error', 'sh:'
    ]
    return any(err in response.text.lower() for err in cmd_errors)

def test_url_params(url, payload, vuln_type):
    """Test URL parameters with a payload for a given vulnerability type."""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    for param in query_params:
        modified_query = parse_qs(parsed.query)
        modified_query[param] = [payload]
        new_url = parsed._replace(
            query="&".join([f"{k}={v[0]}" for k, v in modified_query.items()])
        ).geturl()
        try:
            response = session.get(new_url, timeout=10)
        except Exception as e:
            print(f"Error testing URL parameter '{param}': {e}")
            continue

        if vuln_type == 'sqli' and is_sqli_vulnerable(response):
            return (True, param)
        if vuln_type == 'xss' and is_xss_vulnerable(response, payload):
            return (True, param)
        if vuln_type == 'cmd' and is_cmd_injection_vulnerable(response, payload):
            return (True, param)
    return (False, None)

def scan_vulnerabilities(url, payloads):
    """
    Scan the target URL for vulnerabilities based on the provided payloads.
    payloads: dictionary mapping vulnerability names to a list of payloads.
    """
    print(f"\n[+] Scanning {url}")
    vulns_found = False
    forms = get_all_forms(url)
    
    for vuln in payloads:
        if vuln == 'sqli':
            print("\n=== Testing for SQL Injection ===")
            for form in forms:
                form_details = get_form_details(form)
                for payload in payloads['sqli']:
                    response = submit_form(form_details, url, payload)
                    if is_sqli_vulnerable(response):
                        print(f"[!] SQLi vulnerability in form: {form_details['action']}")
                        print(f"    Payload: {payload}")
                        vulns_found = True
            param_vuln, param = test_url_params(url, payloads['sqli'][0], 'sqli')
            if param_vuln:
                print(f"[!] SQLi vulnerability in URL parameter: {param}")
                vulns_found = True

        elif vuln == 'xss':
            print("\n=== Testing for XSS ===")
            for form in forms:
                form_details = get_form_details(form)
                for payload in payloads['xss']:
                    response = submit_form(form_details, url, payload)
                    if is_xss_vulnerable(response, payload):
                        print(f"[!] XSS vulnerability in form: {form_details['action']}")
                        print(f"    Payload: {payload}")
                        vulns_found = True
            param_vuln, param = test_url_params(url, payloads['xss'][0], 'xss')
            if param_vuln:
                print(f"[!] XSS vulnerability in URL parameter: {param}")
                vulns_found = True

        elif vuln == 'cmd':
            print("\n=== Testing for Command Injection ===")
            for form in forms:
                form_details = get_form_details(form)
                for payload in payloads['cmd']:
                    response = submit_form(form_details, url, payload)
                    if is_cmd_injection_vulnerable(response, payload):
                        print(f"[!] Command Injection vulnerability in form: {form_details['action']}")
                        print(f"    Payload: {payload}")
                        vulns_found = True
            param_vuln, param = test_url_params(url, payloads['cmd'][0], 'cmd')
            if param_vuln:
                print(f"[!] Command Injection vulnerability in URL parameter: {param}")
                vulns_found = True

        else:
            print(f"[-] Vulnerability type '{vuln}' is not supported.")

    if not vulns_found:
        print("[-] No vulnerabilities detected")
    return vulns_found

def load_payloads_from_file(file_path):
    """Load payloads from a given text file (one payload per line)."""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading payload file '{file_path}': {e}")
        return []

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 tester.py <url> <vuln_names> <payload_files>")
        print("Example: python3 tester.py http://example.com sqli,xss,cmd sqli.txt,xss.txt,cmd.txt")
        sys.exit(1)
        
    url = sys.argv[1]
    vuln_names = sys.argv[2].split(',')
    payload_files = sys.argv[3].split(',')
    
    if len(vuln_names) != len(payload_files):
        print("Error: The number of vulnerability names must match the number of payload files provided.")
        sys.exit(1)
    
    
    payloads = {}
    for vuln, file in zip(vuln_names, payload_files):
        vuln = vuln.strip().lower()
        payload_list = load_payloads_from_file(file.strip())
        if payload_list:
            payloads[vuln] = payload_list
        else:
            print(f"Warning: No payloads loaded for vulnerability '{vuln}' from file '{file.strip()}'.")
    
    if not payloads:
        print("Error: No valid payloads loaded.")
        sys.exit(1)
    
    scan_vulnerabilities(url, payloads)

if __name__ == "__main__":
    main()
