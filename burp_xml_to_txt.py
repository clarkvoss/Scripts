import os
import sys
import base64
import xml.etree.ElementTree as ET

def extract_requests(xml_path, output_folder):
    if not os.path.isfile(xml_path):
        print("[!] XML file not found.")
        return

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    tree = ET.parse(xml_path)
    root = tree.getroot()
    count = 0

    for idx, item in enumerate(root.findall('.//item')):
        request_elem = item.find('request')
        if request_elem is not None and request_elem.text:
            try:
                request_data = base64.b64decode(request_elem.text)
            except Exception as e:
                print(f"[!] Failed to decode request {idx}: {e}")
                continue

            filename = f"request_{idx+1:04d}.txt"
            filepath = os.path.join(output_folder, filename)
            with open(filepath, 'wb') as f:
                f.write(request_data)
            count += 1

    print(f"[+] Extracted {count} requests to '{output_folder}'")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python burp_xml_to_txt.py <burp_output.xml> <output_folder>")
        sys.exit(1)

    xml_path = sys.argv[1]
    output_folder = sys.argv[2]
    extract_requests(xml_path, output_folder)
