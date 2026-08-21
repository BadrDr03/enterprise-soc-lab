import os
import sys
import requests

API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    print("Error: VT_API_KEY environment variable is not configured.")
    sys.exit(1)

if len(sys.argv) != 2:
    print("Usage: python virustotal_lookup.py <IP_ADDRESS>")
    sys.exit(1)

ip_address = sys.argv[1]

url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

headers = {
    "x-apikey": API_KEY
}

response = requests.get(url, headers=headers, timeout=15)

if response.status_code != 200:
    print(f"VirusTotal API error: HTTP {response.status_code}")
    sys.exit(1)

data = response.json()

attributes = data["data"]["attributes"]
stats = attributes["last_analysis_stats"]

print("\n=== VirusTotal IP Enrichment ===")
print(f"IP Address : {ip_address}")
print(f"Country    : {attributes.get('country', 'N/A')}")
print(f"Owner      : {attributes.get('as_owner', 'N/A')}")
print(f"Reputation : {attributes.get('reputation', 'N/A')}")
print(f"Malicious  : {stats.get('malicious', 0)}")
print(f"Suspicious : {stats.get('suspicious', 0)}")
print(f"Harmless   : {stats.get('harmless', 0)}")
print("================================")
