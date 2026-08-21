import os
import sys
import requests

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not API_KEY:
    print("Error: ABUSEIPDB_API_KEY environment variable is not configured.")
    sys.exit(1)

if len(sys.argv) != 2:
    print("Usage: python3 abuseipdb_lookup.py <IP_ADDRESS>")
    sys.exit(1)

ip_address = sys.argv[1]

url = "https://api.abuseipdb.com/api/v2/check"

headers = {
    "Accept": "application/json",
    "Key": API_KEY
}

params = {
    "ipAddress": ip_address,
    "maxAgeInDays": 90,
    "verbose": ""
}

response = requests.get(url, headers=headers, params=params, timeout=15)

if response.status_code != 200:
    print(f"AbuseIPDB API error: HTTP {response.status_code}")
    sys.exit(1)

data = response.json()["data"]

print("\n=== AbuseIPDB IP Enrichment ===")
print(f"IP Address        : {data.get('ipAddress', 'N/A')}")
print(f"Country           : {data.get('countryCode', 'N/A')}")
print(f"ISP               : {data.get('isp', 'N/A')}")
print(f"Domain            : {data.get('domain', 'N/A')}")
print(f"Usage Type        : {data.get('usageType', 'N/A')}")
print(f"Abuse Score       : {data.get('abuseConfidenceScore', 'N/A')}")
print(f"Total Reports     : {data.get('totalReports', 'N/A')}")
print(f"Last Reported At  : {data.get('lastReportedAt', 'N/A')}")
print("=================================")
