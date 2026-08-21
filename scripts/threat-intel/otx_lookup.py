import os
import sys
import requests

API_KEY = os.getenv("OTX_API_KEY")

if not API_KEY:
    print("Error: OTX_API_KEY environment variable is not configured.")
    sys.exit(1)

if len(sys.argv) != 2:
    print("Usage: python3 otx_lookup.py <IP_ADDRESS>")
    sys.exit(1)

ip_address = sys.argv[1]

url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"

headers = {
    "X-OTX-API-KEY": API_KEY
}

response = requests.get(url, headers=headers, timeout=15)

if response.status_code != 200:
    print(f"OTX API error: HTTP {response.status_code}")
    sys.exit(1)

data = response.json()

pulse_info = data.get("pulse_info", {})

print("\n=== AlienVault OTX IP Enrichment ===")
print(f"IP Address     : {ip_address}")
print(f"Country        : {data.get('country_code', 'N/A')}")
print(f"ASN            : {data.get('asn', 'N/A')}")
print(f"Pulse Count    : {pulse_info.get('count', 0)}")

pulses = pulse_info.get("pulses", [])

if pulses:
    print("\nThreat Pulses:")
    for pulse in pulses[:5]:
        print(f"- {pulse.get('name', 'Unnamed Pulse')}")
else:
    print("Threat Pulses  : None")

print("====================================")
