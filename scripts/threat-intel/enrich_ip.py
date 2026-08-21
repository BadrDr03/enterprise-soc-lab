import os
import sys
import requests

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

if len(sys.argv) != 2:
    print("Usage: python3 enrich_ip.py <IP_ADDRESS>")
    sys.exit(1)

ip_address = sys.argv[1]

if not all([VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY]):
    print("Error: One or more API keys are not configured.")
    sys.exit(1)


def virustotal_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers, timeout=15)

    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}"}

    attributes = response.json()["data"]["attributes"]
    stats = attributes["last_analysis_stats"]

    return {
        "owner": attributes.get("as_owner", "N/A"),
        "country": attributes.get("country", "N/A"),
        "reputation": attributes.get("reputation", "N/A"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
    }


def abuseipdb_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY,
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=15
    )

    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}"}

    data = response.json()["data"]

    return {
        "isp": data.get("isp", "N/A"),
        "domain": data.get("domain", "N/A"),
        "country": data.get("countryCode", "N/A"),
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
    }


def otx_lookup(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    response = requests.get(url, headers=headers, timeout=15)

    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}"}

    data = response.json()
    pulse_info = data.get("pulse_info", {})

    return {
        "country": data.get("country_code", "N/A"),
        "asn": data.get("asn", "N/A"),
        "pulse_count": pulse_info.get("count", 0),
    }


vt = virustotal_lookup(ip_address)
abuse = abuseipdb_lookup(ip_address)
otx = otx_lookup(ip_address)

print("\n========== Unified IP Enrichment ==========")
print(f"IP Address: {ip_address}")

print("\n--- VirusTotal ---")
for key, value in vt.items():
    print(f"{key}: {value}")

print("\n--- AbuseIPDB ---")
for key, value in abuse.items():
    print(f"{key}: {value}")

print("\n--- AlienVault OTX ---")
for key, value in otx.items():
    print(f"{key}: {value}")

print("\n===========================================")
