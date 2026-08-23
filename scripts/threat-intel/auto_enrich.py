import csv
import os
import ipaddress
import requests

PUBLIC_IPS = "/opt/splunk/etc/apps/search/lookups/public_ips.csv"
OUTPUT = "/opt/splunk/etc/apps/search/lookups/threat_intel.csv"

VT = os.getenv("VT_API_KEY")
ABUSE = os.getenv("ABUSEIPDB_API_KEY")
OTX = os.getenv("OTX_API_KEY")

FIELDS = [
    "ip", "vt_owner", "vt_reputation", "vt_malicious", "vt_suspicious",
    "abuse_isp", "abuse_score", "abuse_reports",
    "otx_asn", "otx_pulse_count"
]

def vt_lookup(ip):
    r = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VT}, timeout=15
    )
    a = r.json()["data"]["attributes"]
    s = a["last_analysis_stats"]
    return a.get("as_owner", "N/A"), a.get("reputation", 0), s.get("malicious", 0), s.get("suspicious", 0)

def abuse_lookup(ip):
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSE, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=15
    )
    d = r.json()["data"]
    return d.get("isp", "N/A"), d.get("abuseConfidenceScore", 0), d.get("totalReports", 0)

def otx_lookup(ip):
    r = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers={"X-OTX-API-KEY": OTX}, timeout=15
    )
    d = r.json()
    return d.get("asn", "N/A"), d.get("pulse_info", {}).get("count", 0)

existing = {}

if os.path.exists(OUTPUT):
    with open(OUTPUT, newline="") as f:
        for row in csv.DictReader(f):
            existing[row["ip"]] = row

with open(PUBLIC_IPS, newline="") as f:
    ips = [row["ip"] for row in csv.DictReader(f)]

for ip in ips:
    try:
        if not ipaddress.ip_address(ip).is_global:
            continue

        if ip in existing:
            continue

        vt_owner, vt_rep, vt_mal, vt_susp = vt_lookup(ip)
        abuse_isp, abuse_score, abuse_reports = abuse_lookup(ip)
        otx_asn, otx_pulses = otx_lookup(ip)

        existing[ip] = {
            "ip": ip,
            "vt_owner": vt_owner,
            "vt_reputation": vt_rep,
            "vt_malicious": vt_mal,
            "vt_suspicious": vt_susp,
            "abuse_isp": abuse_isp,
            "abuse_score": abuse_score,
            "abuse_reports": abuse_reports,
            "otx_asn": otx_asn,
            "otx_pulse_count": otx_pulses
        }

        print(f"[+] Enriched: {ip}")

    except Exception as e:
        print(f"[-] Failed {ip}: {e}")

with open(OUTPUT, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(existing.values())

print("[+] Threat Intelligence lookup updated.")
