#!/usr/bin/env python3

import csv
import os
import sys
import requests

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")


def vt_lookup(ip):
    if not VT_API_KEY:
        return {}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=15)

    if r.status_code != 200:
        return {}

    attrs = r.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})

    return {
        "vt_owner": attrs.get("as_owner", ""),
        "vt_country": attrs.get("country", ""),
        "vt_reputation": attrs.get("reputation", ""),
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
    }


def abuse_lookup(ip):
    if not ABUSEIPDB_API_KEY:
        return {}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    r = requests.get(url, headers=headers, params=params, timeout=15)

    if r.status_code != 200:
        return {}

    data = r.json()["data"]

    return {
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "abuse_reports": data.get("totalReports", 0),
        "abuse_isp": data.get("isp", ""),
        "abuse_country": data.get("countryCode", ""),
    }


def otx_lookup(ip):
    if not OTX_API_KEY:
        return {}

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    r = requests.get(
        url,
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        timeout=15
    )

    if r.status_code != 200:
        return {}

    data = r.json()
    pulse_info = data.get("pulse_info", {})

    return {
        "otx_asn": data.get("asn", ""),
        "otx_country": data.get("country_code", ""),
        "otx_pulse_count": pulse_info.get("count", 0),
    }


reader = csv.DictReader(sys.stdin)

fieldnames = list(reader.fieldnames or []) + [
    "vt_owner",
    "vt_country",
    "vt_reputation",
    "vt_malicious",
    "vt_suspicious",
    "abuse_score",
    "abuse_reports",
    "abuse_isp",
    "abuse_country",
    "otx_asn",
    "otx_country",
    "otx_pulse_count",
]

writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
writer.writeheader()

for row in reader:
    ip = row.get("ip", "").strip()

    if ip:
        row.update(vt_lookup(ip))
        row.update(abuse_lookup(ip))
        row.update(otx_lookup(ip))

    writer.writerow(row)
