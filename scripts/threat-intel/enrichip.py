#!/usr/bin/env python3

import sys
import json
import ipaddress
import urllib.parse
import urllib.request

from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

SECRET_FILE = "/opt/splunk/etc/apps/search/local/threat_intel.env"


def load_keys():
    keys = {}

    try:
        with open(SECRET_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                keys[key.strip()] = value.strip()
    except Exception:
        pass

    return keys


API_KEYS = load_keys()


def request_json(url, headers=None):
    request = urllib.request.Request(
        url,
        headers=headers or {}
    )

    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def virustotal_lookup(ip):
    api_key = API_KEYS.get("VT_API_KEY")

    if not api_key:
        return {}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    data = request_json(
        url,
        {"x-apikey": api_key}
    )

    attributes = data["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})

    return {
        "vt_owner": attributes.get("as_owner", ""),
        "vt_country": attributes.get("country", ""),
        "vt_reputation": attributes.get("reputation", ""),
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
    }


def abuseipdb_lookup(ip):
    api_key = API_KEYS.get("ABUSEIPDB_API_KEY")

    if not api_key:
        return {}

    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": 90,
    })

    url = f"https://api.abuseipdb.com/api/v2/check?{params}"

    data = request_json(
        url,
        {
            "Accept": "application/json",
            "Key": api_key,
        }
    )["data"]

    return {
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "abuse_reports": data.get("totalReports", 0),
        "abuse_isp": data.get("isp", ""),
        "abuse_country": data.get("countryCode", ""),
    }


def otx_lookup(ip):
    api_key = API_KEYS.get("OTX_API_KEY")

    if not api_key:
        return {}

    url = (
        f"https://otx.alienvault.com/api/v1/"
        f"indicators/IPv4/{ip}/general"
    )

    data = request_json(
        url,
        {"X-OTX-API-KEY": api_key}
    )

    pulse_info = data.get("pulse_info", {})

    return {
        "otx_asn": data.get("asn", ""),
        "otx_country": data.get("country_code", ""),
        "otx_pulse_count": pulse_info.get("count", 0),
    }


@Configuration()
class EnrichIPCommand(StreamingCommand):

    ipfield = Option(
        require=True,
        validate=validators.Fieldname()
    )

    def stream(self, records):

        cache = {}

        for record in records:

            ip = str(record.get(self.ipfield, "")).strip()

            if not ip:
                record["threatintel_status"] = "missing_ip"
                yield record
                continue

            try:
                ip_object = ipaddress.ip_address(ip)

                if ip_object.is_private:
                    record["threatintel_status"] = "private_ip_skipped"
                    yield record
                    continue

            except ValueError:
                record["threatintel_status"] = "invalid_ip"
                yield record
                continue

            try:

                if ip not in cache:
                    result = {}

                    result.update(virustotal_lookup(ip))
                    result.update(abuseipdb_lookup(ip))
                    result.update(otx_lookup(ip))

                    cache[ip] = result

                record.update(cache[ip])
                record["threatintel_status"] = "enriched"

            except Exception as error:
                record["threatintel_status"] = "error"
                record["threatintel_error"] = str(error)

            yield record


dispatch(
    EnrichIPCommand,
    sys.argv,
    sys.stdin,
    sys.stdout,
    __name__
)
