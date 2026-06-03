import requests
from urllib.parse import urlparse

from config import (
    ALIENVAULT_API_KEY,
    ABUSEIPDB_API_KEY
)


def fetch_abuseipdb():

    url = "https://api.abuseipdb.com/api/v2/blacklist"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 401:
        raise Exception("API Key AbuseIPDB inválida")

    if response.status_code != 200:
        raise Exception(
            f"Erro AbuseIPDB: {response.status_code}"
        )

    data = response.json()

    ips = []

    for item in data["data"]:
        ips.append(item["ipAddress"])

    return ips


def fetch_otx():

    url = (
        "https://otx.alienvault.com"
        "/api/v1/pulses/subscribed"
    )

    headers = {
        "X-OTX-API-KEY": ALIENVAULT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 401:
        raise Exception("API Key AlienVault inválida")

    if response.status_code != 200:
        raise Exception(
            f"Erro OTX: {response.status_code}"
        )

    data = response.json()

    ips = []

    phishing_tags = {
        "phishing",
        "vishing",
        "smishing"
    }

    for pulse in data["results"]:

        tags = [
            tag.lower()
            for tag in pulse.get("tags", [])
        ]

        if not any(
                tag in phishing_tags
                for tag in tags
        ):
            continue

        for indicator in pulse.get("indicators", []):

            indicator_type = (
                indicator.get("type", "")
                .lower()
            )

            indicator_value = (
                indicator.get("indicator", "")
            )

            if indicator_type in (
                    "ipv4",
                    "ipv6"
            ):

                ips.append(indicator_value)

            elif indicator_type == "url":

                parsed = urlparse(
                    indicator_value
                )

                host = parsed.hostname

                if host:
                    ips.append(host)

    return ips