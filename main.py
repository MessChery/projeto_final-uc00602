import sys
import argparse
from urllib.parse import urlparse
from api_ingestion import fetch_abuseipdb, fetch_otx
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "database"))
from database.db_queries import process_ioc


SOURCE_ABUSEIPDB = 1
SOURCE_OTX       = 2

SEVERITY_ABUSEIPDB = 8.0
SEVERITY_OTX       = 7.0


def _classify_indicator(value: str) -> str:
    import socket
    try:
        socket.inet_aton(value)
        return "IPv4"
    except socket.error:
        pass

    if ":" in value:
        return "IPv6"

    return "domain"


def update_database():

    print("=" * 60)
    print("Phishing & Threat Intelligence Engine — DB Update")
    print("=" * 60)

    total_success  = 0
    total_failures = 0

    print("\n[1/2] Connecting to AbuseIPDB...")

    abuseipdb_ips = []

    try:
        abuseipdb_ips = fetch_abuseipdb()
        print(
            f"Fetched {len(abuseipdb_ips)} IPs from AbuseIPDB. "
            f"Injecting into database"
        )
    except Exception as error:
        print(f"Could not fetch AbuseIPDB data: {error}")
        print("Skipping AbuseIPDB — continuing with other sources.")

    for ip in abuseipdb_ips:

        ip = ip.strip()

        if not ip:
            continue

        indicator_type = _classify_indicator(ip)

        success = process_ioc(
            indicator_value=ip,
            indicator_type=indicator_type,
            source_id=SOURCE_ABUSEIPDB,
            severity_score=SEVERITY_ABUSEIPDB
        )

        if success:
            total_success += 1
        else:
            total_failures += 1

    if abuseipdb_ips:
        print(
            f"AbuseIPDB done. "
            f"{total_success} inserted/updated, "
            f"{total_failures} failed."
        )

    print("\n[2/2] Connecting to AlienVault OTX...")

    otx_indicators = []

    success_before_otx = total_success
    failures_before_otx = total_failures

    try:
        otx_indicators = fetch_otx()
        print(
            f"Fetched {len(otx_indicators)} indicator(s) from AlienVault OTX. "
            f"Injecting into database"
        )
    except Exception as error:
        print(f"Could not fetch AlienVault OTX data: {error}")
        print("Skipping AlienVault OTX — continuing with other sources.")

    for indicator in otx_indicators:

        indicator = indicator.strip()

        if not indicator:
            continue

        indicator_type = _classify_indicator(indicator)

        success = process_ioc(
            indicator_value=indicator,
            indicator_type=indicator_type,
            source_id=SOURCE_OTX,
            severity_score=SEVERITY_OTX
        )

        if success:
            total_success += 1
        else:
            total_failures += 1

    if otx_indicators:
        otx_success  = total_success  - success_before_otx
        otx_failures = total_failures - failures_before_otx
        print(
            f"AlienVault OTX done. "
            f"{otx_success} inserted/updated, "
            f"{otx_failures} failed."
        )

    print("\n" + "=" * 60)
    print("Update complete.")
    print(f"Total indicators inserted/updated: {total_success}")
    print(f"Total failures: {total_failures}")
    print("=" * 60 + "\n")


def main():

    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Phishing & Threat Intelligence Engine — Orchestrator\n"
            "Fetches malicious indicators from threat-intelligence APIs\n"
            "and stores them in the MySQL database."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help=(
            "Pull the latest threat indicators from AbuseIPDB and "
            "AlienVault OTX and insert them into the database."
        )
    )

    args = parser.parse_args()

    if args.update:
        update_database()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()