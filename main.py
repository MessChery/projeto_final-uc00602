import argparse

from api_ingestion import (
    fetch_abuseipdb,
    fetch_otx
)


def update():

    abuse_ips = fetch_abuseipdb()
    otx_ips = fetch_otx()

    print(
        f"AbuseIPDB: {len(abuse_ips)} IPs"
    )

    print(
        f"AlienVault: {len(otx_ips)} IPs"
    )


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--update",
        action="store_true"
    )

    args = parser.parse_args()

    if args.update:
        update()


if __name__ == "__main__":
    main()