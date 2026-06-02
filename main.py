import argparse

from api_ingestion import (
    fetch_abuseipdb,
    fetch_otx
)

# ajustar conforme o código da tua colega
from database.db_queries import (
    process_ioc
)

from risk_engine import (
    get_risk_score
)

from output import (
    print_risk_report
)


def update():

    abuse_ips = fetch_abuseipdb()
    otx_ips = fetch_otx()

    print(
        f"[+] AbuseIPDB: {len(abuse_ips)} IPs"
    )

    print(
        f"[+] AlienVault: {len(otx_ips)} IPs"
    )

    for ip in abuse_ips:
        process_ioc(
            ip=ip,
            source="AbuseIPDB"
        )

    for ip in otx_ips:
        process_ioc(
            ip=ip,
            source="AlienVault"
        )


def check(ip):

    score = get_risk_score(ip)

    print_risk_report(ip, score)


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--update",
        action="store_true"
    )

    parser.add_argument(
        "--check",
        type=str
    )

    args = parser.parse_args()

    if args.update:
        update()

    elif args.check:
        check(args.check)


if __name__ == "__main__":
    main()