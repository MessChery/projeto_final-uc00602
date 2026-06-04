
import db_queries
import risk_engine


def run_test():

    print("")
    print("=" * 55)
    print("       PHISHING & THREAT INTELLIGENCE ENGINE TEST      ")
    print("=" * 55)

    test_ip = "185.100.200.55"

    print(f"\nSTEP 1 — Simulating API data ingestion for IP: {test_ip}")
    print("-" * 55)

    print("  -> Sending sighting from Source 1 (severity: 7/10) ...")
    result_source_1 = db_queries.process_ioc(test_ip, "IPv4", 1, 7)

    if result_source_1:
        print("  -> Source 1 sighting: SAVED SUCCESSFULLY.")
    else:
        print("  -> Source 1 sighting: FAILED. Check the error message above.")

    print("  -> Sending sighting from Source 2 (severity: 9/10) ...")
    result_source_2 = db_queries.process_ioc(test_ip, "IPv4", 2, 9)

    if result_source_2:
        print("  -> Source 2 sighting: SAVED SUCCESSFULLY.")
    else:
        print("  -> Source 2 sighting: FAILED. Check the error message above.")

    print(f"\nSTEP 2 — Fetching full threat history for IP: {test_ip}")
    print("-" * 55)

    threat_history = db_queries.get_threat_history(test_ip)

    if len(threat_history) == 0:
        print("  [ERROR] No history was returned from the database.")
        print("  Please check your database connection and that source IDs 1 and 2 exist in the 'sources' table.")
        print("")
        return

    print(f"  -> Retrieved {len(threat_history)} sighting record(s). Details:")
    print("")

    record_number = 1
    for record in threat_history:
        print(f"     Record #{record_number}")
        print(f"       Indicator Value : {record.get('indicator_value', 'N/A')}")
        print(f"       Indicator Type  : {record.get('indicator_type', 'N/A')}")
        print(f"       Source Name     : {record.get('source_name', 'N/A')}")
        print(f"       Severity Score  : {record.get('severity_score', 'N/A')} / 10")
        print(f"       First Seen      : {record.get('first_seen', 'N/A')}")
        print(f"       Last Seen       : {record.get('last_seen', 'N/A')}")
        print(f"       Times Seen      : {record.get('times_seen', 'N/A')}")
        print("")
        record_number = record_number + 1

    print(f"STEP 3 — Calculating risk score for IP: {test_ip}")
    print("-" * 55)

    final_score = risk_engine.calculate_risk(threat_history)

    risk_label = risk_engine.get_risk_label(final_score)

    print("")
    print("=" * 55)
    print("              FINAL THREAT REPORT                     ")
    print("=" * 55)
    print(f"  TARGET IP      : {test_ip}")
    print(f"  RISK SCORE     : {final_score} / 100")
    print(f"  CLASSIFICATION : {risk_label}")
    print("=" * 55)
    print("")


if __name__ == "__main__":
    run_test()