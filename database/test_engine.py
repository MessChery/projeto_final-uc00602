# test_engine.py
# -------------------------------------------------------------------------
# Purpose:
#   This script tests the complete flow of the Phishing & Threat Intelligence
#   Engine. It covers four main steps:
#
#   STEP 1 — Simulate API data ingestion (calls process_ioc twice for the
#             same IP to verify that INSERT IGNORE and ON DUPLICATE KEY UPDATE
#             work correctly without creating duplicate rows).
#
#   STEP 2 — Fetch the full threat history from the database for that IP
#             (calls get_threat_history, which uses a JOIN across three tables).
#
#   STEP 3 — Calculate the risk score from the fetched history
#             (calls calculate_risk and get_risk_label from risk_engine.py).
#
#   STEP 4 — Print a clean, formatted "Final Threat Report" to the terminal.
#
# How to run:
#   Make sure your .env file is configured and MySQL is running, then execute:
#       python test_engine.py
# -------------------------------------------------------------------------

# Import the two modules that contain all our logic
import db_queries
import risk_engine


# =========================================================================
# MAIN TEST FUNCTION
# =========================================================================
# We put everything inside a function called run_test() so the code is
# organised and easy to follow. It gets called at the bottom of the file.
# =========================================================================
def run_test():

    # Print a clear header so we know the test has started
    print("")
    print("=" * 55)
    print("       PHISHING & THREAT INTELLIGENCE ENGINE TEST      ")
    print("=" * 55)

    # -----------------------------------------------------------------------
    # Define the fake test IP address we will use throughout this test.
    # In a real scenario, this value would come from an external API.
    # -----------------------------------------------------------------------
    test_ip = "185.100.200.55"

    # -----------------------------------------------------------------------
    # STEP 1 — SIMULATE API DATA INGESTION
    #
    # We call process_ioc() TWICE for the same IP address.
    # This is intentional: we want to prove that:
    #   - The indicators table does NOT create a duplicate row (INSERT IGNORE).
    #   - The sightings table correctly creates TWO separate rows, one per
    #     source, because each (indicator_id, source_id) pair is unique.
    #
    # We pretend:
    #   - Source ID 1 is "AbuseIPDB" and reported this IP with severity 7.
    #   - Source ID 2 is "AlienVault" and reported this IP with severity 9.
    # -----------------------------------------------------------------------
    print(f"\nSTEP 1 — Simulating API data ingestion for IP: {test_ip}")
    print("-" * 55)

    # First call: Source 1 (e.g. AbuseIPDB), severity score = 7 out of 10
    print("  -> Sending sighting from Source 1 (severity: 7/10) ...")
    result_source_1 = db_queries.process_ioc(test_ip, "IPv4", 1, 7)

    # Check if the first call was successful
    if result_source_1:
        print("  -> Source 1 sighting: SAVED SUCCESSFULLY.")
    else:
        print("  -> Source 1 sighting: FAILED. Check the error message above.")

    # Second call: Source 2 (e.g. AlienVault), severity score = 9 out of 10
    print("  -> Sending sighting from Source 2 (severity: 9/10) ...")
    result_source_2 = db_queries.process_ioc(test_ip, "IPv4", 2, 9)

    # Check if the second call was successful
    if result_source_2:
        print("  -> Source 2 sighting: SAVED SUCCESSFULLY.")
    else:
        print("  -> Source 2 sighting: FAILED. Check the error message above.")

    # -----------------------------------------------------------------------
    # STEP 2 — FETCH THE THREAT HISTORY FROM THE DATABASE
    #
    # get_threat_history() returns a list of dictionaries.
    # Each dictionary is one row from the database JOIN result.
    # If the list is empty, the IP was not found or a DB error occurred.
    # -----------------------------------------------------------------------
    print(f"\nSTEP 2 — Fetching full threat history for IP: {test_ip}")
    print("-" * 55)

    threat_history = db_queries.get_threat_history(test_ip)

    # If we got no data back, there is no point continuing the test
    if len(threat_history) == 0:
        print("  [ERROR] No history was returned from the database.")
        print("  Please check your database connection and that source IDs 1 and 2 exist in the 'sources' table.")
        print("")
        return  # Stop the function here

    # Print each sighting record we received so we can see the raw data
    print(f"  -> Retrieved {len(threat_history)} sighting record(s). Details:")
    print("")

    # Loop through each record and print its fields in a readable way
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

    # -----------------------------------------------------------------------
    # STEP 3 — CALCULATE THE RISK SCORE
    #
    # We pass the full threat history to calculate_risk().
    # It returns an integer between 0 and 100.
    # We then pass that integer to get_risk_label() to get a text description.
    # -----------------------------------------------------------------------
    print(f"STEP 3 — Calculating risk score for IP: {test_ip}")
    print("-" * 55)

    # calculate_risk() will also print its internal steps to the terminal
    final_score = risk_engine.calculate_risk(threat_history)

    # Convert the numeric score to a human-readable classification label
    risk_label = risk_engine.get_risk_label(final_score)

    # -----------------------------------------------------------------------
    # STEP 4 — PRINT THE FINAL THREAT REPORT
    #
    # This is the formatted summary that clearly shows the result of the test.
    # -----------------------------------------------------------------------
    print("")
    print("=" * 55)
    print("              FINAL THREAT REPORT                     ")
    print("=" * 55)
    print(f"  TARGET IP      : {test_ip}")
    print(f"  RISK SCORE     : {final_score} / 100")
    print(f"  CLASSIFICATION : {risk_label}")
    print("=" * 55)
    print("")


# =========================================================================
# ENTRY POINT
# =========================================================================
# This block makes sure that run_test() is only called when we run this
# file directly (e.g. "python test_engine.py").
# It will NOT run automatically if this file is imported by another module.
# =========================================================================
if __name__ == "__main__":
    run_test()