# risk_engine.py
# This file calculates a risk score for a given IP address based on its threat history.
# It receives the data already fetched from the database (by db_queries.py) and
# applies a simple, step-by-step scoring system to return a score from 0 to 100.

from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# FUNCTION: calculate_risk
# ---------------------------------------------------------------------------
# Purpose: Analyses the threat history of an IP and calculates a risk score.
#
# Parameters:
#   threat_history (list) - A list of dictionaries returned by get_threat_history().
#                           Each dictionary represents one sighting of the IP.
#
# Returns:
#   An integer between 0 and 100 representing the overall risk level.
#   0  = No risk / Not seen before
#   100 = Maximum / Critical risk
#
# Scoring breakdown (total possible = 100 points):
#   - Base severity score  : up to 40 points  (from the database severity field)
#   - Recency bonus        : up to 30 points  (was it seen recently?)
#   - Multiple sources     : up to 20 points  (how many different sources reported it?)
#   - Times seen bonus     : up to 10 points  (how many total sightings?)
# ---------------------------------------------------------------------------
def calculate_risk(threat_history):

    # If there is no history, there is no risk to calculate
    if threat_history is None or len(threat_history) == 0:
        print("RISK ENGINE: No threat history provided. Risk score = 0.")
        return 0

    # ------------------------------------------------------------------
    # PART 1 — SEVERITY SCORE (0 to 40 points)
    #
    # The database stores a severity_score between 0 and 10 for each sighting.
    # We take the highest severity found across all sightings (the worst case),
    # then scale it up to a maximum of 40 points.
    #
    # Formula: (max_severity / 10) * 40
    # Example: severity 8.0 → (8.0 / 10) * 40 = 32 points
    # ------------------------------------------------------------------

    # Start by collecting all severity values from the history records
    all_severity_values = []
    for record in threat_history:
        severity_value = record.get("severity_score", 0)
        if severity_value is not None:
            all_severity_values.append(float(severity_value))

    # Find the maximum severity across all sightings
    if len(all_severity_values) > 0:
        highest_severity = max(all_severity_values)
    else:
        highest_severity = 0.0

    # Scale to a maximum of 40 points
    severity_points = (highest_severity / 10.0) * 40
    severity_points = round(severity_points, 2)

    print(f"RISK ENGINE: Highest severity found = {highest_severity} → {severity_points} severity points.")

    # ------------------------------------------------------------------
    # PART 2 — RECENCY SCORE (0 to 30 points)
    #
    # A threat seen very recently is much more dangerous than an old one.
    # We check the most recent "last_seen" date across all sightings and
    # award points based on how many days ago it was last observed.
    #
    #   Seen within the last 7 days   → 30 points  (very recent, high risk)
    #   Seen within the last 30 days  → 20 points  (recent, medium-high risk)
    #   Seen within the last 90 days  → 10 points  (somewhat recent, medium risk)
    #   Older than 90 days            →  0 points  (old, lower concern)
    # ------------------------------------------------------------------

    # Collect all "last_seen" timestamps from the records
    all_last_seen_dates = []
    for record in threat_history:
        last_seen_value = record.get("last_seen")
        if last_seen_value is not None:
            all_last_seen_dates.append(last_seen_value)

    recency_points = 0

    if len(all_last_seen_dates) > 0:
        # Find the most recent sighting date
        most_recent_date = max(all_last_seen_dates)

        # Make sure it is a datetime object (MySQL sometimes returns it already as one)
        if isinstance(most_recent_date, str):
            most_recent_date = datetime.strptime(most_recent_date, "%Y-%m-%d %H:%M:%S")

        # Get the current date/time in UTC so the comparison is fair
        today = datetime.now(timezone.utc)

        # Remove timezone info if present so we can subtract the two dates
        if most_recent_date.tzinfo is not None:
            most_recent_date = most_recent_date.replace(tzinfo=None)

        today_naive = today.replace(tzinfo=None)

        # Calculate the difference in days
        difference = today_naive - most_recent_date
        days_ago = difference.days

        # Award points based on how recent the last sighting was
        if days_ago <= 7:
            recency_points = 30
        elif days_ago <= 30:
            recency_points = 20
        elif days_ago <= 90:
            recency_points = 10
        else:
            recency_points = 0

        print(f"RISK ENGINE: Last seen {days_ago} day(s) ago → {recency_points} recency points.")
    else:
        print("RISK ENGINE: No valid last_seen date found → 0 recency points.")

    # ------------------------------------------------------------------
    # PART 3 — MULTIPLE SOURCES SCORE (0 to 20 points)
    #
    # If many different threat intelligence sources reported this IP,
    # it means the threat is more widely confirmed and more dangerous.
    # We count the number of unique source names in the history.
    #
    #   1 source  →  5 points
    #   2 sources → 10 points
    #   3 sources → 15 points
    #   4+ sources → 20 points (maximum)
    # ------------------------------------------------------------------

    # Collect unique source names using a set (sets automatically remove duplicates)
    unique_sources = set()
    for record in threat_history:
        source_name = record.get("source_name")
        if source_name is not None:
            unique_sources.add(source_name)

    number_of_sources = len(unique_sources)

    # Award points based on how many sources confirmed the threat
    if number_of_sources >= 4:
        source_points = 20
    else:
        # Each source adds 5 points (1 source = 5, 2 = 10, 3 = 15)
        source_points = number_of_sources * 5

    print(f"RISK ENGINE: {number_of_sources} unique source(s) → {source_points} source points.")

    # ------------------------------------------------------------------
    # PART 4 — TIMES SEEN SCORE (0 to 10 points)
    #
    # How many times total has this indicator been reported?
    # Frequently sighted threats are more persistent and dangerous.
    # We sum up the "times_seen" count from all sighting records.
    #
    #   1-2 times total   → 2 points
    #   3-5 times total   → 5 points
    #   6-10 times total  → 8 points
    #   11+ times total   → 10 points (maximum)
    # ------------------------------------------------------------------

    total_times_seen = 0
    for record in threat_history:
        times_seen_value = record.get("times_seen", 0)
        if times_seen_value is not None:
            total_times_seen = total_times_seen + int(times_seen_value)

    if total_times_seen >= 11:
        frequency_points = 10
    elif total_times_seen >= 6:
        frequency_points = 8
    elif total_times_seen >= 3:
        frequency_points = 5
    elif total_times_seen >= 1:
        frequency_points = 2
    else:
        frequency_points = 0

    print(f"RISK ENGINE: Total sightings = {total_times_seen} → {frequency_points} frequency points.")

    # ------------------------------------------------------------------
    # FINAL CALCULATION
    # Add up all four category scores to get the total risk score.
    # Use min(..., 100) to make sure we never exceed the maximum of 100.
    # ------------------------------------------------------------------

    total_risk_score = severity_points + recency_points + source_points + frequency_points
    total_risk_score = int(min(total_risk_score, 100))

    print(f"RISK ENGINE: Final risk score = {total_risk_score} / 100")

    return total_risk_score


# ---------------------------------------------------------------------------
# HELPER FUNCTION: get_risk_label
# ---------------------------------------------------------------------------
# Purpose: Converts the numeric risk score into a human-readable label.
#          This makes it easier to present the result to the user.
#
# Parameters:
#   score (int) - The risk score returned by calculate_risk()
#
# Returns:
#   A string describing the risk level.
# ---------------------------------------------------------------------------
def get_risk_label(score):
    if score == 0:
        return "No Risk"
    elif score <= 25:
        return "Low Risk"
    elif score <= 50:
        return "Medium Risk"
    elif score <= 75:
        return "High Risk"
    else:
        return "Critical Risk"
