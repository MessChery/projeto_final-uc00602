
from datetime import datetime, timezone


def calculate_risk(threat_history):

    if threat_history is None or len(threat_history) == 0:
        print("No threat history provided. Risk score = 0.")
        return 0


    all_severity_values = []
    for record in threat_history:
        severity_value = record.get("severity_score", 0)
        if severity_value is not None:
            all_severity_values.append(float(severity_value))

    if len(all_severity_values) > 0:
        highest_severity = max(all_severity_values)
    else:
        highest_severity = 0.0

    severity_points = (highest_severity / 10.0) * 40
    severity_points = round(severity_points, 2)

    print(f"Highest severity found = {highest_severity} → {severity_points} severity points.")


    all_last_seen_dates = []
    for record in threat_history:
        last_seen_value = record.get("last_seen")
        if last_seen_value is not None:
            all_last_seen_dates.append(last_seen_value)

    recency_points = 0

    if len(all_last_seen_dates) > 0:
        most_recent_date = max(all_last_seen_dates)

        if isinstance(most_recent_date, str):
            most_recent_date = datetime.strptime(most_recent_date, "%Y-%m-%d %H:%M:%S")

        today = datetime.now(timezone.utc)

        if most_recent_date.tzinfo is not None:
            most_recent_date = most_recent_date.replace(tzinfo=None)

        today_naive = today.replace(tzinfo=None)

        difference = today_naive - most_recent_date
        days_ago = difference.days

        if days_ago <= 7:
            recency_points = 30
        elif days_ago <= 30:
            recency_points = 20
        elif days_ago <= 90:
            recency_points = 10
        else:
            recency_points = 0

        print(f"Last seen {days_ago} day(s) ago → {recency_points} recency points.")
    else:
        print("No valid last_seen date found → 0 recency points.")


    unique_sources = set()
    for record in threat_history:
        source_name = record.get("source_name")
        if source_name is not None:
            unique_sources.add(source_name)

    number_of_sources = len(unique_sources)

    if number_of_sources >= 4:
        source_points = 20
    else:
        source_points = number_of_sources * 5

    print(f"{number_of_sources} unique source(s) → {source_points} source points.")


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

    print(f"Total sightings = {total_times_seen} → {frequency_points} frequency points.")


    total_risk_score = severity_points + recency_points + source_points + frequency_points
    total_risk_score = int(min(total_risk_score, 100))

    print(f"Final risk score = {total_risk_score} / 100")

    return total_risk_score


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
