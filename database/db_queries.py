# db_queries.py
# This file handles all database operations for the Phishing & Threat Intelligence Engine.
# It imports the database connection from db_connector.py and provides two main functions:
#   - process_ioc: saves a new threat indicator into the database
#   - get_threat_history: retrieves the full history of a given IP address
#
# SCHEMA REFERENCE (exact column names that exist in MySQL):
#
#   indicators table:
#       indicator_id    - auto-increment primary key
#       indicator_value - the IP address or domain string
#       indicator_type  - e.g. "IPv4", "domain"
#       first_seen      - auto-generated timestamp on row creation (we do NOT insert this)
#
#   sightings table:
#       sighting_id     - auto-increment primary key
#       indicator_id    - foreign key linking to indicators
#       source_id       - foreign key linking to sources
#       severity_score  - numeric score 0-10
#       last_seen       - timestamp that we SET manually and UPDATE on duplicate
#
#   sources table:
#       source_id       - primary key
#       source_name     - name of the threat intelligence source

from db_connector import create_connection


# ---------------------------------------------------------------------------
# FUNCTION: process_ioc
# ---------------------------------------------------------------------------
# Purpose: Receives data about a threat indicator and saves it to the database.
#
# Parameters:
#   indicator_value (str)  - The actual threat, e.g. "192.168.1.1" or "evil.com"
#   indicator_type  (str)  - The category, e.g. "IPv4", "domain", "url"
#   source_id       (int)  - The ID of the intelligence source that reported it
#   severity_score  (float)- A numeric score from 0 to 10 indicating danger level
#
# Returns:
#   True  if the operation was successful
#   False if any database error occurred
# ---------------------------------------------------------------------------
def process_ioc(indicator_value, indicator_type, source_id, severity_score):

    # Open a connection to the database
    connection = create_connection()

    # If the connection failed, we cannot continue
    if connection is None:
        print("ERROR: Could not connect to the database in process_ioc().")
        return False

    # Create a cursor to execute SQL queries
    cursor = connection.cursor()

    try:
        # ------------------------------------------------------------------
        # STEP 1: Insert the indicator into the "indicators" table.
        #
        # We only provide indicator_value and indicator_type.
        # We do NOT touch first_seen — MySQL auto-generates it with a
        # DEFAULT CURRENT_TIMESTAMP, so we must leave it out entirely.
        #
        # INSERT IGNORE means: if a row with this indicator_value already
        # exists, do nothing and skip silently (no error, no duplicate row).
        # ------------------------------------------------------------------
        insert_indicator_query = """
            INSERT IGNORE INTO indicators (indicator_value, indicator_type)
            VALUES (%s, %s)
        """
        cursor.execute(insert_indicator_query, (indicator_value, indicator_type))

        # ------------------------------------------------------------------
        # STEP 2: Get the ID of the indicator we just inserted (or the one
        # that already existed). We do a SELECT to find it by its value.
        # ------------------------------------------------------------------
        select_id_query = """
            SELECT indicator_id FROM indicators
            WHERE indicator_value = %s
        """
        cursor.execute(select_id_query, (indicator_value,))

        # fetchone() returns the first row of the result as a tuple
        result_row = cursor.fetchone()

        # Safety check: if for some reason we got nothing back, stop here
        if result_row is None:
            print(f"ERROR: Could not retrieve indicator ID for '{indicator_value}'.")
            connection.rollback()
            return False

        # The indicator_id is the first (and only) column in the result
        indicator_id = result_row[0]

        # ------------------------------------------------------------------
        # STEP 3: Insert or update the "sightings" table.
        #
        # The sightings table does NOT have a first_seen column.
        # It only has: sighting_id, indicator_id, source_id, severity_score,
        # and last_seen.
        #
        # INSERT ... ON DUPLICATE KEY UPDATE means:
        #   - If this (indicator_id, source_id) pair does NOT exist yet:
        #       insert a brand new row with last_seen = NOW().
        #   - If it ALREADY exists (duplicate key):
        #       only update last_seen to NOW() and update severity_score
        #       with the newest value received.
        # ------------------------------------------------------------------
        upsert_sighting_query = """
            INSERT INTO sightings (indicator_id, source_id, severity_score, last_seen)
            VALUES (%s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                last_seen      = NOW(),
                severity_score = %s
        """
        cursor.execute(upsert_sighting_query, (indicator_id, source_id, severity_score, severity_score))

        # Commit saves all changes permanently to the database
        connection.commit()

        print(f"SUCCESS: Indicator '{indicator_value}' processed. Sighting saved/updated.")
        return True

    except Exception as error:
        # If anything went wrong, rollback cancels ALL changes made in this transaction.
        # This prevents the database from ending up in a broken/partial state.
        print(f"ERROR in process_ioc(): {error}")
        connection.rollback()
        return False

    finally:
        # The "finally" block always runs, whether there was an error or not.
        # We always close the cursor and connection to free up resources.
        cursor.close()
        connection.close()


# ---------------------------------------------------------------------------
# FUNCTION: get_threat_history
# ---------------------------------------------------------------------------
# Purpose: Looks up an IP address in the database and returns its complete
#          threat history by joining three related tables together.
#
# Parameters:
#   ip (str) - The IP address to search for, e.g. "192.168.1.1"
#
# Returns:
#   A list of dictionaries, where each dictionary is one sighting record.
#   Returns an empty list if the IP was not found or an error occurred.
# ---------------------------------------------------------------------------
def get_threat_history(ip):

    # Open a connection to the database
    connection = create_connection()

    # If the connection failed, return an empty list
    if connection is None:
        print("ERROR: Could not connect to the database in get_threat_history().")
        return []

    # dictionary=True makes each row come back as a dict like {"column": "value"}
    # instead of a plain tuple like ("value1", "value2"). Much easier to read.
    cursor = connection.cursor(dictionary=True)

    try:
        # ------------------------------------------------------------------
        # This SELECT uses two JOINs to pull data from three tables at once:
        #
        #   indicators  - holds the IP/domain value, its type, AND first_seen
        #   sightings   - holds last_seen and severity_score (NO first_seen here)
        #   sources     - holds the name of who reported it (e.g. "VirusTotal")
        #
        # IMPORTANT column locations (fixed from previous version):
        #   first_seen  → comes from indicators (not sightings)
        #   last_seen   → comes from sightings  (not indicators)
        #
        # We filter with WHERE to only return rows matching our target IP.
        # ------------------------------------------------------------------
        join_query = """
            SELECT
                indicators.indicator_value,
                indicators.indicator_type,
                indicators.first_seen,
                sightings.severity_score,
                sightings.last_seen,
                sources.source_name
            FROM indicators
            JOIN sightings ON indicators.indicator_id = sightings.indicator_id
            JOIN sources   ON sightings.source_id     = sources.source_id
            WHERE indicators.indicator_value = %s
            ORDER BY sightings.last_seen DESC
        """
        cursor.execute(join_query, (ip,))

        # Fetch all matching rows at once
        rows = cursor.fetchall()

        if len(rows) == 0:
            print(f"INFO: No threat history found for IP '{ip}'.")
        else:
            print(f"INFO: Found {len(rows)} sighting record(s) for IP '{ip}'.")

        return rows

    except Exception as error:
        # If the query failed, log the error and return an empty list
        print(f"ERROR in get_threat_history(): {error}")
        connection.rollback()
        return []

    finally:
        # Always close the cursor and connection when done
        cursor.close()
        connection.close()
