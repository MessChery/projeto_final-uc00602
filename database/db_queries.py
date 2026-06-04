
from db_connector import create_connection


def process_ioc(indicator_value, indicator_type, source_id, severity_score):

    connection = create_connection()

    if connection is None:
        print("ERROR: Could not connect to the database in process_ioc().")
        return False

    cursor = connection.cursor()

    try:
        insert_indicator_query = """
            INSERT IGNORE INTO indicators (indicator_value, indicator_type)
            VALUES (%s, %s)
        """
        cursor.execute(insert_indicator_query, (indicator_value, indicator_type))

        select_id_query = """
            SELECT indicator_id FROM indicators
            WHERE indicator_value = %s
        """
        cursor.execute(select_id_query, (indicator_value,))

        result_row = cursor.fetchone()

        if result_row is None:
            print(f"ERROR: Could not retrieve indicator ID for '{indicator_value}'.")
            connection.rollback()
            return False

        indicator_id = result_row[0]

        upsert_sighting_query = """
            INSERT INTO sightings (indicator_id, source_id, severity_score, last_seen)
            VALUES (%s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                last_seen      = NOW(),
                severity_score = %s
        """
        cursor.execute(upsert_sighting_query, (indicator_id, source_id, severity_score, severity_score))

        connection.commit()

        print(f"SUCCESS: Indicator '{indicator_value}' processed. Sighting saved/updated.")
        return True

    except Exception as error:
        print(f"ERROR in process_ioc(): {error}")
        connection.rollback()
        return False

    finally:
        cursor.close()
        connection.close()


def get_threat_history(ip):

    connection = create_connection()

    if connection is None:
        print("ERROR: Could not connect to the database in get_threat_history().")
        return []

    cursor = connection.cursor(dictionary=True)

    try:
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

        rows = cursor.fetchall()

        if len(rows) == 0:
            print(f"INFO: No threat history found for IP '{ip}'.")
        else:
            print(f"INFO: Found {len(rows)} sighting record(s) for IP '{ip}'.")

        return rows

    except Exception as error:
        print(f"ERROR in get_threat_history(): {error}")
        connection.rollback()
        return []

    finally:
        cursor.close()
        connection.close()
