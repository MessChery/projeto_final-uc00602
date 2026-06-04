import os
import mysql.connector
from mysql.connector import Error
import dotenv

dotenv.load_dotenv()

def create_connection():
    """
    Establishes a connection to the MySQL database.
    Returns the connection object if successful, or None if an error occurs.
    """
    try:
        connection = mysql.connector.connect(
            host=os.getenv('HOST'),
            database=os.getenv('DATABASE'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            port=os.getenv('PORT')
        )
        if connection.is_connected():
            print("Connection to MySQL database was successful.")
            return connection
    except Error as db_error:
        print(f"Error while connecting to MySQL: {db_error}")
        return None
    