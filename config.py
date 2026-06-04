from dotenv import load_dotenv
import os

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
HOST = os.getenv("HOST")
DATABASE = os.getenv("DATABASE")
PORT = os.getenv("PORT")

ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")