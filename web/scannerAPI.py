import os
import sqlite3 
import boto3
from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime
import tempfile

# --- Configuration and Setup ---

app = Flask(__name__)
CORS(app) # Allow requests from Spring Boot/Angular

# AWS S3 Configuration
S3_BUCKET_NAME = 'capstone-2025-wifi-scanner-data'
S3_DB_KEY = 'wifi_scan.db'
LOCAL_DB_PATH = os.path.join(tempfile.gettempdir(), S3_DB_KEY) # Use a temporary directory for the DB file

# Initialize a boto3 S3 client
s3_client = boto3.client('s3')

# --- Helper Functions ---

def download_db_from_s3():
    """Downloads the SQLite DB file from S3 to the local EC2 filesystem."""
    print(f"Attempting to download {S3_DB_KEY} from S3 bucket {S3_BUCKET_NAME} to {LOCAL_DB_PATH}...")
    try:
        # Download the file
        s3_client.download_file(S3_BUCKET_NAME, S3_DB_KEY, LOCAL_DB_PATH)
        print("Database file downloaded successfully.")
        return True
    except Exception as e:
        print(f"Error downloading DB file from S3: {e}")
        return False

def query_db(query, args=()):
    """
    Connects to the local SQLite DB, executes a query, fetches results, and closes the connection.
    Assumes the DB file is already downloaded to LOCAL_DB_PATH.
    """
    conn = None
    results = []
    try:
        # Establish connection to the local DB file
        conn = sqlite3.connect(LOCAL_DB_PATH)
        conn.row_factory = sqlite3.Row # Allows accessing columns by name
        cur = conn.cursor()
        # Execute the query
        cur.execute(query, args)
        results = cur.fetchall()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        results = []
    finally:
        # Ensure the connection is closed
        if conn:
            conn.close()
    # Return a list of row objects
    return results


# --- API Endpoints ---

@app.before_request
def before_request_check():
    """Hook to ensure the database file is downloaded before any request that needs it."""
    # Check if the DB file exists locally or if the download fails
    if not os.path.exists(LOCAL_DB_PATH) or (datetime.now().minute % 5 == 0 and datetime.now().second < 5): # Simple check to periodically re-download every 5 minutes
        # Attempt to download the latest version
        if not download_db_from_s3():

            print("Could not download DB file from S3. Proceeding with potentially stale data or empty results.")
    pass # Continue to the route handler

@app.route('/scans', methods=['GET'])
def get_scans():
    scans = query_db("SELECT * FROM scan_results ORDER BY scanned_at DESC LIMIT 100")
    return jsonify([{
        "id": row[0],
        "essid": row[1],
        "bssid": row[2],
        "channel": row[3],
        "avg_power": row[4],
        "auth": row[5],
        "enc": row[6],
        "scanned_at": row[7],
        "whitelist_id": row[8]
    } for row in scans])

@app.route('/alerts', methods=['GET'])
def get_alerts():
    alerts = query_db("SELECT * FROM alerts ORDER BY detected_at DESC LIMIT 50")
    return jsonify([{
        "id": row[0],
        "essid": row[1],
        "bssid": row[2],
        "channel": row[3],
        "avg_power": row[4],
        "auth": row[5],
        "enc": row[6],
        "alert_type": row[7],
        "detected_at": row[8],
        "whitelist_id": row[9]
    } for row in alerts])


# --- Application Run ---
if __name__ == '__main__':

    download_db_from_s3()

    app.run(host='0.0.0.0', port=5000)
