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

def get_scans_data():
    """Queries and formats scan results from the database."""
    # Execute the SQL query
    scans = query_db("SELECT id, essid, bssid, channel, avg_power, auth, enc, scanned_at, whitelist_id FROM scan_results ORDER BY scanned_at DESC LIMIT 100")

    # Format the results into a list of dictionaries
    return [{
        "id": row['id'],
        "essid": row['essid'],
        "bssid": row['bssid'],
        "channel": row['channel'],
        "avg_power": row['avg_power'],
        "auth": row['auth'],
        "enc": row['enc'],
        "scanned_at": row['scanned_at'],
        "whitelist_id": row['whitelist_id']
    } for row in scans]

def get_alerts_data():
    """Queries and formats alerts from the database."""
    # Execute the SQL query
    alerts = query_db("SELECT id, essid, bssid, channel, avg_power, auth, enc, alert_type, detected_at, whitelist_id FROM alerts ORDER BY detected_at DESC LIMIT 50")

    # Format the results into a list of dictionaries
    return [{
        "id": row['id'],
        "essid": row['essid'],
        "bssid": row['bssid'],
        "channel": row['channel'],
        "avg_power": row['avg_power'],
        "auth": row['auth'],
        "enc": row['enc'],
        "alert_type": row['alert_type'],
        "detected_at": row['detected_at'],
        "whitelist_id": row['whitelist_id']
    } for row in alerts]

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
    """Fetches scan results from the local DB (pulled from S3) and returns them as a JSON response."""
    scans = get_scans_data()
    return jsonify(scans)

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Fetches alerts from the local DB (pulled from S3) and returns them as a JSON response."""
    alerts = get_alerts_data()
    return jsonify(alerts)


# --- Application Run ---
if __name__ == '__main__':

    download_db_from_s3()

    app.run(host='0.0.0.0', port=5000)
