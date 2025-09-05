from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
from datetime import datetime
import os # Import the os module

app = Flask(__name__)
CORS(app)  # Allow requests from Spring Boot/Angular

# Get the users home directory regardless of device or where script is run from
home_directory = os.path.expanduser('~')
DB_PATH = os.path.join(home_directory, "SDNE_Capstone/db/wifi_scanner.db")

# Helper function to fetch data from SQLite
def query_db(query, args=()):
    # Check if the database file exists before trying to connect
    if not os.path.exists(DB_PATH):
        print(f"Error: Database file not found at {DB_PATH}")
        return []
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(query, args)
    rows = cursor.fetchall()
    conn.close()
    return rows

# API Endpoints
@app.route('/scans', methods=['GET'])
def get_scans():
    scans = query_db("SELECT * FROM scan_results ORDER BY scanned_at DESC")
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
    alerts = query_db("SELECT * FROM alerts ORDER BY detected_at DESC")
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # Accessible on Pi's IP
