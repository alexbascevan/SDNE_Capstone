import os
import json
import boto3
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Allow requests from Spring Boot/Angular

# AWS S3 Configuration
S3_BUCKET_NAME = 'capstone-2025-wifi-scanner-data'
S3_SCANS_KEY = 'scan_results.json'
S3_ALERTS_KEY = 'alerts.json'

# Initialize a boto3 S3 client
s3_client = boto3.client('s3')

# Helper function to fetch data from S3
def get_data_from_s3(key):
    """Fetches and parses a JSON file from an S3 bucket."""
    try:
        # Get the object from S3
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=key)
        # Read the content
        content = response['Body'].read().decode('utf-8')
        # Parse the JSON content
        return json.loads(content)
    except Exception as e:
        print(f"Error fetching data from S3: {e}")
        return []

# API Endpoints
@app.route('/scans', methods=['GET'])
def get_scans():
    """Fetches scan results from S3 and returns them as a JSON response."""
    scans = get_data_from_s3(S3_SCANS_KEY)
    # The data from S3 is already a list of dictionaries, so just return it.
    return jsonify(scans)

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Fetches alerts from S3 and returns them as a JSON response."""
    alerts = get_data_from_s3(S3_ALERTS_KEY)
    # The data from S3 is already a list of dictionaries, so just return it.
    return jsonify(alerts)

if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5000) # Accessible on EC2's public IP
