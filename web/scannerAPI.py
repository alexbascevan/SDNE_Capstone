import json
import logging
import os
import sys
from flask import Flask, jsonify
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- BUCKET NAME RETRIEVAL ---
# AWS credentials will be automatically handled by the EC2 Instance Role.
bucket_name = os.getenv('S3_BUCKET_NAME')

if not bucket_name:
    logger.error("Error: S3_BUCKET_NAME environment variable is not set. The application cannot connect to S3.")
    # Exit with a non-zero status code if configuration is missing
    sys.exit(1) 

# Initialize S3 client. Boto3 will automatically look for the EC2 role credentials.
s3_client = boto3.client('s3')

def get_most_recent_scans():
    scans = []
    alerts = []
    
    try:
        # Check if the bucket exists and we have permissions by attempting to list objects.
        s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        
        # 1. Fetch Scan Results
        try:
            obj_scans = s3_client.get_object(Bucket=bucket_name, Key='scan_results.json')
            scans = json.loads(obj_scans['Body'].read())
        except ClientError as e:
            # A 404 error here is expected if the file doesn't exist yet, but still log it.
            logger.error(f"Error fetching scan_results.json: {e}")
        
        # 2. Fetch Alerts
        try:
            obj_alerts = s3_client.get_object(Bucket=bucket_name, Key='alerts.json')
            alerts = json.loads(obj_alerts['Body'].read())
        except ClientError as e:
            logger.error(f"Error fetching alerts.json: {e}")

    except (NoCredentialsError, ClientError, json.JSONDecodeError) as e:
        # This catch handles connection errors, including any persistent 403 Forbidden errors.
        logger.error(f"Error connecting to S3 or decoding JSON: {e}")
        return [], []
    
    return scans, alerts

@app.route('/scans', methods=['GET'])
def get_scans():
    scans, _ = get_most_recent_scans()
    return jsonify(scans)

@app.route('/alerts', methods=['GET'])
def get_alerts():
    _, alerts = get_most_recent_scans()
    return jsonify(alerts)

@app.route('/scans/latest', methods=['GET'])
def get_latest_scans():
    scans, _ = get_most_recent_scans()
    return jsonify(scans)

@app.route('/alerts/latest', methods=['GET'])
def get_latest_alerts():
    _, alerts = get_most_recent_scans()
    return jsonify(alerts)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
