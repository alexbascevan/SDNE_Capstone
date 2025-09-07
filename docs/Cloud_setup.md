Project Naming Convention: Capstone_2025_...
S3 Bucket: capstone-2025-wifi-scanner-data

IAM User (for Pi): Capstone_2025_Pi_User

IAM Policy (for Pi): Capstone_2025_Pi_Policy

EC2 Instance: Capstone_2025_Web_Server

IAM Role (for EC2): Capstone_2025_EC2_Role

IAM Policy (for EC2): Capstone_2025_EC2_Policy

DB File: wifi_scan.db

Step 1: AWS Setup ☁️
A. Create an S3 Bucket
Log in to the AWS Management Console and navigate to the S3 service.

Click "Create bucket".

For Bucket name, enter: capstone-2025-wifi-scanner-data.

Choose the AWS Region closest to you or your target audience.

Keep all other settings at their defaults and click "Create bucket".

B. Create an IAM User for the Raspberry Pi
Navigate to the IAM service in the AWS Management Console.

In the left-hand navigation pane, click "Users", then "Create user".

For User name, enter: Capstone_2025_Pi_User.

Keep all other options default and click "Next".

On the Set permissions page, select "Attach policies directly".

Click "Create policy". This will open a new tab.

In the new tab, select the "JSON" tab. Copy and paste the following policy, replacing your-region with your chosen AWS region and your-account-id with your actual AWS account ID.

JSON

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::capstone-2025-wifi-scanner-data/*"
        }
    ]
}
This policy grants permission to PutObject (upload) to your S3 bucket, and nothing else.

Click "Next". Give the policy a name: Capstone_2025_Pi_Policy.

Click "Create policy".

Go back to the user creation tab. Click the refresh button next to the policy list, search for Capstone_2025_Pi_Policy, and select it.

Click "Next", then "Create user".

After the user is created, click on the user name. Go to the "Security credentials" tab and click "Create access key".

Select "Application running on EC2" (even though it's a Pi, this is the most secure option for programmatic access). Note: The user won't be on an EC2 instance, so you should actually choose "Other" and set a custom tag. This is a crucial distinction. For our purposes, "Other" is the correct choice.

Click "Next". Provide a description tag if you want, then click "Create access key".

IMPORTANT: Copy the Access key and Secret access key. You will not be able to see the secret key again. Store these securely. These are the credentials your Raspberry Pi will use.

C. Launch an EC2 Instance and Configure its Permissions
Navigate to the EC2 service and click "Launch instance".

Name the instance: Capstone_2025_Web_Server.

Choose an AMI (Amazon Machine Image). A free-tier Linux AMI like Ubuntu or Amazon Linux is a good choice.

Choose a free-tier eligible instance type like t2.micro.

Create a new key pair for SSH access.

Configure the Security Group. Add rules for inbound traffic:

SSH (Port 22): For you to connect and set up the server. Set the source to your IP address.

Custom TCP (Port 5000): For your Python API. Set the source to 0.0.0.0/0 to allow access from anywhere, or restrict it to your IP for testing.

HTTP (Port 80) / HTTPS (Port 443): If your Spring application uses these ports, add them.

Review and launch the instance.

Once the instance is running, navigate to the IAM service again.

Click "Roles" in the left-hand navigation pane and "Create role".

For Trusted entity type, select "AWS service" and choose "EC2". Click "Next".

Search for AmazonS3ReadOnlyAccess and select it. While a custom policy is more secure, this pre-built policy is a quick way to grant read access to S3. For a more secure approach, you would create a custom policy like this:

JSON

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::capstone-2025-wifi-scanner-data/*"
        }
    ]
}
Let's create this custom policy for best practice.

Click "Create policy" and paste the JSON above. Name it Capstone_2025_EC2_Policy.

Go back to the role creation tab, refresh the policies, and search for Capstone_2025_EC2_Policy. Select it and click "Next".

Name the role: Capstone_2025_EC2_Role.

Review and click "Create role".

Go back to your running EC2 instance in the EC2 dashboard. Select it.

Go to "Actions" -> "Security" -> "Modify IAM role".

Select Capstone_2025_EC2_Role from the dropdown and click "Update IAM role".

Step 2: Raspberry Pi Automation 🤖
Install boto3: Open a terminal on your Raspberry Pi and run:

Bash

pip3 install boto3
Securely Configure AWS Credentials: DO NOT hardcode credentials in your script. The most secure method is to use environment variables. In your Pi's .zshrc file, add these lines:

export AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="your-aws-region"
Then, run source ~/.zshrc to load them.

Step 3: Backend/Frontend Integration 💻
A. Connect to the EC2 Instance
Use SSH to connect to your EC2 instance.

Bash

ssh -i /path/to/your-key-pair.pem ubuntu@<EC2-Public-IP>
Install all necessary dependencies for your Spring and Python applications (Java, Python, pip, etc.).

sudo dnf update -y

sudo dnf install -y python3-boto3 python3-pip java-17-amazon-corretto-devel nginx nodejs

sudo dnf install git -y

sudo dnf install tmux -y

sudo dnf install maven -y
sudo dnf install -y java-21-amazon-corretto-devel

git clone https://github.com/alexbascevan/SDNE_Capstone.git

Now cd into SDNE_Capstone/web/Frontend/Capstone_Gagandeep_kooner_Ava/ and run: mvn clean package to compile the java backend

start tmux by: tmux, then ctrl-b % and then

from project root, run java -jar target/Capstone_Gagandeep_Kooner_Ava-0.0.1-SNAPSHOT.jar to start the backend

use other tmux terminal to cd src/main/capstone-frontend/
run npm install
sudo npm install -g @angular/cli

run ng serve --proxy-config proxy-conf.json

