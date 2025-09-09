## **Project Naming & AWS Resources**

  * **Project Naming Convention:** `Capstone_2025_...`
  * **S3 Bucket:** `capstone-2025-wifi-scanner-data`
  * **IAM User (for Pi):** `Capstone_2025_Pi_User`
  * **IAM Policy (for Pi):** `Capstone_2025_Pi_Policy`
  * **EC2 Instance:** `Capstone_2025_Web_Server`
  * **IAM Role (for EC2):** `Capstone_2025_EC2_Role`
  * **IAM Policy (for EC2):** `Capstone_2025_EC2_Policy`
  * **DB File:** `wifi_scan.db`

-----

## **Step 1: AWS Setup** ☁️

### **A. Create an S3 Bucket**

1.  Navigate to the **S3 service** in the AWS Management Console.
2.  Click **"Create bucket"**.
3.  Name the bucket: **`capstone-2025-wifi-scanner-data`**.
4.  Select a nearby **AWS Region**.
5.  Click **"Create bucket"**.

### **B. Create an IAM User for the Raspberry Pi**

1.  Go to the **IAM service** and click **"Users" \> "Create user"**.
2.  Name the user: **`Capstone_2025_Pi_User`**.
3.  Click **"Next"**.
4.  Select **"Attach policies directly"** and click **"Create policy"**.
5.  In the new tab, select the **"JSON"** tab and paste the following policy, replacing `<your-region>` and `<your-account-id>`:
      * ```json
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
        ```
6.  Name the policy **`Capstone_2025_Pi_Policy`** and click **"Create policy"**.
7.  Return to the user creation tab, refresh the policy list, select **`Capstone_2025_Pi_Policy`**, and click **"Next" \> "Create user"**.
8.  After creation, click the user name, go to **"Security credentials"**, and click **"Create access key"**.
9.  Choose **"Other"** and then **"Create access key"**.
10. **IMPORTANT:** **Copy the Access key and Secret access key** and store them securely. They will not be visible again.

### **C. Launch an EC2 Instance and Configure Permissions**

1.  Navigate to the **EC2 service** and click **"Launch instance"**.
2.  Name the instance: **`Capstone_2025_Web_Server`**.
3.  Select a free-tier eligible **AMI** (e.g., Ubuntu Linux) and **instance type** (e.g., `t2.micro`).
4.  Create a new **key pair** for SSH access.
5.  Configure the **Security Group** to allow inbound traffic:
      * **SSH (Port 22):** Source set to your IP.
      * **Custom TCP (Port 5000):** Source set to `0.0.0.0/0`.
      * **HTTP (Port 80) / HTTPS (Port 443):** If needed.
6.  Launch the instance.
7.  Navigate back to the **IAM service**, click **"Roles" \> "Create role"**.
8.  Select **"AWS service"** and **"EC2"**, then click **"Next"**.
9.  Click **"Create policy"** in a new tab.
10. Select the **"JSON"** tab and paste the following policy:
      * ```json
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
        ```
11. Name the policy **`Capstone_2025_EC2_Policy`** and click **"Create policy"**.
12. Go back to the role creation tab, refresh, select **`Capstone_2025_EC2_Policy`**, and click **"Next"**.
13. Name the role **`Capstone_2025_EC2_Role`** and click **"Create role"**.
14. In the EC2 dashboard, select your running instance.
15. Go to **"Actions" \> "Security" \> "Modify IAM role"**.
16. Select **`Capstone_2025_EC2_Role`** from the dropdown and click **"Update IAM role"**.

-----

## **Step 2: Raspberry Pi Automation** 🤖

1.  **Install `boto3`**:
      * `pip3 install boto3`
2.  **Configure AWS Credentials**:
      * Add the following lines to your Pi's `.zshrc` file:
          * `export AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY_ID"`
          * `export AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"`
          * `export AWS_DEFAULT_REGION="your-aws-region"`
      * Run `source ~/.zshrc` to apply the changes.

-----

## **Step 3: Backend/Frontend Integration** 💻

### **A. Connect to the EC2 Instance**

1.  Use SSH to connect:
      * `ssh -i /path/to/your-key-pair.pem ubuntu@<EC2-Public-IP>`
2.  **Install dependencies** (run as `sudo`):
      * `sudo dnf update -y`
      * `sudo dnf install -y python3-boto3 python3-pip java-17-amazon-corretto-devel nginx nodejs`
      * `sudo dnf install git -y`
      * `sudo dnf install tmux -y`
      * `sudo dnf install maven -y`
      * `sudo dnf install -y java-21-amazon-corretto-devel`
3.  **Clone the repository**:
      * `git clone https://github.com/alexbascevan/SDNE_Capstone.git`
4.  **Compile the Java backend**:
      * `cd SDNE_Capstone/web/Frontend/Capstone_Gagandeep_kooner_Ava/`
      * `mvn clean package`
5.  **Start the backend**:
      * Start a new `tmux` session: `tmux`.
      * Start the Java application in one pane:
          * `java -jar target/Capstone_Gagandeep_Kooner_Ava-0.0.1-SNAPSHOT.jar`
6.  **Run the frontend**:
      * Switch to another `tmux` pane (`ctrl-b %`).
      * Navigate to the frontend directory: `cd src/main/capstone-frontend/`
      * Install dependencies: `npm install`
      * Install Angular CLI globally: `sudo npm install -g @angular/cli`
      * Run the frontend with the proxy config: `ng serve --proxy-config proxy-conf.json`
