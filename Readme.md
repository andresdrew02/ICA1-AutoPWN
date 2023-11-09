## Autopwn Script for VulnHub Machine (ICA1)

This script is designed to automate the process of gaining low privileges on the ICA1 machine from VulnHub. The script employs various techniques, such as extracting database credentials, performing brute-force attacks on SSH, and establishing a shell on the target machine.

### Prerequisites
- Python 3.x
- Required Python packages (install using `pip install -r requirements.txt`):
  - requests
  - yaml
  - re
  - mysql-connector-python
  - base64
  - paramiko
  - threading
  - inquirer
  - argparse
  - termcolor
  - pwn
  - itertools
  - ping3

### Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/andresdrew02/ICA1-AutoPWN.git
   cd ICA1-AutoPWN
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the script with the target machine's IP address as an argument:
   ```bash
   python3 autopwn.py <TARGET_IP>
   ```

### Functionality

#### 1. Database Credentials Extraction
The script first attempts to download the `databases.yml` file from the target machine at the specified IP address. It then parses this file to extract the username and encoded password for the database.

#### 2. Database Users Dump
Using the obtained credentials, the script connects to the MySQL database on the target machine and retrieves the usernames and their corresponding passwords from the 'staff' database.

#### 3. SSH Brute-Force
The script launches a multi-threaded SSH brute-force attack using the previously extracted usernames and passwords. For each successful authentication, the script adds the credentials to the list of matches.

#### 4. User Selection
After the brute-force attack, the user is prompted to select a valid username from the list of successfully authenticated credentials.

#### 5. Shell Establishment
Finally, the script establishes an SSH connection to the target machine using the selected username and password. Once connected, it provides an interactive shell for executing commands on the target.

### Note
- This script is designed for educational and ethical testing purposes only. Unauthorized access to computer systems is illegal and could result in severe consequences.
- First autopwn made by me :)

### Disclaimer
The author is not responsible for any misuse or damage caused by this script. Use it responsibly and only on systems for which you have explicit permission.
