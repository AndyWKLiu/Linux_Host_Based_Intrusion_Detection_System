import yaml                             # parse the yaml file
import os
import time                         
import re
import hashlib                          # create sha-256 hashes of config.yaml
from datetime import datetime, timedelta
from collections import defaultdict 

# Filenames within the directory that the program will use
config_file = "config.yaml"
baseline_file = "baseline_hashes.txt"
alert_file = "alert.log"

# Open config_file and load into dictionary
def load_config():
    with open(config_file, "r") as f:
        return yaml.safe_load(f)

# Load baseline_file into dictionary
def load_baseline():
    baseline_dict = {}
    if os.path.exists(baseline_file):
        with open(baseline_file, "r") as f:
            # Create dictionary of file to hashed_value
            for line in f:
                file, hashed_value = line.strip().split(" ")
                baseline_dict[file] = hashed_value
    return baseline_dict

# Hash files
def hash_file(file):
    hasher = hashlib.sha256()
    try:
        # Open file and read chunks of 4096 bytes
        with open(file, "rb") as f:
            chunk = f.read(4096)        # Read first 4096 bytes
            while chunk:
                hasher.update(chunk)    # Add chunk to the hash object
                chunk = f.read(4096)    # Read next 4096 bytes
        return hasher.hexdigest()       # Return the file as hexadecimal string
    except FileNotFoundError:
        return None

# Log any alerts
def alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[timestamp] ALERT: {message}"
    print(log_message)
    with open(alert_file, "a") as f:
        f.write(log_message + "\n")

# Save current file-hash mapping into baseline_hashes.txt
def save_baseline_file(baseline):
    with open(baseline_file, "w") as f:
        for file, hashed_value in baseline.items():
            # Goes back to load_baseline function on how each line should look like
            f.write(f"{file} {hashed_value}\n")

def integrity_check_monitored_files(monitor_files, baseline):
    # Loop through each file: 
        for file in monitor_files:
            current_hash_file = hash_file(file)     # Hash files
            if not current_hash_file:               # Missing file
                alert(f"File missing: {file}")
                continue

            # Save file to baseline if not already included
            if file not in baseline:
                baseline[file] = current_hash_file
                save_baseline_file(baseline)
                continue
            
            # Hash in baseline does not match current hash in the loop
            if baseline[file] != current_hash_file:
                alert(f"File integrity violation detected: {path}")

def monitored_files_ssh(log_file, login_threshold, time_window_threshold):
    failed_logins = defaultdict(list) # Track amount of failed login attempts
    pattern = re.compile(r"Failed password.*from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    with open(log_file, "r") as f:
        for line in f:
            match = pattern.search(line) # Look for failed login lines
            if match:
                ip_address = match.group(1)
                current_time = datetime.now()
                failed_logins[ip_address].append(time)
                '''
                Only keep the  values in the key-value pair of failed_logins that exceeds cutoff
                '''
                cutoff = current_time - timedelta(seconds = time_window_threshold)
                failed_logins[ip] = [i for i in failed_logins[ip] if i > time_window_threshold]
                if len(failed_logins[ip] > login_threshold):
                    alert(f"SSH brute-force detected from {ip_address}")

def main():
    config = load_config()              # Load config file
    baseline = load_baseline()          # Load baseline file

    # File Integrity check monitored files with baseline 
    integrity_check_monitored_files(config["monitored_files"], baseline)

    # Detect SSH-brute force
    monitored_files_ssh(config["ssh"]["log_file"],
                        config["ssh"]["failed_sshlogin_threshold"],
                        config["ssh"]["threshold_time_window"])

if __name__ == "__main__":
    main()
