Phase 1:

    - Define files that will be monitored by the program in the .yaml file
        - This is more specific but detect brute-force attacks by setting/adjust        ing a threshold
    - Hash the monitored files and store into baseline_hashes.txt
        - On each subsequent run after, compare each new hash file to the ones
        stored in baseline_hashes.txt to check for tampering
    - Log SSH failed logins 
    - Alert system via writing to alerts.log
    - (Side note) .venv/ is just for testing

Phase 2:

    - Auto block suspicious IP addresses with iptables 
    - Process monitoring: check for suspicious processes running on the system
        - this is for attackers utilizing concept of reverse shell or nmap
    - Add alert mechanism that sends the alert to email, slack, or etc
    - Sign baseline to avoid tampering of hash values  
