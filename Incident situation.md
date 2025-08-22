
# Incident situation

For this practical class, I manage an IT infrastructure through Proxmox.

---

## Summary

1. [Scenario](#Scenario)
2. [Investigation](#Investigation)
3. [Stopping attack](#Stopping-attack)
4. [Verify Effectiveness](#Verify-Effectiveness)
5. [Isolated Machine Investigation](#Isolated-Machine-Investigation)
6. [Cleanup and Remediation](#Cleanup-and-Remediation)
7. [Rapport conclusion](#Rapport-conclusion)
8. [Recommendations](#Recommendations)

---

## Scenario

I have recently joined a French company as the new system administrator, taking over responsibility for the IT services.

The company’s infrastructure is currently composed of three machines:

- A client machine located on the 172.19.0.0/24 network

- A server machine located on the 172.20.0.0/24 network

- A third machine that no longer has any network interface other than its loopback, and therefore does not appear to communicate externally anymore

Shortly after I started, I was contacted by the IT department of another French company. 
They reported that they had observed cyberattacks targeting their network on 10.0.0.196, and to their surprise, the malicious traffic seemed to originate from our company.

My task is now to investigate which machine(s) in our environment may have been compromised and used as a bot to launch attacks against external infrastructures.


---

## Investigation

Identify active hosts and services using tools such as nmap and arp-scan.
Validate connectivity and confirm network configuration.


### Host Discovery

Objective:

Detect active hosts within the internal networks (172.19.0.0/24 and 172.20.0.0/24). This allows us to identify which machines are up and potentially communicating.

Commands:

#### ICMP sweep with Nmap (no port scan)

```
- sudo nmap -sn -n 172.19.0.0/24
- sudo nmap -sn -n 172.20.0.0/24
```

```nmap -sn``` performs a ping sweep to identify live hosts without scanning for services.

```
nmap -sn -n 172.19.0.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-22 04:11 EDT
Nmap scan report for 172.19.0.22
Host is up (0.00034s latency).
MAC Address: BC:24:11:FB:F0:03 (Proxmox Server Solutions GmbH)
Nmap scan report for 172.19.0.254
Host is up (0.00026s latency).
MAC Address: BC:24:11:56:E8:C9 (Proxmox Server Solutions GmbH)
Nmap scan report for 172.19.0.100
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.06 seconds

nmap -sn -n 172.20.0.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-22 04:11 EDT
Nmap scan report for 172.20.0.10
Host is up (0.00049s latency).
Nmap scan report for 172.20.0.254
Host is up (0.00034s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 4.02 seconds
```

We only have my kali on 172.19.0.100, and the server and client on their network, nothin suspicious found.


### Service Enumeration

Objective:

Determine which services are exposed on the discovered hosts. This helps identify unusual or unauthorized applications (e.g., a client machine unexpectedly running a server service).

Commands:

Scan common ports
```
sudo nmap -sS -Pn -n --top-ports 50 $ip
```

Lightweight version detection
```
sudo nmap -sS -sV -Pn -n --top-ports 50 $ip
```


Explanation:

```-sS``` uses a SYN scan (stealthier than a full TCP connect).

```-Pn``` skips host discovery (useful if ICMP is blocked).

```--top-ports 50``` limits the scan to the 50 most common ports, reducing noise.

```-sV``` attempts to identify the service version (e.g., Apache, SSH, etc.).

Results:

```
Nmap scan report for 172.20.0.10
Host is up (0.00040s latency).
Not shown: 47 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```

```
Nmap scan report for 172.19.0.22
Host is up (0.00012s latency).
Not shown: 49 closed tcp ports (reset)
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
MAC Address: BC:24:11:FB:F0:03 (Proxmox Server Solutions GmbH)
```


### Active Connections

Objective:

Inspect current network activity from each machine to detect suspicious outbound connections, such as repeated contact with external servers or Command & Control infrastructure.

Commands:

List established TCP/UDP connections
```
ss -tunap
```

List processes and their open sockets
```
sudo lsof -i -P -n
```

Display neighbor (ARP) table
```
ip neigh show
```


Explanation:

```ss -tunap``` shows active TCP/UDP sockets with process IDs.

```lsof -i -P -n``` maps open sockets to specific processes, revealing which applications are communicating.

```ip neigh show``` lists ARP neighbors (other machines in direct communication).


Results:

On the ```ss -tunap``` on the server machine ```172.20.0.10``` I can localize the attacking machine, the server is so compromised.

<img width="2338" height="1054" alt="TP ss tunap" src="https://github.com/user-attachments/assets/837b7c35-07df-49b6-9b5f-d80b68227e00" />



---

## Stopping attack


Objective:

Stop the ongoing attack without disabling essential services (SSH, Apache, MariaDB).
Block Malicious Outbound Traffic (Granular Isolation)

Commands (nftables):

Create a dedicated table for emergency blocks
```
sudo nft add table inet incident
```

Create an output chain
```
sudo nft add chain inet incident output '{ type filter hook output priority 0; }'
```

Drop all outbound traffic to the victim
```
sudo nft add rule inet incident output ip daddr 10.0.0.196 drop
```

Explanation:

A new nftables table (incident) isolates incident-response rules from normal firewall rules.

The rule specifically blocks outgoing traffic to 10.0.0.196, while allowing all other services to function normally.


---

## Verify Effectiveness

Commands:

# Attempt to connect to the victim (should be blocked)
```
curl -v http://10.0.0.196
```

# Check that no new connections are opened
```
ss -tunap | grep "10.0.0.196"
```


Explanation:

If the rule is working, no new TCP connections should establish to 10.0.0.196.

The server’s legitimate services remain reachable from internal clients.

Results:

The curl didn't give me responses and the ```ss -tunap``` command show me a clear traffic :

```
root@server01:~# ss -tunap | grep "10.0.0.196"
tcp   SYN-SENT 0      1        172.20.0.10:53324   10.0.0.196:80    users:(("nc",pid=6849,fd=3))   
```


---

## Isolated Machine Investigation

Review local logs and file integrity.

Assess whether the network interface was intentionally disabled due to a prior infection.

### Check for outbound connections

```sudo lsof -i @10.0.0.196```

Result:

```
COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
nc      6856 root    3u  IPv4  36972      0t0  TCP 172.20.0.10:35384->10.0.0.196:http (SYN_SENT)
```

Explanation:

The command shows which processes are communicating with a specific host. Here, a nc (netcat) process running as root is attempting to connect to 10.0.0.196 on port 80. This is a strong indicator of malicious activity.


### Review Apache access logs

```sudo tail -n 200 /var/log/apache2/access.log```

Result:

```
10.0.0.203 - - [22/Aug/2025:09:21:09 +0200] "GET / HTTP/1.1" 200 3380 ...
10.0.0.203 - - [22/Aug/2025:09:21:10 +0200] "GET /icons/openlogo-75.png ...
```

Explanation:

Normal HTTP requests from another machine (10.0.0.203). Nothing suspicious in these lines.


### Review Apache error logs

```sudo tail -n 200 /var/log/apache2/error.log```


Result:

```
[Fri Aug 22 09:15:02.531376 2025] [mpm_event:notice] ... Apache/2.4.62 (Debian) configured
```

Explanation:

Only standard startup messages. No signs of exploitation attempts.

### Inspect cron jobs

```
crontab -l
```

Result:

```
no crontab for root
```

```
sudo ls -l /etc/cron.*
```

Result:

Only default system cron jobs (apache2, apt-compat, logrotate, etc.).

Explanation:

No malicious persistence through cron tasks.

### Check temporary directories

```sudo find /tmp /var/tmp /dev/shm -type f -exec ls -lh {} \;```


Result:

```
-rwxr-xr-x 1 root root 64  9 août  23:40 /tmp/bot.sh
```

Explanation:

A suspicious script named bot.sh was found in /tmp. This is likely the source of the malicious netcat process.


## Cleanup and Remediation

### Analyze the malicious script

```
cat /tmp/bot.sh
```

Purpose:

Display the script’s content to understand its behavior (downloading payloads, spawning processes, persistence attempts).
This helps determine how the system was compromised.

Result :

```
#!/bin/bash

while true; do nc -zv 10.0.0.196 80; sleep 2; done
```

So this is only a simple loop that do a netcat on the victim each 2 seconds.


### Kill the malicious process

```
sudo kill -9 6856
```

Purpose:

Terminate the identified malicious nc process (PID 6856).
Ensures the bot is no longer actively communicating with the attacker.


### Remove the script

```
sudo rm -f /tmp/bot.sh
```

Purpose:

Delete the discovered malicious file to prevent re-execution.


### Check for persistence

```
sudo grep -r "bot.sh" /etc/cron* /var/spool/cron
sudo systemctl list-unit-files | grep enabled
```

Purpose:

Verify whether the attacker tried to persist via cron jobs or systemd services.
(Already confirmed no malicious cron entries, but double-checking is recommended.)

Result :

No malicious trace found.


### Monitor for other suspicious files

```
sudo find / -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | grep -i "bot"
```

Purpose:

Search the filesystem for other scripts or payloads related to the infection.

Result :

No malicious trace found.


### Review user accounts and privileges

```
sudo cat /etc/passwd | grep -vE "nologin|false"
sudo last
```

Purpose:

Check for unauthorized accounts or unexpected logins.
Attackers sometimes create new users for persistence.

Result :

No trace of privilege escalation.


### Update and patch

```
sudo apt update && sudo apt upgrade -y
```

Purpose:

Ensure the server is running the latest security patches to reduce re-infection risks.


---

## Rapport conclusion


Suspicious outbound traffic observed on the port 80 of the IP attacked provided.

Malicious process identified, a simple script was the origin, everything was cleaned.

Signs of compromise detected on server machine.

Based on the collected evidence, determine whether the company’s systems were indeed compromised and used to perform attacks against the external organization.



---

## Recommendations


Pursue invesitgation and immediately isolate any compromised machine from the network.

Perform cleanup or full reinstallation where required.

Apply security patches and updates.

Strengthen monitoring with IDS/IPS solutions and centralized logging (e.g., SIEM).

Conduct awareness training for administrators and employees.



---
