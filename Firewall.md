# Firewall

For this practical class, I simply use a kali "client" on the network.

---

## Summary

1. [nftables filter](#nftables-filter)

---

## nftables filter

Setting up a local nftables filter on srv-web

### Create new table:
First, we need to define a new table and an input chain that will handle filtering rules. The chain is attached to the input hook with priority 0.

```
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \; }
```

### Add the following rules:
These rules will define what type of traffic is allowed or denied.

Allow established and related traffic: This ensures that replies to already established connections (such as ongoing SSH or HTTP sessions) are accepted.

```
nft add rule inet filter input ct state established,related accept
```

### Allow SSH (port 22) and HTTP (port 80):
These are the essential services we want accessible from external clients.

```
nft add rule inet filter input tcp dport 22 accept
nft add rule inet filter input tcp dport 80 accept
```

### Deny all other traffic: 
Any packet not explicitly allowed by the rules above will be dropped.

```
nft add rule inet filter input drop
```

### Test from client01:
From another machine (client01), verify that the rules behave as expected:

#### Check connectivity with a simple ping:

```
ping srv-web
```
Observation : The ping did not come back.


#### Test HTTP access:

```
curl http://srv-web
```
Observation : We can access to the website.

#### Test SSH access:

```
ssh user@srv-web
```
Observation : We can connect to ssh.

#### Test with netcat:
Use nc (netcat) to manually open a connection to the web server and simulate HTTP requests. This helps confirm that the filtering rules allow valid HTTP traffic.

First, simulate an HTTP/1.1 request:

```
nc -C srv-web 80
GET / HTTP/1.1
Host: client.local
```
Observation : We do not have a full response.

Then, test with an HTTP/2.0 request:

```
nc -C srv-web 80
GET / HTTP/2.0
Host: client.local
```
Observation : We do have a full response.

