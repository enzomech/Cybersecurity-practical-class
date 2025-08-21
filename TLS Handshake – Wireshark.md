
# TLS Handshake – Wireshark

For this practical class, I simply use wireshark on my network.

---

## Summary

1. [Handshake messages](#Handshake-messages)
2. [Protocol version & cipher suites](#Protocol-version-&-cipher-suites)
3. [Key negotiation](#Key-negotiation)
4. [Supported version analyse](#Supported-version-analyse)

---

## Handshake messages

The TLS handshake begins with a ClientHello (sent by the client) and a ServerHello (sent by the server). 
These messages set the foundation for the encrypted session.
Filter to use in Wireshark: tls.handshake
Here is my ClientHello :

<img width="1862" height="1113" alt="TP Client Hello" src="https://github.com/user-attachments/assets/30e4b595-f571-4f22-a9cc-d85197c29541" />


---

## Protocol version & cipher suites

ClientHello: proposes a list of supported protocol versions (e.g., TLS 1.2, TLS 1.3) and available cipher suites (AES, ChaCha20, etc.).
ServerHello: selects exactly one version and one cipher suite from the client’s list.
Here is my ServerHello :

<img width="1881" height="581" alt="TP Server Hello" src="https://github.com/user-attachments/assets/db710cd5-accc-4176-9d0f-55cc234160d4" />

We can see that the Cipher Suite selected by the server is :
```
Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
```

---

## Key negotiation

In ClientHello, the extension key_share contains the client’s public key (e.g., X25519).

<img width="1120" height="261" alt="TP Keyshare client" src="https://github.com/user-attachments/assets/99fdc8fd-1c70-4587-99f2-80cbb01ab406" />

In ServerHello, the server sends its own public key.

<img width="1120" height="230" alt="TP Keyshare server" src="https://github.com/user-attachments/assets/da0131f0-ecf8-4fff-ae20-b08699fcb0ec" />

Both are combined through Diffie-Hellman to generate a shared secret used for encryption.

The Diffie-Hellman exchange is visible in the key_share extension of both ClientHello and ServerHello. 
Each side provides a public key (e.g., X25519), which is later combined to generate a shared secret. 
Wireshark only shows the public values, not the final secret.

---


## Transition to encrypted traffic

Immediately after the ServerHello, the handshake continues with encrypted messages (e.g., EncryptedExtensions, Finished). 
This confirms that key exchange worked, and from this point, application data (like HTTP) is protected.

---


## Supported version analyse

The field supported_versions in the ClientHello lists all TLS protocol versions the client can handle (e.g., TLS 1.2, TLS 1.3). 
The server then selects one version in the ServerHello, ensuring both parties use a common and secure protocol.
If a server still accepted TLS 1.0, it would create a serious security risk: this version is outdated, weak against modern attacks, and lacks strong cryptographic protections. 
An attacker could exploit vulnerabilities to downgrade the connection or decrypt sensitive data.

---

```text
Client                          Server
  | ---- ClientHello ---------> |
  |   supported_versions:       |
  |   [TLS1.3, TLS1.2]          |
  |                             |
  | <----- ServerHello -------- |
  |   selected_version: TLS1.3  |
  |                             |
  | (If TLS1.0 accepted → risk) |





