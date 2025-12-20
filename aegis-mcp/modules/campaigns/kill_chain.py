"""
Kill Chain Automation Framework - Red Team Edition

End-to-end attack campaign automation following:
- Lockheed Martin Cyber Kill Chain
- MITRE ATT&CK Framework
- Unified Kill Chain

Phases:
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objectives

Features:
- Automated phase transitions
- Fallback/alternative techniques
- OPSEC considerations
- Campaign state persistence
- Multi-target coordination
"""

import json
import time
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any, Callable, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class KillChainPhase(Enum):
    """Kill chain phases."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class AttackStatus(Enum):
    """Attack/technique status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    DETECTED = "detected"
    FALLBACK = "fallback"


class OPSECLevel(Enum):
    """Operational security levels."""
    LOUD = "loud"           # No concern for detection
    NORMAL = "normal"       # Basic OPSEC
    CAREFUL = "careful"     # Avoid common detections
    STEALTHY = "stealthy"   # Maximum stealth
    APT = "apt"             # Nation-state level


@dataclass
class Technique:
    """ATT&CK technique representation."""
    id: str              # e.g., T1566.001
    name: str
    tactic: str
    phase: KillChainPhase
    command: str = ""
    alternatives: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    opsec_impact: int = 3   # 1-5, higher = more detectable
    success_rate: float = 0.7


@dataclass
class Target:
    """Campaign target."""
    id: str
    hostname: str
    ip: str
    os: str = ""
    domain: str = ""
    status: str = "alive"
    access_level: str = "none"  # none, user, admin, system
    credentials: List[Dict] = field(default_factory=list)
    implants: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class CampaignObjective:
    """Campaign objective definition."""
    id: str
    name: str
    description: str
    target_data: List[str]      # Types of data to exfiltrate
    priority: int               # 1-5
    completed: bool = False
    completion_evidence: str = ""


@dataclass
class PhaseResult:
    """Result of a kill chain phase."""
    phase: KillChainPhase
    status: AttackStatus
    technique_used: str
    start_time: float
    end_time: float
    target: str
    output: str = ""
    artifacts: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)  # Generated IOCs


class TechniqueLibrary:
    """
    Library of ATT&CK techniques organized by phase.
    """

    TECHNIQUES = {
        KillChainPhase.RECONNAISSANCE: [
            Technique(
                id="T1595.002",
                name="Active Scanning: Vulnerability Scanning",
                tactic="Reconnaissance",
                phase=KillChainPhase.RECONNAISSANCE,
                command="nmap -sV -sC --script vuln {target}",
                opsec_impact=4
            ),
            Technique(
                id="T1592",
                name="Gather Victim Host Information",
                tactic="Reconnaissance",
                phase=KillChainPhase.RECONNAISSANCE,
                command="passive_recon --domain {target}",
                opsec_impact=1
            ),
            Technique(
                id="T1589",
                name="Gather Victim Identity Information",
                tactic="Reconnaissance",
                phase=KillChainPhase.RECONNAISSANCE,
                command="osint_harvest --domain {target} --emails --employees",
                opsec_impact=1
            ),
            Technique(
                id="T1596",
                name="Search Open Technical Databases",
                tactic="Reconnaissance",
                phase=KillChainPhase.RECONNAISSANCE,
                command="shodan search hostname:{target}",
                opsec_impact=1
            ),
        ],
        KillChainPhase.WEAPONIZATION: [
            Technique(
                id="T1587.001",
                name="Develop Capabilities: Malware",
                tactic="Resource Development",
                phase=KillChainPhase.WEAPONIZATION,
                command="generate_payload --type reverse_shell --format exe",
                opsec_impact=1
            ),
            Technique(
                id="T1588.002",
                name="Obtain Capabilities: Tool",
                tactic="Resource Development",
                phase=KillChainPhase.WEAPONIZATION,
                command="download_tool --name {tool}",
                opsec_impact=1
            ),
            Technique(
                id="T1027",
                name="Obfuscated Files or Information",
                tactic="Defense Evasion",
                phase=KillChainPhase.WEAPONIZATION,
                command="obfuscate --input payload.exe --technique polymorphic",
                opsec_impact=1
            ),
        ],
        KillChainPhase.DELIVERY: [
            Technique(
                id="T1566.001",
                name="Phishing: Spearphishing Attachment",
                tactic="Initial Access",
                phase=KillChainPhase.DELIVERY,
                command="send_phish --target {email} --template invoice --payload {file}",
                opsec_impact=3
            ),
            Technique(
                id="T1566.002",
                name="Phishing: Spearphishing Link",
                tactic="Initial Access",
                phase=KillChainPhase.DELIVERY,
                command="send_phish --target {email} --template meeting --url {url}",
                opsec_impact=3
            ),
            Technique(
                id="T1190",
                name="Exploit Public-Facing Application",
                tactic="Initial Access",
                phase=KillChainPhase.DELIVERY,
                command="exploit --target {url} --vuln {cve}",
                opsec_impact=4
            ),
            Technique(
                id="T1133",
                name="External Remote Services",
                tactic="Initial Access",
                phase=KillChainPhase.DELIVERY,
                command="brute_force --service {service} --target {ip} --creds {wordlist}",
                opsec_impact=5
            ),
        ],
        KillChainPhase.EXPLOITATION: [
            Technique(
                id="T1203",
                name="Exploitation for Client Execution",
                tactic="Execution",
                phase=KillChainPhase.EXPLOITATION,
                command="exploit_client --target {target} --vuln {cve}",
                opsec_impact=3
            ),
            Technique(
                id="T1059.001",
                name="Command and Scripting Interpreter: PowerShell",
                tactic="Execution",
                phase=KillChainPhase.EXPLOITATION,
                command="execute --type powershell --command {command}",
                opsec_impact=3
            ),
            Technique(
                id="T1059.004",
                name="Command and Scripting Interpreter: Unix Shell",
                tactic="Execution",
                phase=KillChainPhase.EXPLOITATION,
                command="execute --type bash --command {command}",
                opsec_impact=2
            ),
        ],
        KillChainPhase.INSTALLATION: [
            Technique(
                id="T1547.001",
                name="Boot or Logon Autostart Execution: Registry Run Keys",
                tactic="Persistence",
                phase=KillChainPhase.INSTALLATION,
                command="persist --method registry --payload {payload}",
                opsec_impact=3
            ),
            Technique(
                id="T1053.005",
                name="Scheduled Task/Job: Scheduled Task",
                tactic="Persistence",
                phase=KillChainPhase.INSTALLATION,
                command="persist --method schtask --payload {payload}",
                opsec_impact=3
            ),
            Technique(
                id="T1543.002",
                name="Create or Modify System Process: Systemd Service",
                tactic="Persistence",
                phase=KillChainPhase.INSTALLATION,
                command="persist --method systemd --payload {payload}",
                opsec_impact=3
            ),
            Technique(
                id="T1546.003",
                name="Event Triggered Execution: WMI Event Subscription",
                tactic="Persistence",
                phase=KillChainPhase.INSTALLATION,
                command="persist --method wmi --payload {payload}",
                opsec_impact=4
            ),
        ],
        KillChainPhase.COMMAND_CONTROL: [
            Technique(
                id="T1071.001",
                name="Application Layer Protocol: Web Protocols",
                tactic="Command and Control",
                phase=KillChainPhase.COMMAND_CONTROL,
                command="c2_connect --protocol https --server {c2_server}",
                opsec_impact=2
            ),
            Technique(
                id="T1071.004",
                name="Application Layer Protocol: DNS",
                tactic="Command and Control",
                phase=KillChainPhase.COMMAND_CONTROL,
                command="c2_connect --protocol dns --domain {c2_domain}",
                opsec_impact=2
            ),
            Technique(
                id="T1572",
                name="Protocol Tunneling",
                tactic="Command and Control",
                phase=KillChainPhase.COMMAND_CONTROL,
                command="tunnel --protocol {protocol} --server {server}",
                opsec_impact=3
            ),
            Technique(
                id="T1090.002",
                name="Proxy: External Proxy",
                tactic="Command and Control",
                phase=KillChainPhase.COMMAND_CONTROL,
                command="proxy --type socks5 --server {proxy_server}",
                opsec_impact=2
            ),
        ],
        KillChainPhase.ACTIONS_ON_OBJECTIVES: [
            Technique(
                id="T1005",
                name="Data from Local System",
                tactic="Collection",
                phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                command="collect --type files --patterns {patterns}",
                opsec_impact=2
            ),
            Technique(
                id="T1039",
                name="Data from Network Shared Drive",
                tactic="Collection",
                phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                command="collect --type shares --target {target}",
                opsec_impact=3
            ),
            Technique(
                id="T1041",
                name="Exfiltration Over C2 Channel",
                tactic="Exfiltration",
                phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                command="exfil --method c2 --data {staged_data}",
                opsec_impact=3
            ),
            Technique(
                id="T1567",
                name="Exfiltration Over Web Service",
                tactic="Exfiltration",
                phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                command="exfil --method cloud --service {service} --data {staged_data}",
                opsec_impact=2
            ),
            Technique(
                id="T1486",
                name="Data Encrypted for Impact",
                tactic="Impact",
                phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
                command="encrypt --target {target} --key {key}",
                opsec_impact=5
            ),
        ],
    }

    @classmethod
    def get_techniques(cls, phase: KillChainPhase,
                       max_opsec: int = 5) -> List[Technique]:
        """Get techniques for a phase, filtered by OPSEC level."""
        techniques = cls.TECHNIQUES.get(phase, [])
        return [t for t in techniques if t.opsec_impact <= max_opsec]

    @classmethod
    def get_by_id(cls, technique_id: str) -> Optional[Technique]:
        """Get technique by ATT&CK ID."""
        for techniques in cls.TECHNIQUES.values():
            for t in techniques:
                if t.id == technique_id:
                    return t
        return None


class CampaignState:
    """
    Campaign state management with persistence.
    """

    def __init__(self, campaign_id: str):
        self.campaign_id = campaign_id
        self.created_at = datetime.utcnow().isoformat()
        self.current_phase = KillChainPhase.RECONNAISSANCE
        self.phase_results: Dict[str, List[PhaseResult]] = {}
        self.targets: Dict[str, Target] = {}
        self.objectives: List[CampaignObjective] = []
        self.artifacts: List[Dict] = []
        self.iocs_generated: List[str] = []
        self.opsec_level = OPSECLevel.NORMAL
        self.notes: List[Dict] = []

    def add_target(self, target: Target):
        """Add a target to the campaign."""
        self.targets[target.id] = target

    def add_objective(self, objective: CampaignObjective):
        """Add an objective to the campaign."""
        self.objectives.append(objective)

    def record_phase_result(self, result: PhaseResult):
        """Record a phase execution result."""
        phase_key = result.phase.value
        if phase_key not in self.phase_results:
            self.phase_results[phase_key] = []
        self.phase_results[phase_key].append(result)

        # Track IOCs
        self.iocs_generated.extend(result.iocs)

    def advance_phase(self) -> Optional[KillChainPhase]:
        """Advance to the next kill chain phase."""
        phases = list(KillChainPhase)
        current_idx = phases.index(self.current_phase)

        if current_idx < len(phases) - 1:
            self.current_phase = phases[current_idx + 1]
            return self.current_phase
        return None

    def add_note(self, note: str, phase: KillChainPhase = None):
        """Add operational note."""
        self.notes.append({
            "timestamp": datetime.utcnow().isoformat(),
            "phase": phase.value if phase else self.current_phase.value,
            "note": note
        })

    def get_target_by_status(self, access_level: str) -> List[Target]:
        """Get targets by access level."""
        return [t for t in self.targets.values() if t.access_level == access_level]

    def export(self) -> Dict:
        """Export campaign state."""
        return {
            "campaign_id": self.campaign_id,
            "created_at": self.created_at,
            "current_phase": self.current_phase.value,
            "opsec_level": self.opsec_level.value,
            "targets": {k: vars(v) for k, v in self.targets.items()},
            "objectives": [vars(o) for o in self.objectives],
            "phase_results": {
                k: [
                    {
                        "phase": r.phase.value,
                        "status": r.status.value,
                        "technique": r.technique_used,
                        "target": r.target,
                        "duration": r.end_time - r.start_time,
                    }
                    for r in results
                ]
                for k, results in self.phase_results.items()
            },
            "iocs_generated": self.iocs_generated,
            "notes": self.notes,
        }

    def save(self, filepath: str):
        """Save campaign state to file."""
        with open(filepath, "w") as f:
            json.dump(self.export(), f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "CampaignState":
        """Load campaign state from file."""
        with open(filepath, "r") as f:
            data = json.load(f)

        state = cls(data["campaign_id"])
        state.created_at = data["created_at"]
        state.current_phase = KillChainPhase(data["current_phase"])
        state.opsec_level = OPSECLevel(data["opsec_level"])
        state.notes = data.get("notes", [])
        state.iocs_generated = data.get("iocs_generated", [])

        return state


class KillChainOrchestrator:
    """
    Main kill chain orchestration engine.

    Automates attack campaign execution with:
    - Phase-by-phase progression
    - Technique selection based on OPSEC
    - Fallback mechanisms
    - Multi-target coordination
    - Real-time decision making
    """

    def __init__(self, campaign_id: str = None,
                 opsec_level: OPSECLevel = OPSECLevel.NORMAL,
                 callback_host: str = None,
                 parallel_targets: int = 3):
        self.campaign_id = campaign_id or str(uuid.uuid4())[:8]
        self.state = CampaignState(self.campaign_id)
        self.state.opsec_level = opsec_level
        self.callback_host = callback_host
        self.parallel_targets = parallel_targets

        # Execution hooks
        self.pre_phase_hooks: Dict[KillChainPhase, List[Callable]] = {}
        self.post_phase_hooks: Dict[KillChainPhase, List[Callable]] = {}

        # Technique executor (would be implemented with actual tools)
        self.executor = None

        # Statistics
        self.stats = {
            "techniques_attempted": 0,
            "techniques_succeeded": 0,
            "techniques_failed": 0,
            "targets_compromised": 0,
            "data_exfiltrated": 0,
        }

    def add_target(self, hostname: str, ip: str, os: str = "",
                   domain: str = "") -> Target:
        """Add a target to the campaign."""
        target = Target(
            id=str(uuid.uuid4())[:8],
            hostname=hostname,
            ip=ip,
            os=os,
            domain=domain
        )
        self.state.add_target(target)
        return target

    def add_objective(self, name: str, description: str,
                      target_data: List[str], priority: int = 3) -> CampaignObjective:
        """Add a campaign objective."""
        objective = CampaignObjective(
            id=str(uuid.uuid4())[:8],
            name=name,
            description=description,
            target_data=target_data,
            priority=priority
        )
        self.state.add_objective(objective)
        return objective

    def register_hook(self, phase: KillChainPhase,
                      hook: Callable, pre: bool = True):
        """Register pre/post phase execution hook."""
        if pre:
            if phase not in self.pre_phase_hooks:
                self.pre_phase_hooks[phase] = []
            self.pre_phase_hooks[phase].append(hook)
        else:
            if phase not in self.post_phase_hooks:
                self.post_phase_hooks[phase] = []
            self.post_phase_hooks[phase].append(hook)

    def select_technique(self, phase: KillChainPhase,
                         target: Target = None) -> Optional[Technique]:
        """
        Intelligently select technique based on:
        - OPSEC level
        - Target characteristics
        - Previous success/failures
        - Available tools
        """
        max_opsec = {
            OPSECLevel.LOUD: 5,
            OPSECLevel.NORMAL: 4,
            OPSECLevel.CAREFUL: 3,
            OPSECLevel.STEALTHY: 2,
            OPSECLevel.APT: 1,
        }[self.state.opsec_level]

        techniques = TechniqueLibrary.get_techniques(phase, max_opsec)

        if not techniques:
            return None

        # Filter based on target OS if available
        if target and target.os:
            if "windows" in target.os.lower():
                techniques = [t for t in techniques
                             if "unix" not in t.name.lower() and "linux" not in t.name.lower()]
            elif "linux" in target.os.lower():
                techniques = [t for t in techniques
                             if "windows" not in t.name.lower() and "powershell" not in t.name.lower()]

        # Sort by success rate and OPSEC impact
        techniques.sort(key=lambda t: (t.success_rate, -t.opsec_impact), reverse=True)

        # Avoid recently failed techniques
        failed_techniques = set()
        for results in self.state.phase_results.get(phase.value, []):
            if results.status == AttackStatus.FAILED:
                failed_techniques.add(results.technique_used)

        for technique in techniques:
            if technique.id not in failed_techniques:
                return technique

        # If all failed, return highest success rate anyway
        return techniques[0] if techniques else None

    def execute_technique(self, technique: Technique,
                          target: Target,
                          params: Dict = None) -> PhaseResult:
        """Execute a technique against a target."""
        start_time = time.time()
        params = params or {}

        # Build command with parameters
        command = technique.command
        command = command.replace("{target}", target.hostname or target.ip)
        for key, value in params.items():
            command = command.replace("{" + key + "}", str(value))

        self.stats["techniques_attempted"] += 1

        # Simulate execution (would be actual tool invocation)
        # In real implementation, this would call actual exploitation tools
        result = PhaseResult(
            phase=technique.phase,
            status=AttackStatus.SUCCESS,  # Simulated
            technique_used=technique.id,
            start_time=start_time,
            end_time=time.time(),
            target=target.hostname or target.ip,
            output=f"Executed: {command}",
            artifacts=[],
            iocs=[]
        )

        if result.status == AttackStatus.SUCCESS:
            self.stats["techniques_succeeded"] += 1
        else:
            self.stats["techniques_failed"] += 1

        return result

    def execute_phase(self, phase: KillChainPhase,
                      targets: List[Target] = None) -> List[PhaseResult]:
        """Execute a kill chain phase against targets."""
        results = []
        targets = targets or list(self.state.targets.values())

        # Run pre-phase hooks
        for hook in self.pre_phase_hooks.get(phase, []):
            hook(phase, targets)

        # Execute against each target
        with ThreadPoolExecutor(max_workers=self.parallel_targets) as executor:
            futures = []

            for target in targets:
                technique = self.select_technique(phase, target)
                if technique:
                    future = executor.submit(
                        self.execute_technique, technique, target
                    )
                    futures.append((future, target, technique))

            for future, target, technique in futures:
                try:
                    result = future.result(timeout=300)
                    results.append(result)
                    self.state.record_phase_result(result)

                    # Update target status based on result
                    if result.status == AttackStatus.SUCCESS:
                        if phase == KillChainPhase.EXPLOITATION:
                            target.access_level = "user"
                        elif phase == KillChainPhase.INSTALLATION:
                            target.implants.append(technique.id)

                except Exception as e:
                    # Record failure
                    result = PhaseResult(
                        phase=phase,
                        status=AttackStatus.FAILED,
                        technique_used=technique.id,
                        start_time=time.time(),
                        end_time=time.time(),
                        target=target.hostname or target.ip,
                        output=str(e)
                    )
                    results.append(result)
                    self.state.record_phase_result(result)

        # Run post-phase hooks
        for hook in self.post_phase_hooks.get(phase, []):
            hook(phase, results)

        return results

    def run_campaign(self, auto_advance: bool = True) -> Dict:
        """
        Run the full kill chain campaign.

        Args:
            auto_advance: Automatically advance through phases

        Returns:
            Campaign execution summary
        """
        campaign_start = time.time()

        phases_order = [
            KillChainPhase.RECONNAISSANCE,
            KillChainPhase.WEAPONIZATION,
            KillChainPhase.DELIVERY,
            KillChainPhase.EXPLOITATION,
            KillChainPhase.INSTALLATION,
            KillChainPhase.COMMAND_CONTROL,
            KillChainPhase.ACTIONS_ON_OBJECTIVES,
        ]

        for phase in phases_order:
            self.state.current_phase = phase
            self.state.add_note(f"Starting phase: {phase.value}")

            # Get appropriate targets for this phase
            if phase == KillChainPhase.RECONNAISSANCE:
                targets = list(self.state.targets.values())
            elif phase in [KillChainPhase.WEAPONIZATION]:
                targets = []  # No specific target for weaponization
            elif phase == KillChainPhase.DELIVERY:
                targets = list(self.state.targets.values())
            elif phase in [KillChainPhase.EXPLOITATION, KillChainPhase.INSTALLATION]:
                # Only target systems we've delivered to
                targets = list(self.state.targets.values())
            elif phase == KillChainPhase.COMMAND_CONTROL:
                # Only systems with implants
                targets = [t for t in self.state.targets.values() if t.implants]
            else:
                # Actions on objectives - compromised systems
                targets = [t for t in self.state.targets.values()
                          if t.access_level in ["user", "admin", "system"]]

            if not targets and phase not in [KillChainPhase.WEAPONIZATION]:
                self.state.add_note(f"No suitable targets for phase: {phase.value}")
                if not auto_advance:
                    break
                continue

            results = self.execute_phase(phase, targets)

            # Check if we should continue
            successful = [r for r in results if r.status == AttackStatus.SUCCESS]
            if not successful and phase != KillChainPhase.WEAPONIZATION:
                self.state.add_note(f"Phase {phase.value} failed, considering fallbacks")

                if not auto_advance:
                    break

        campaign_end = time.time()

        # Count compromised targets
        compromised = [t for t in self.state.targets.values()
                      if t.access_level != "none"]
        self.stats["targets_compromised"] = len(compromised)

        return {
            "campaign_id": self.campaign_id,
            "duration_seconds": campaign_end - campaign_start,
            "final_phase": self.state.current_phase.value,
            "targets_total": len(self.state.targets),
            "targets_compromised": self.stats["targets_compromised"],
            "techniques_attempted": self.stats["techniques_attempted"],
            "techniques_succeeded": self.stats["techniques_succeeded"],
            "objectives_completed": len([o for o in self.state.objectives if o.completed]),
            "iocs_generated": len(self.state.iocs_generated),
        }

    def generate_report(self) -> Dict:
        """Generate comprehensive campaign report."""
        return {
            "executive_summary": {
                "campaign_id": self.campaign_id,
                "opsec_level": self.state.opsec_level.value,
                "duration": "N/A",  # Would calculate from first/last phase
                "success_rate": (
                    self.stats["techniques_succeeded"] /
                    max(self.stats["techniques_attempted"], 1) * 100
                ),
            },
            "targets": {
                "total": len(self.state.targets),
                "compromised": len([t for t in self.state.targets.values()
                                   if t.access_level != "none"]),
                "with_persistence": len([t for t in self.state.targets.values()
                                        if t.implants]),
            },
            "techniques_used": [
                {
                    "phase": phase,
                    "techniques": [r.technique_used for r in results],
                    "success_count": len([r for r in results
                                         if r.status == AttackStatus.SUCCESS]),
                }
                for phase, results in self.state.phase_results.items()
            ],
            "objectives": [
                {
                    "name": o.name,
                    "priority": o.priority,
                    "completed": o.completed,
                }
                for o in self.state.objectives
            ],
            "indicators_of_compromise": self.state.iocs_generated,
            "operational_notes": self.state.notes,
            "recommendations": self._generate_recommendations(),
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on campaign results."""
        recommendations = []

        # Based on failed techniques
        failed_count = self.stats["techniques_failed"]
        if failed_count > self.stats["techniques_succeeded"]:
            recommendations.append(
                "Consider adjusting OPSEC level to allow more aggressive techniques"
            )

        # Based on compromised targets
        total = len(self.state.targets)
        compromised = self.stats["targets_compromised"]
        if compromised < total * 0.5:
            recommendations.append(
                "Low compromise rate - consider additional reconnaissance or alternative delivery methods"
            )

        # Based on persistence
        with_persistence = len([t for t in self.state.targets.values() if t.implants])
        if compromised > 0 and with_persistence < compromised:
            recommendations.append(
                "Not all compromised hosts have persistence - prioritize installation phase"
            )

        return recommendations


class CampaignTemplates:
    """
    Pre-built campaign templates for common scenarios.
    """

    @staticmethod
    def ransomware_simulation(targets: List[Dict],
                              callback_host: str) -> KillChainOrchestrator:
        """
        Ransomware attack simulation campaign.
        """
        orchestrator = KillChainOrchestrator(
            opsec_level=OPSECLevel.LOUD,
            callback_host=callback_host
        )

        for t in targets:
            orchestrator.add_target(
                hostname=t.get("hostname", ""),
                ip=t.get("ip", ""),
                os=t.get("os", "windows")
            )

        orchestrator.add_objective(
            name="Deploy ransomware",
            description="Encrypt files on target systems",
            target_data=["documents", "databases"],
            priority=1
        )

        return orchestrator

    @staticmethod
    def data_exfiltration(targets: List[Dict],
                          callback_host: str,
                          target_data: List[str]) -> KillChainOrchestrator:
        """
        Data exfiltration campaign.
        """
        orchestrator = KillChainOrchestrator(
            opsec_level=OPSECLevel.STEALTHY,
            callback_host=callback_host
        )

        for t in targets:
            orchestrator.add_target(
                hostname=t.get("hostname", ""),
                ip=t.get("ip", ""),
                os=t.get("os", "")
            )

        orchestrator.add_objective(
            name="Exfiltrate sensitive data",
            description="Locate and exfiltrate target data",
            target_data=target_data,
            priority=1
        )

        return orchestrator

    @staticmethod
    def red_team_assessment(domain: str,
                            targets: List[Dict],
                            callback_host: str) -> KillChainOrchestrator:
        """
        Full red team assessment campaign.
        """
        orchestrator = KillChainOrchestrator(
            opsec_level=OPSECLevel.CAREFUL,
            callback_host=callback_host
        )

        for t in targets:
            target = orchestrator.add_target(
                hostname=t.get("hostname", ""),
                ip=t.get("ip", ""),
                os=t.get("os", ""),
                domain=domain
            )

        # Multiple objectives
        orchestrator.add_objective(
            name="Domain Admin Access",
            description="Obtain domain administrator privileges",
            target_data=["credentials"],
            priority=1
        )

        orchestrator.add_objective(
            name="Persistence",
            description="Establish persistent access to network",
            target_data=[],
            priority=2
        )

        orchestrator.add_objective(
            name="Data Access",
            description="Access sensitive business data",
            target_data=["documents", "emails", "databases"],
            priority=3
        )

        return orchestrator


# Convenience functions
def create_campaign(targets: List[Dict],
                    callback_host: str,
                    opsec_level: str = "normal") -> KillChainOrchestrator:
    """Create a new campaign with default settings."""
    level = OPSECLevel(opsec_level)
    orchestrator = KillChainOrchestrator(
        opsec_level=level,
        callback_host=callback_host
    )

    for t in targets:
        orchestrator.add_target(
            hostname=t.get("hostname", ""),
            ip=t.get("ip", ""),
            os=t.get("os", ""),
            domain=t.get("domain", "")
        )

    return orchestrator


def run_quick_campaign(targets: List[Dict],
                       callback_host: str) -> Dict:
    """Run a quick campaign and return results."""
    orchestrator = create_campaign(targets, callback_host)
    return orchestrator.run_campaign(auto_advance=True)
