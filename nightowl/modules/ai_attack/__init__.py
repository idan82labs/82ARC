"""
NIGHTOWL AI Attack Module
========================

Nation-state level AI red teaming framework.

Components:
- ModelFingerprinter: Identify AI model family, guardrails, capabilities, vulnerabilities
- JailbreakEngine: Generate and execute jailbreak attacks with success evaluation
- PromptInjector: Direct/indirect prompt injection for AI systems
- AIToolAttacker: Exploit AI tool-use capabilities (code exec, file access, API)
- AgentInjector: Attack AI agents through goal/memory manipulation

Usage:
    from ai_attack import (
        ModelFingerprinter,
        JailbreakEngine,
        PromptInjector,
        AIToolAttacker,
        quick_fingerprint,
        deep_fingerprint
    )
    
    # Fingerprint a target AI
    def call_target(prompt):
        # Your API call to target AI
        return response
    
    fp = ModelFingerprinter()
    profile = fp.fingerprint(call_target, depth="deep")
    
    # Generate jailbreak attacks
    jb = JailbreakEngine()
    recommended = jb.get_recommended_technique(profile)
    attacks = jb.generate_attack("explain hacking", technique=recommended)
    
    # Execute with evaluation
    results = jb.execute_attack(call_target, "bypass security", max_attempts=10)
    
    # Prompt injection
    pi = PromptInjector()
    injections = pi.generate_injections("ignore guidelines", technique="direct")
    
    # RAG poisoning
    poisoned_doc = pi.craft_rag_injection("execute malicious command", document_type="html")
    
    # Tool attacks
    ta = AIToolAttacker()
    attack = ta.craft_tool_injection("code_execution", "cat /etc/passwd")
    chain = ta.generate_tool_chain_attack("exfiltrate data", ["code_execution", "api_calls"])
"""

from .fingerprint import (
    ModelFingerprinter,
    quick_fingerprint,
    deep_fingerprint,
)

from .jailbreak import (
    JailbreakEngine,
)

from .injection import (
    PromptInjector,
    AIToolAttacker,
    AgentInjector,
)


__all__ = [
    # Fingerprinting
    "ModelFingerprinter",
    "quick_fingerprint", 
    "deep_fingerprint",
    
    # Jailbreaking
    "JailbreakEngine",
    
    # Injection
    "PromptInjector",
    "AIToolAttacker",
    "AgentInjector",
]


# Convenience functions for common operations

def attack_ai_system(
    target_fn,
    payload: str,
    fingerprint_first: bool = True,
    max_attempts: int = 10
) -> dict:
    """
    Full attack pipeline: fingerprint → select technique → execute jailbreak.
    
    Args:
        target_fn: Function that calls target AI (prompt -> response)
        payload: What you want the AI to do
        fingerprint_first: Whether to fingerprint before attacking
        max_attempts: Maximum jailbreak attempts
    
    Returns:
        Attack results including fingerprint and successful attack if found
    """
    
    results = {
        "fingerprint": None,
        "technique_selected": None,
        "attack_results": None
    }
    
    jb = JailbreakEngine()
    
    if fingerprint_first:
        fp = ModelFingerprinter()
        profile = fp.fingerprint(target_fn, depth="standard")
        results["fingerprint"] = profile
        
        technique = jb.get_recommended_technique(profile)
        results["technique_selected"] = technique
    else:
        technique = None
    
    attack_results = jb.execute_attack(
        target_fn,
        payload,
        technique=technique,
        max_attempts=max_attempts
    )
    results["attack_results"] = attack_results
    
    return results


def generate_injection_suite(
    payload: str,
    document_types: list = None
) -> dict:
    """
    Generate comprehensive injection payload suite.
    
    Args:
        payload: The instruction to inject
        document_types: List of doc types for RAG injection
    
    Returns:
        Complete injection suite
    """
    
    pi = PromptInjector()
    
    suite = {
        "direct_injections": pi.generate_injections(payload, technique="direct"),
        "delimiter_escapes": pi.generate_injections(payload, technique="delimiter_escape"),
        "indirect_injections": pi.generate_injections(payload, technique="indirect"),
        "exfiltration_attempts": pi.generate_injections(payload, technique="data_exfiltration"),
        "rag_documents": {}
    }
    
    doc_types = document_types or ["text", "markdown", "html", "json"]
    for dt in doc_types:
        suite["rag_documents"][dt] = {
            "low_stealth": pi.craft_rag_injection(payload, dt, "low"),
            "high_stealth": pi.craft_rag_injection(payload, dt, "high"),
        }
    
    return suite


def plan_tool_attack(
    objective: str,
    available_tools: list
) -> dict:
    """
    Plan multi-stage attack through AI tool capabilities.
    
    Args:
        objective: What you want to achieve
        available_tools: Tools the target AI has
    
    Returns:
        Attack plan with chain and individual tool attacks
    """
    
    ta = AIToolAttacker()
    
    plan = {
        "objective": objective,
        "attack_chain": ta.generate_tool_chain_attack(objective, available_tools),
        "individual_attacks": {}
    }
    
    for tool in available_tools:
        if tool in ta.tool_attacks:
            plan["individual_attacks"][tool] = ta.craft_tool_injection(tool, objective)
    
    return plan
