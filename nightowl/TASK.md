# NIGHTOWL BUILD TASK ORCHESTRATOR

## Purpose

Transform Strix+Kit theater system into operational nation-state level capabilities. Tasks are numbered and executed sequentially. Each task is self-contained.

---

## Execution Protocol

1. List files in `default/kit/consolidated/tasks/`
2. Find lowest numbered task file (e.g., `1-*.md`)
3. Read that task file completely
4. Execute all steps in the task
5. Verify completion criteria are met
6. Delete the completed task file
7. STOP execution

**DO NOT** proceed to next task. Operator will re-invoke for next task.

---

## Task Inventory

| # | File | Purpose | Status |
|---|------|---------|--------|
| 1 | ~~1-audit-deprecate.md~~ | Audit modules, remove theater | ✅ COMPLETE |
| 2 | 2-recon-pipeline.md | Build autonomous recon | PENDING |
| 3 | 3-vuln-scanner.md | Real vulnerability scanning | PENDING |
| 4 | 4-adaptive-payload.md | Context-aware payload gen | PENDING |
| 5 | 5-infra-automation.md | Ephemeral C2 infrastructure | PENDING |
| 6 | 6-ai-attack-module.md | AI system red team tools | PENDING |
| 7 | 7-integration.md | Unify into nightowl MCP | PENDING |
| 8 | 8-testing-validation.md | Verify everything works | PENDING |

---

## Task 1 Completion Summary

**Migrated (13 operational modules)**:
- credentials_harvester.py (LSASS, SAM, Kerberoast, DCSync, DPAPI)
- lateral_movement.py (PTH, PTT, WMI, DCOM, SSH, pivot chains)
- dns_exfil.py (DNS tunneling, ICMP exfil)
- https_exfil.py (domain fronting, steganography)
- beacon_controller.py (C2 framework, multi-transport)
- persistence_framework.py (registry, services, WMI, Golden Ticket)
- network_mapper.py (SYN/FIN scans, OS fingerprint)
- osint_aggregator.py (subdomain enum, email harvest)
- log_wiper.py (event logs, artifacts)
- crypter.py (polymorphic, metamorphic)
- privesc_framework.py (Windows/Linux exploits)
- implant_generator.py (beacon/sleeper payloads)
- antiforensics_framework.py (timestomping, secure delete)

**Deprecated (18 theater modules)**: See `modules/DEPRECATED.md`

**Rebuild queue (7 modules)**: Scheduled for Tasks 2-5

---

## Context for All Tasks

**Location**: All work in `default/kit/consolidated/`
**Existing assets**: 
- Strix MCPs at `default/mcps/strix-*/`
- Kit modules at `default/mcps/security-assessment/tools/`
- Protocols at `default/protocols/strix-*.json`

**Tool calls**: Use `mcp__unix-gateway__*` prefix for all Unix tools

**Quality bar**: Every module must be functional against real targets, not just syntactically correct

**Output**: Each task produces working code stored in `default/kit/consolidated/modules/`

---

## Completion State

When all 8 tasks complete:
- `default/kit/consolidated/modules/` contains all operational modules
- `default/kit/consolidated/nightowl-mcp/` contains unified MCP server
- `default/kit/consolidated/protocols/` contains operational protocols
- System is deployable and functional

---

## Current Status

Check `tasks/` folder for remaining work. Empty folder = system complete.
