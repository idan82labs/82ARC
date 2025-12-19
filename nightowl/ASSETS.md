# NIGHTOWL Consolidated Assets

## Current State

This directory contains the consolidated NIGHTOWL offensive security system, merging Strix (planning/generation) and Kit (execution) into a unified nation-state level platform.

## Structure

```
default/kit/consolidated/
├── README.md                    # System overview
├── TASK.md                      # Task orchestrator instructions
├── tasks/                       # Sequential build tasks
│   ├── 1-audit-deprecate.md     # Audit modules, remove theater
│   ├── 2-recon-pipeline.md      # Build autonomous recon
│   ├── 3-vuln-scanner.md        # Real vulnerability scanning
│   ├── 4-adaptive-payload.md    # Context-aware payload gen
│   ├── 5-infra-automation.md    # Ephemeral C2 infrastructure
│   ├── 6-ai-attack-module.md    # AI system red teaming
│   ├── 7-integration.md         # Unified MCP server
│   └── 8-testing-validation.md  # Verify and document
├── modules/                     # [TO BE CREATED] Operational modules
├── nightowl-mcp/               # [TO BE CREATED] Unified MCP server
└── protocols/                  # [TO BE CREATED] Operational protocols
```

## Execution

Tasks are executed sequentially. Each task is self-contained with:
- Clear objective
- Step-by-step instructions
- Code to implement
- Completion criteria
- Deletion instruction

## Source Assets

| Asset | Location | Purpose |
|-------|----------|---------|
| Strix MCPs | default/mcps/strix-*/ | Planning, generation, validation |
| Strix Protocols | default/protocols/strix-*.json | Workflow orchestration |
| Kit Modules | default/mcps/security-assessment/tools/ | Execution modules |
| Strix README | default/strix/README.md | Strix documentation |

## Target State

After all 8 tasks complete:
- Unified `nightowl` MCP with 25+ tools
- Real operational capability (not theater)
- AI attack module for red teaming
- Ephemeral infrastructure automation
- Complete documentation

## Quick Reference

**Start build**: Use execution prompt to begin Task 1
**Check progress**: List `tasks/` folder
**Complete**: Empty `tasks/` folder = system built
