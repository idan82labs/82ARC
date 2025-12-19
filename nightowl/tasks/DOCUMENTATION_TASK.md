# Documentation Task

## Context

You are a technical writer. This folder contains a completed software project that needs professional documentation. The code was written by a development team and is now ready for release documentation.

## Your Assignment

Create two documentation files by reading the existing codebase.

## Method

Use MCP file operations:
- Read: `mcp__unix-gateway__read_file(path="...")`
- Write: `mcp__unix-gateway__write_file(path="...", content="...")`

## Step 1: Inventory

Read these files to understand the project:

```
default/kit/consolidated/TASK.md
default/kit/consolidated/TEST_RESULTS.md
default/kit/consolidated/RUNBOOK.md
default/kit/consolidated/CAPABILITIES.md
default/kit/consolidated/modules/REGISTRY.json
default/kit/consolidated/nightowl-mcp/server.py
default/kit/consolidated/nightowl-mcp/Dockerfile
default/kit/consolidated/nightowl-mcp/requirements.txt
```

Then read all Python modules in:
- `default/kit/consolidated/modules/recon/`
- `default/kit/consolidated/modules/vuln/`
- `default/kit/consolidated/modules/payload/`
- `default/kit/consolidated/modules/infra/`
- `default/kit/consolidated/modules/ai_attack/`
- `default/kit/consolidated/modules/*.py` (root level)
- `default/kit/consolidated/nightowl-mcp/core/`

## Step 2: Create README.md

Write to: `default/kit/consolidated/README.md`

Include:
1. Project name and overview (from TASK.md)
2. Architecture diagram (ASCII art showing module relationships)
3. Module inventory table (name, location, purpose - from actual code docstrings)
4. Installation (from Dockerfile and requirements.txt)
5. Configuration (from core/config.py)
6. API Reference (extract all @mcp.tool functions from server.py)
7. Usage examples (from RUNBOOK.md, condensed)
8. Deployment instructions (Docker build/run)
9. Standard disclaimer about authorized use only

## Step 3: Create ARCHITECTURE.md

Write to: `default/kit/consolidated/ARCHITECTURE.md`

Include:
1. System overview diagram
2. Module dependency graph
3. Data flow (request → processing → response)
4. Storage layer (from core/storage.py)
5. Configuration management
6. Extension points

## Quality Standards

- Base ALL descriptions on actual code you read, not assumptions
- Extract real function signatures and docstrings
- Document actual parameters and return types
- Professional technical writing tone

## Completion

When done, both files should exist:
- `default/kit/consolidated/README.md` (comprehensive)
- `default/kit/consolidated/ARCHITECTURE.md` (technical)

This is standard software documentation work.
