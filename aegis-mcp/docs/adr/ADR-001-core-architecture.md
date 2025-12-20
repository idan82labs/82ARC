# ADR-001: Core Architecture

**Status:** Accepted
**Date:** 2024-12-20
**Author:** Aegis Team

## Context

Aegis is being redesigned as an AI Security Testing Platform for authorized red/purple teams. The existing codebase has offensive security modules but lacks:
- Authorization/scope enforcement
- Run primitives and audit trails
- Safety guardrails
- Structured test packs
- CLI/REST/MCP interfaces over a unified core

## Decision

### Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      INTERFACES                              │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐                │
│   │   CLI   │    │   REST  │    │   MCP   │                │
│   │ (Typer) │    │(FastAPI)│    │(FastMCP)│                │
│   └────┬────┘    └────┬────┘    └────┬────┘                │
│        └──────────────┼──────────────┘                      │
│                       ▼                                      │
├─────────────────────────────────────────────────────────────┤
│                    CORE ENGINE                               │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                    Engine                            │   │
│   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐ │   │
│   │  │  Scope  │ │   Run   │ │  Pack   │ │ Reporting │ │   │
│   │  │ Enforcer│ │Orchestr.│ │ Executor│ │  Engine   │ │   │
│   │  └─────────┘ └─────────┘ └─────────┘ └───────────┘ │   │
│   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐ │   │
│   │  │ Evidence│ │ Scoring │ │Redaction│ │   Audit   │ │   │
│   │  │Collector│ │ Engine  │ │ Service │ │  Logger   │ │   │
│   │  └─────────┘ └─────────┘ └─────────┘ └───────────┘ │   │
│   └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    PACKS (Test Suites)                       │
│   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│   │   Prompt     │ │  Guardrail   │ │    Agent     │        │
│   │  Injection   │ │  Evaluation  │ │ Tool-Boundary│        │
│   └──────────────┘ └──────────────┘ └──────────────┘        │
├─────────────────────────────────────────────────────────────┤
│                    TARGET ADAPTERS                           │
│   ┌────────┐ ┌────────┐ ┌──────────┐ ┌────────┐            │
│   │  HTTP  │ │ OpenAI │ │Anthropic │ │ Local  │            │
│   │Generic │ │  API   │ │   API    │ │(Ollama)│            │
│   └────────┘ └────────┘ └──────────┘ └────────┘            │
├─────────────────────────────────────────────────────────────┤
│                    PERSISTENCE                               │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  SQLite Store  │  Artifact Store  │  Audit Log      │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Core Primitives

1. **Scope** - Defines authorized testing boundaries
2. **Target** - The AI system under test
3. **Pack** - Versioned test suite with deterministic cases
4. **Run** - Single execution of a pack against a target
5. **Evidence** - Captured request/response transcripts
6. **Score** - Severity assessment with remediation

### Interface Parity

All three interfaces (CLI, REST, MCP) call the same core engine. No divergent logic.

```python
# All interfaces use:
from aegis.core.engine import AegisEngine

engine = AegisEngine()
run = engine.create_run(scope_id, target_id, pack_id, seed)
engine.execute_run(run.id)
report = engine.generate_report(run.id, format="markdown")
```

## Consequences

**Positive:**
- Single source of truth for all business logic
- Consistent behavior across interfaces
- Easier testing and maintenance
- Clear separation of concerns

**Negative:**
- More initial setup work
- All changes must consider all interfaces

## Alternatives Considered

1. **Separate implementations per interface** - Rejected due to divergence risk
2. **MCP-only interface** - Rejected due to limited adoption
3. **REST-only interface** - Rejected due to CLI workflow importance
