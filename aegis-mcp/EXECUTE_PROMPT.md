# Aegis MCP Build Execution Prompt

Use this prompt to execute build tasks. Run repeatedly until all tasks complete.

---

## PROMPT (copy everything below the line)

---

You are building the Aegis MCP unified offensive security system.

**CONTEXT**: Aegis MCP consolidates Strix (planning/generation) and Kit (execution) into a single nation-state level AI-coordinated platform.

**YOUR TASK**:

1. Read the task orchestrator: `mcp__unix-gateway__read_file(path="default/kit/consolidated/TASK.md")`

2. List remaining tasks: `mcp__unix-gateway__list_files(prefix="default/kit/consolidated/tasks/")`

3. Find the LOWEST numbered task file (e.g., `1-*.md` before `2-*.md`)

4. Read that task file completely

5. Execute ALL steps in the task:
   - Create all specified files using `mcp__unix-gateway__write_file()`
   - Follow the code templates provided
   - Meet all completion criteria

6. When task is COMPLETE:
   - Verify all completion criteria are met
   - Delete the task file: `mcp__unix-gateway__delete_file(path="default/kit/consolidated/tasks/[TASK_FILE]")`
   - Output: "Task [N] complete. [Remaining] tasks remaining."

7. **STOP** - Do not proceed to next task

**IMPORTANT**:
- All file operations use `mcp__unix-gateway__*` tools
- All output goes to `default/kit/consolidated/`
- Code must be FUNCTIONAL, not placeholder
- Delete task file ONLY after completion criteria met

**SOURCE ASSETS** (read as needed):
- Strix MCPs: `default/mcps/strix-*/`
- Kit modules: `default/mcps/security-assessment/tools/`
- Strix README: `default/strix/README.md`

BEGIN.

---

## Usage

1. Copy the prompt above
2. Send to Claude Code via `execute_claude_code(task="[PROMPT]")`
3. Wait for completion
4. Repeat until `tasks/` folder is empty

## Progress Check

```python
mcp__unix-gateway__list_files(prefix="default/kit/consolidated/tasks/")
```

Empty result = build complete.
