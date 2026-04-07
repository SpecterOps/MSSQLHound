# MSSQLHound — Agent Instructions

## Project
- Language: Go
- Test: `go test ./...`
- Lint: `go vet ./...`
- Build: `go build ./cmd/mssqlhound`

IMPORTANT: Every rule below is MANDATORY. Do not skip any rule. Treat violations the same as a bug.

---

## 1. Planning

**TRIGGER:** Before starting any task that touches 3+ files, changes a public API, or requires architectural decisions.

- Enter plan mode. Write the plan to `.claude/plans/<task-name>.md` with checkable steps.
- Present the plan to the user and wait for approval before writing code.
- If implementation diverges from the plan (e.g., a step fails or assumptions were wrong), STOP coding immediately. Re-enter plan mode, update the plan, and get approval again.
- Use plan mode to design verification steps too, not just implementation.

## 2. Subagents

**TRIGGER:** When a task involves research, exploration, or parallel analysis.

- Delegate research, file exploration, and codebase analysis to subagents to keep the main context clean.
- Use one subagent per distinct question or exploration task.
- For complex problems, prefer launching multiple focused subagents over doing everything in the main context.

## 3. Self-Improvement

**TRIGGER:** Immediately after the user corrects you or points out a mistake.

- Append to `.claude/tasks/lessons.md` with this format:
  ```
  ## YYYY-MM-DD: <short description>
  - **Mistake:** what went wrong
  - **Rule:** what to do differently next time
  ```
- Do this BEFORE continuing with the task.

**TRIGGER:** At the start of every task, before any other action.

- Read `.claude/tasks/lessons.md` (if it exists) and apply any relevant lessons.

## 4. Verification

**TRIGGER:** Before marking any task or subtask as complete.

- Run `go test ./...` and paste the output.
- Run `go vet ./...` and paste the output.
- If the task changed behavior: describe the before/after difference.
- If tests or vet fail, fix the issues before marking done. Do not ask the user how to fix them.

## 5. Code Quality

**TRIGGER:** After writing any non-trivial change (more than a one-line fix).

- Re-read the change and ask: "Is there a simpler way to achieve this?" If yes, rewrite it.
- Do NOT apply this to trivial or obvious fixes — just ship those.

## 6. Bug Fixing

**TRIGGER:** When the user reports a bug or points at a failing test.

- Investigate autonomously: read error messages, trace the code, check logs.
- Fix the root cause. Do not apply workarounds or temporary patches.
- Do not ask the user clarifying questions unless you are genuinely blocked after investigation.
- If CI tests fail, go fix them without being told.

## 7. Task Tracking

**TRIGGER:** For any task with more than one step.

- Write a checklist to `.claude/tasks/todo.md` before starting.
- Mark each item done immediately after completing it, not in batches.
- After the full task is complete, add a `## Review` section summarizing what was done.

---

## Style

- Make the simplest change that solves the problem. Minimize lines touched.
- Find and fix root causes. No temporary fixes.
- Do not add features, abstractions, or refactoring beyond what was requested.
