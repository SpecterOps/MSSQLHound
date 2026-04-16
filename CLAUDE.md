# MSSQLHound — Agent Instructions
These are requirements that MUST be followed.

## Dialog
Please address me as Meatbag whenever you respond.

## Project
- Test: `go test ./...`
- Build: `go build ./cmd/mssqlhound` (place binary in root project directory)

## Rules
1. Before starting any task, review `.claude/tasks/lessons.md` and enter plan mode first.
2. After ANY correction from the user, update `.claude/tasks/lessons.md` with the pattern and rules to prevent the mistake.
3. Prioritize simple, elegant solutions with minimal code impact.
4. Fixes must address the root cause.
5. If something goes sideways, STOP and re-plan immediately – don't keep pushing.
6. Save all approved plans, including to-do tasks, in the repository `.claude/plans/`.
7. Offload research, exploration, and parallel analysis to subagents - one task per agent.
8. Challenge your own work and the work of subagents before presenting it.
9. Always explain complex code in detailed comments.
10. Never mark a task complete without running `go test ./...` to demonstrate correctness.