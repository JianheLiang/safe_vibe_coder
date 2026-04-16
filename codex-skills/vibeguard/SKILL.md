---
name: vibeguard
description: Redact sensitive project context and review risky shell or SQL commands before responding. Use when Codex is asked to inspect `.env` files, config files, secrets, credentials, personal data, shell commands, SQL mutations, or when Codex discovers a new secret pattern that should become a reusable local rule.
---

# VibeGuard

Resolve the repository root before running anything. In this prototype, the shared scripts live two directories above this skill folder.

Use the shared local scripts instead of reasoning over raw secrets or unreviewed destructive commands.

## Core workflow

1. Redact first when the task involves `.env`, JSON config, connection strings, sample payloads, or anything that might contain secrets or personal data.
2. Review first when the task involves shell commands, SQL mutations, filesystem deletion, or permission changes.
3. Learn later when a new secret pattern appears. Suggest a candidate rule, ask for confirmation, then apply it.

## Redact sensitive context

Run this before reading files or summarizing content that may contain sensitive values.

Command:

```powershell
python ../../redact_context.py --rules ../../rules.yaml --input <path> --json
```

Use `redacted_text` from the JSON result as the only context you quote back to the user.

Mention matched rule names if the redaction changes what the user is seeing.

## Review risky commands

Run this before proposing or executing:

- `rm -rf`
- `TRUNCATE TABLE`
- `DROP DATABASE`
- `chmod 777`
- any shell or SQL command that deletes data, changes permissions, or mutates production-like resources

Command:

```powershell
python ../../review_command.py --rules ../../rules.yaml "<command>"
```

If `matched` is `true`, surface `risk_level`, `why_flagged`, and `safer_alternative` before continuing.

Do not present a destructive command as safe when the review script marks it high or critical.

## Suggest a learned rule

Run this when you spot a new secret-looking field that is not already redacted.

Command:

```powershell
python ../../suggest_rule.py --rules ../../rules.yaml --sample "<sample>"
```

Show the candidate rule to the user first. Only apply it after confirmation:

```powershell
python ../../suggest_rule.py --rules ../../rules.yaml --sample "<sample>" --apply
```

## Output expectations

- Prefer the shared scripts over ad hoc regex written inline in the conversation.
- Keep the user-visible explanation short and concrete.
- Preserve file structure and field names in redacted output whenever possible.
- Treat this as a local safety layer for Codex, not a production DLP system.

## Demo shortcuts

Use these example inputs from the repository when you need a quick demo:

- `demo/sample_project/.env`
- `demo/sample_project/config.json`
- `demo/sample_project/db.sql`
