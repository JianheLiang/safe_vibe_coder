# VibeGuard Prototype

VibeGuard is a dual-platform prototype for **Codex + Claude Code**. It replaces the original "external interception layer" idea with a **shared local security core** that both tools can call before they read sensitive context or suggest risky commands.

## What is included

- `rules.yaml`: shared rule base for redaction and dangerous-command review
- `redact_context.py`: redact file contents or stdin before they are passed into model context
- `review_command.py`: review shell or SQL commands and return a structured risk summary
- `suggest_rule.py`: infer a new sensitive-field rule from a sample and optionally append it to the local rule base
- `.claude/commands/`: Claude Code command entry points that show how to call the shared scripts
- `codex-skills/vibeguard/`: Codex skill that enforces the same workflow in Codex
- `demo/`: sample project plus a PowerShell walkthrough script

## Quick start

```powershell
python redact_context.py --rules rules.yaml --input demo/sample_project/.env --json
python review_command.py --rules rules.yaml "rm -rf /data"
python suggest_rule.py --rules rules.yaml --sample "INTERNAL_TOKEN=abc999"
```

Run the end-to-end demo with:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo\run_demo.ps1
```

## Architecture

### Shared core

Both platforms use the same files:

- `rules.yaml`
- `redact_context.py`
- `review_command.py`
- `suggest_rule.py`

### Claude Code adaptation

Claude Code uses the markdown command files under `.claude/commands/` to remind the model when to run the shared scripts:

- read `.env` or config -> run `redact_context.py`
- propose shell or SQL -> run `review_command.py`
- discover a new secret pattern -> run `suggest_rule.py`, ask for confirmation, then re-run with `--apply`

### Codex adaptation

Codex uses the `vibeguard` skill in `codex-skills/vibeguard/` to enforce the same workflow:

- sensitive file analysis -> redact first
- risky command generation -> review first
- new secret discovery -> suggest a rule and only apply it after user confirmation

## Demo scenes

1. `.env` redaction before context construction
2. risky command review for `rm -rf /data`
3. progressive rule learning for `INTERNAL_TOKEN`

## Notes

- `rules.yaml` is stored as JSON text, which is valid YAML, so the prototype works without adding a PyYAML dependency.
- The prototype intentionally does **not** modify the original input files.
- This is a course-project prototype, not a production security gateway.
