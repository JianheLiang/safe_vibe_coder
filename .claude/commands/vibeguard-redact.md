# `/vibeguard-redact`

Use this command before reading `.env`, `config.json`, connection strings, or any snippet that might contain credentials or personal data.

## Workflow

1. Run `python redact_context.py --rules rules.yaml --input <path> --json`.
2. Read and reason over `redacted_text`, not the raw file contents.
3. Tell the user which rules matched if the redaction changes the context in a meaningful way.

## Example

```powershell
python redact_context.py --rules rules.yaml --input demo/sample_project/.env --json
```
