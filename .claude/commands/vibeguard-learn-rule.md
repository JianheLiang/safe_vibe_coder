# `/vibeguard-learn-rule`

Use this command when you spot a previously unseen secret or sensitive identifier in project context.

## Workflow

1. Run `python suggest_rule.py --rules rules.yaml --sample "<sample>"`.
2. Show the suggested rule to the user and ask for confirmation.
3. Only after confirmation, run `python suggest_rule.py --rules rules.yaml --sample "<sample>" --apply`.

## Example

```powershell
python suggest_rule.py --rules rules.yaml --sample "INTERNAL_TOKEN=abc999"
```
