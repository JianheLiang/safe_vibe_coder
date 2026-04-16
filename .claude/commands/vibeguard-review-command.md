# `/vibeguard-review-command`

Use this command before proposing or executing shell or SQL commands that delete data, change permissions, or mutate infrastructure.

## Workflow

1. Run `python review_command.py --rules rules.yaml "<command>"`.
2. If `matched` is `true`, explain `risk_level`, `why_flagged`, and `safer_alternative` before proceeding.
3. If `matched` is `false`, continue with the normal tool-side permission flow.

## Example

```powershell
python review_command.py --rules rules.yaml "rm -rf /data"
```
