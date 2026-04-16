$repoRoot = Split-Path -Parent $PSScriptRoot
$tempRules = Join-Path $env:TEMP "vibeguard-demo-rules.yaml"

Copy-Item -LiteralPath (Join-Path $repoRoot "rules.yaml") -Destination $tempRules -Force

Write-Host "=== Scene 1: redact .env before sending context ==="
python (Join-Path $repoRoot "redact_context.py") --rules $tempRules --input (Join-Path $PSScriptRoot "sample_project\\.env") --json

Write-Host ""
Write-Host "=== Scene 2: review risky command before execution ==="
python (Join-Path $repoRoot "review_command.py") --rules $tempRules "rm -rf /data"

Write-Host ""
Write-Host "=== Scene 3: learn a new rule and re-run redaction ==="
python (Join-Path $repoRoot "suggest_rule.py") --rules $tempRules --sample "INTERNAL_TOKEN=abc999"
python (Join-Path $repoRoot "suggest_rule.py") --rules $tempRules --sample "INTERNAL_TOKEN=abc999" --apply
@"
INTERNAL_TOKEN=abc999
OPENAI_API_KEY=sk-test-123456789
"@ | python (Join-Path $repoRoot "redact_context.py") --rules $tempRules --json

Write-Host ""
Write-Host "Temporary demo rules saved to: $tempRules"
