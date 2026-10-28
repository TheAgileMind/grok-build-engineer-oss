$ErrorActionPreference = "Stop"
$response = [ordered]@{
  contractVersion = "agent-platform.grok-build-engineer-cli.v2"
  ok = $false
  operation = "job-host"
  error = [ordered]@{
    code = "migration_required"
    message = "The persistent MCP job host is retired. Use scripts/grok-delegate.mjs for prepare, submit, status, repair, collect, and cancel."
  }
  exitCode = 69
}
$response | ConvertTo-Json -Compress
exit 69
