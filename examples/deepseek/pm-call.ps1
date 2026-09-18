# deepseek-harness 外部工具包装（Windows PowerShell）
# 用法：pm-call.ps1 <site> <method> <path> [json_body]
# 环境变量：PM_DAEMON=http://127.0.0.1:9777  PM_TOKEN=<token>
param(
    [Parameter(Mandatory=$true)][string]$Site,
    [Parameter(Mandatory=$true)][string]$Method,
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$Body = ""
)
$daemon = if ($env:PM_DAEMON) { $env:PM_DAEMON } else { "http://127.0.0.1:9777" }
if (-not $env:PM_TOKEN) { throw "缺少环境变量 PM_TOKEN" }
$args = @("call", "--daemon", $daemon, "--token", $env:PM_TOKEN, "--site", $Site, "--method", $Method, "--path", $Path)
if ($Body) { $args += @("--json", $Body) }
& pm @args
exit $LASTEXITCODE
