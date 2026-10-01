#requires -Version 5.1
# Local Windows-only smoke tests. No network, service install or machine policy changes.
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'Core\AgentCore.cs') -ReferencedAssemblies 'System.dll','System.Core.dll','System.Net.Http.dll','System.Runtime.Serialization.dll','System.Xml.dll'
$directory = Join-Path ([IO.Path]::GetTempPath()) ('NetShield-Smoke-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
$queue = $null
try {
    $configuration = New-Object NetShield.Agent.Configuration
    $configuration.Server = 'https://netshield.example'
    $configuration.DeviceId = 'smoke-device'
    $configuration.Token = 'a' * 43
    $protector = New-Object NetShield.Agent.WindowsProtector
    $clear = [Text.Encoding]::UTF8.GetBytes('synthetic-dpapi-test')
    $protected = $protector.Protect($clear)
    if ([Convert]::ToBase64String($protected) -eq [Convert]::ToBase64String($clear)) { throw 'DPAPI did not protect data.' }
    if ([Text.Encoding]::UTF8.GetString($protector.Unprotect($protected)) -ne 'synthetic-dpapi-test') { throw 'DPAPI round trip failed.' }
    Write-Output 'PASS Windows CurrentUser DPAPI round trip'
    $path = Join-Path $directory 'state.dat'
    $queue = [NetShield.Agent.DurableQueue]::new($path, $protector, $configuration)
    $id = $queue.Enqueue('agent_started', [DateTimeOffset]::UtcNow)
    $queue.Dispose()
    $queue = [NetShield.Agent.DurableQueue]::new($path, $protector, $null)
    if ($queue.Count -ne 1 -or $queue.Batch([DateTimeOffset]::UtcNow.ToString('o'), 'unknown', 'running').Events[0].Id -ne $id) { throw 'Persisted event was not restored.' }
    if ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($path)).Contains($configuration.Token)) { throw 'Plaintext credential found in state.' }
    Write-Output 'PASS Windows protected queue reopen and credential storage'
    $queue.Dispose()
    $queue = $null
    $bad = [IO.File]::ReadAllBytes($path)
    $bad[0] = $bad[0] -bxor 255
    [IO.File]::WriteAllBytes($path, $bad)
    $rejected = $false
    try { $queue = [NetShield.Agent.DurableQueue]::new($path, $protector, $null) } catch { $rejected = $true }
    if (-not $rejected) { throw 'Corrupt protected state was accepted.' }
    Write-Output 'PASS corrupt Windows state rejected without reset'
    Write-Output 'Windows storage smoke checks passed; interactive lock/sleep/shutdown tests remain separate.'
} finally {
    if ($queue) { $queue.Dispose() }
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
}
