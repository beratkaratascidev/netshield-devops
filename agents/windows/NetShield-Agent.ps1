#requires -Version 5.1
<# Visible, interactive-session agent. No service installation or hidden startup.
   Start with: powershell.exe -STA -File .\NetShield-Agent.ps1 -Config .\agent-config.json
#>
param([Parameter(Mandatory=$true)][string]$Config)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$configuration = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$serverUri = [Uri]$configuration.server
if ($serverUri.Scheme -ne 'https' -or $serverUri.UserInfo -or $serverUri.Query -or $serverUri.Fragment -or $serverUri.AbsolutePath -ne '/') {
    throw 'An HTTPS server origin without credentials or path is required.'
}
if ($configuration.device_id -notmatch '^[a-zA-Z0-9_-]{1,64}$' -or $configuration.token -notmatch '^[a-zA-Z0-9_-]{40,128}$') {
    throw 'Invalid device configuration.'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$script:bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
$script:sessionState = 'unknown'
$script:pending = New-Object System.Collections.ArrayList
$script:lastSent = [DateTime]::MinValue
$sourcePrefix = 'NetShield-' + [Guid]::NewGuid().ToString('N')
function Add-StatusEvent([string]$kind, [DateTime]$when = [DateTime]::UtcNow) {
    [void]$script:pending.Add(@{id=[Guid]::NewGuid().ToString('N'); kind=$kind; time=$when.ToUniversalTime().ToString('o')})
    while ($script:pending.Count -gt 100) { $script:pending.RemoveAt(0) }
}
$form = New-Object System.Windows.Forms.Form
$form.Text = 'NetShield - Cihaz durum ajani'
$form.ClientSize = New-Object System.Drawing.Size(610, 260)
$form.StartPosition = 'CenterScreen'
$notice = New-Object System.Windows.Forms.Label
$notice.Location = New-Object System.Drawing.Point(20, 20)
$notice.Size = New-Object System.Drawing.Size(570, 125)
$notice.Text = "Bu ajan acilis zamanini, kilit/uyku olaylarini ve baglanti durumunu bildirir.`r`nHedef: $($configuration.server)`r`nCihaz: $($configuration.device_id)`r`nEkran, tuslar, dosyalar veya kullanilan uygulamalar toplanmaz.`r`nPencereyi kapatmak veri gonderimini durdurur."
$form.Controls.Add($notice)
$script:statusLabel = New-Object System.Windows.Forms.Label
$script:statusLabel.Location = New-Object System.Drawing.Point(20, 155)
$script:statusLabel.Size = New-Object System.Drawing.Size(570, 55)
$script:statusLabel.Text = 'Baglanti bekleniyor...'
$form.Controls.Add($script:statusLabel)
$stopButton = New-Object System.Windows.Forms.Button
$stopButton.Text = 'Ajani durdur'
$stopButton.Location = New-Object System.Drawing.Point(20, 215)
$stopButton.Size = New-Object System.Drawing.Size(160, 30)
$stopButton.Add_Click({ $form.Close() })
$form.Controls.Add($stopButton)

function Send-Status {
    $body = @{boot_time=$script:bootTime; session=$script:sessionState; events=@($script:pending.ToArray())} | ConvertTo-Json -Depth 5 -Compress
    $endpoint = $configuration.server.TrimEnd('/') + '/v1/status/' + $configuration.device_id
    try {
        # Normal certificate/hostname validation; redirects are never followed.
        Invoke-RestMethod -Uri $endpoint -Method Post -Headers @{Authorization=('Bearer ' + $configuration.token)} -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 5 -MaximumRedirection 0 | Out-Null
        $script:pending.Clear()
        $script:statusLabel.Text = 'Bagli. Son basarili bildirim: ' + (Get-Date -Format 'HH:mm:ss')
    } catch {
        # Do not print exception bodies or credentials. Retry a bounded queue in memory.
        $script:statusLabel.Text = 'Sunucuya ulasilamadi. TLS sertifikasi, adres ve eslestirmeyi kontrol edin. 30 sn sonra tekrar denenecek.'
    }
    $script:lastSent = [DateTime]::UtcNow
}
# Queued .NET events are consumed on the GUI thread, avoiding PowerShell runspace callbacks.
Register-ObjectEvent -InputObject ([Microsoft.Win32.SystemEvents]) -EventName SessionSwitch -SourceIdentifier ($sourcePrefix + '-session') | Out-Null
Register-ObjectEvent -InputObject ([Microsoft.Win32.SystemEvents]) -EventName PowerModeChanged -SourceIdentifier ($sourcePrefix + '-power') | Out-Null
Add-StatusEvent 'agent_started'
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    foreach ($eventItem in @(Get-Event | Where-Object { $_.SourceIdentifier -like ($sourcePrefix + '-*') })) {
        $kind = $null
        if ($eventItem.SourceIdentifier -eq ($sourcePrefix + '-session')) {
            switch ($eventItem.SourceEventArgs.Reason.ToString()) {
                'SessionLock' { $script:sessionState = 'locked'; $kind = 'session_lock' }
                'SessionUnlock' { $script:sessionState = 'unlocked'; $kind = 'session_unlock' }
                'SessionLogoff' { $script:sessionState = 'unknown'; $kind = 'session_logoff' }
            }
        } else {
            switch ($eventItem.SourceEventArgs.Mode.ToString()) {
                'Suspend' { $kind = 'suspend' }
                'Resume' { $kind = 'resume' }
            }
        }
        if ($kind) { Add-StatusEvent $kind $eventItem.TimeGenerated }
        Remove-Event -EventIdentifier $eventItem.EventIdentifier
    }
    if (([DateTime]::UtcNow - $script:lastSent).TotalSeconds -ge 30) { Send-Status }
})
$form.Add_FormClosing({
    $timer.Stop()
    Add-StatusEvent 'agent_stopped'
    Send-Status
})
try {
    $timer.Start()
    [void]$form.ShowDialog()
} finally {
    $timer.Dispose()
    Unregister-Event -SourceIdentifier ($sourcePrefix + '-session') -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier ($sourcePrefix + '-power') -ErrorAction SilentlyContinue
    Get-Event | Where-Object { $_.SourceIdentifier -like ($sourcePrefix + '-*') } | Remove-Event
    $form.Dispose()
}
