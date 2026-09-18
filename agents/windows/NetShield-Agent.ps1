#requires -Version 5.1
<# Visible, interactive-session agent. No service installation or hidden startup.
   Start with: powershell.exe -STA -File .\NetShield-Agent.ps1 -Config .\agent-config.json
#>
param([string]$Config, [string]$DeviceId)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -Path (Join-Path $PSScriptRoot 'Core\AgentCore.cs') -ReferencedAssemblies 'System.dll','System.Core.dll','System.Net.Http.dll','System.Runtime.Serialization.dll'
if ((-not $Config -and -not $DeviceId) -or ($Config -and $DeviceId)) {
    throw 'Use -Config to import a pairing file, or -DeviceId to use protected local state.'
}
[NetShield.Agent.Configuration]$bootstrap = $null
if ($Config) {
    if ((Get-Item -LiteralPath $Config).Length -gt 16384) { throw 'Configuration file is too large.' }
    $configuration = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
    $bootstrap = New-Object NetShield.Agent.Configuration
    $bootstrap.Server = $configuration.server
    $bootstrap.DeviceId = $configuration.device_id
    $bootstrap.Token = $configuration.token
    $bootstrap.Validate()
    $DeviceId = $bootstrap.DeviceId
}
if ($DeviceId -notmatch '\A[a-zA-Z0-9_-]{1,64}\z') { throw 'Invalid device ID.' }
$stateDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('NetShield\Agent\' + $DeviceId)
[void][IO.Directory]::CreateDirectory($stateDirectory)
if ((Get-Item -LiteralPath $stateDirectory).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State directory cannot be a reparse point.' }
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$rule = New-Object Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', $inherit, 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $stateDirectory -AclObject $acl
$protector = New-Object NetShield.Agent.WindowsProtector
$script:queue = [NetShield.Agent.DurableQueue]::new((Join-Path $stateDirectory 'state.dat'), $protector, $bootstrap)
$script:runtime = $null
$timer = $null
$form = $null
$sourcePrefix = 'NetShield-' + [Guid]::NewGuid().ToString('N')
try {
$configuration = $script:queue.Configuration
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$script:bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
$script:sessionState = 'unknown'
$script:clock = [Diagnostics.Stopwatch]::StartNew()
$script:nextSend = 0
$script:failures = 0
$script:closing = $false
$script:allowClose = $false
$script:closeDeadline = 0
$script:finalSendStarted = $false
$script:runtime = [NetShield.Agent.AgentRuntime]::new($script:queue, (New-Object NetShield.Agent.Transport))
function Add-StatusEvent([string]$kind, [DateTime]$when = [DateTime]::UtcNow) {
    [void]$script:queue.Enqueue($kind, [DateTimeOffset]$when.ToUniversalTime())
}
$form = New-Object System.Windows.Forms.Form
$form.Text = 'NetShield - Cihaz durum ajani'
$form.ClientSize = New-Object System.Drawing.Size(610, 260)
$form.StartPosition = 'CenterScreen'
$notice = New-Object System.Windows.Forms.Label
$notice.Location = New-Object System.Drawing.Point(20, 20)
$notice.Size = New-Object System.Drawing.Size(570, 125)
$notice.Text = "Bu ajan acilis zamanini, kilit/uyku olaylarini ve baglanti durumunu bildirir.`r`nHedef: $($configuration.Server)`r`nCihaz: $($configuration.DeviceId)`r`nEkran, tuslar, dosyalar veya kullanilan uygulamalar toplanmaz.`r`nPencereyi kapatmak veri gonderimini durdurur."
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

function Poll-Sender {
    $result = $script:runtime.Poll()
    if ($null -eq $result) { return }
    $labels = @{
        accepted='Bildirim teslim edildi'; credential_rejected='Eslesme anahtari reddedildi; yeniden eslestirin'
        receiver_busy='Alici mesgul veya depolama hatasi; tekrar denenecek'; timeout='Baglanti zaman asimi'
        dns_error='Sunucu adi cozumlenemedi; DNS ve adresi kontrol edin'
        tls_error='TLS sertifikasi dogrulanamadi; ad ve guven zincirini kontrol edin'
        connection_error='Sunucuya baglanilamadi; ag ve aliciyi kontrol edin'
        protocol_error='Alici protokolu/teslim onayi gecersiz; olaylar korundu'
        storage_error='Yerel kuyruk yazilamadi; disk ve izinleri kontrol edin'; cancelled='Gonderim iptal edildi'
    }
    $script:statusLabel.Text = $labels[$result.Code] + "`r`nBekleyen: $($script:queue.Count) | Kota/saklama nedeniyle dusen: $($script:queue.Dropped)"
    if ($result.Success) {
        $script:failures = 0
        $delay = 30000
        if ($script:queue.Count -gt 0) { $delay = 2500 }
    } else {
        $script:failures = [Math]::Min(6, $script:failures + 1)
        $delay = [Math]::Min(60000, 1000 * [Math]::Pow(2, $script:failures)) + (Get-Random -Minimum 0 -Maximum 1000)
    }
    $script:nextSend = $script:clock.ElapsedMilliseconds + $delay
}
# Queued .NET events are consumed on the GUI thread, avoiding PowerShell runspace callbacks.
Register-ObjectEvent -InputObject ([Microsoft.Win32.SystemEvents]) -EventName SessionSwitch -SourceIdentifier ($sourcePrefix + '-session') | Out-Null
Register-ObjectEvent -InputObject ([Microsoft.Win32.SystemEvents]) -EventName PowerModeChanged -SourceIdentifier ($sourcePrefix + '-power') | Out-Null
Add-StatusEvent 'agent_started'
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
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
        if ($kind -and -not $script:closing) {
            try { Add-StatusEvent $kind $eventItem.TimeGenerated }
            catch { $script:statusLabel.Text = 'Olay diske kaydedilemedi. Mevcut kuyruk korundu; disk ve izinleri kontrol edin.' }
        }
        Remove-Event -EventIdentifier $eventItem.EventIdentifier
    }
    Poll-Sender
    if ($script:closing) {
        if (-not $script:runtime.Busy -and -not $script:finalSendStarted) {
            $script:finalSendStarted = $true
            [void]$script:runtime.BeginSend($script:bootTime, $script:sessionState, 'stopped')
        }
        if ($script:clock.ElapsedMilliseconds -ge $script:closeDeadline -or ($script:finalSendStarted -and -not $script:runtime.Busy)) {
            $script:allowClose = $true
            $form.Close()
        }
    } elseif (-not $script:runtime.Busy -and $script:clock.ElapsedMilliseconds -ge $script:nextSend) {
        [void]$script:runtime.BeginSend($script:bootTime, $script:sessionState, 'running')
    }
})
$form.Add_FormClosing({
    param($sender, $eventArgs)
    if ($script:allowClose) { return }
    if (-not $script:closing) {
        $script:closing = $true
        $script:closeDeadline = $script:clock.ElapsedMilliseconds + 2000
        try { Add-StatusEvent 'agent_stopped' }
        catch { $script:statusLabel.Text = 'Son olay kaydedilemedi; mevcut kuyruk korundu.' }
    }
    if ($eventArgs.CloseReason -eq [System.Windows.Forms.CloseReason]::WindowsShutDown) {
        $script:allowClose = $true
    } else {
        $eventArgs.Cancel = $true
        $stopButton.Enabled = $false
    }
})
    $timer.Start()
    [void]$form.ShowDialog()
} finally {
    if ($timer) { $timer.Dispose() }
    if ($script:runtime) { $script:runtime.Dispose() } else { $script:queue.Dispose() }
    Unregister-Event -SourceIdentifier ($sourcePrefix + '-session') -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier ($sourcePrefix + '-power') -ErrorAction SilentlyContinue
    Get-Event | Where-Object { $_.SourceIdentifier -like ($sourcePrefix + '-*') } | Remove-Event
    if ($form) { $form.Dispose() }
}
