<#
.SYNOPSIS
    Assess Azure Windows VMs at risk for the 2023 Secure Boot certificate update.

.DESCRIPTION
    Iterates over every accessible subscription in the Azure tenant (or only the ones
    provided), enumerates Windows VMs and flags those that may require the
    "Windows UEFI CA 2023" / Secure Boot 2023 certificate update.

    Phase 1 (control-plane, always runs):
      - Lists Windows VMs.
      - Flags VMs created before 2024-04-01.
      - Reports security profile: securityType, Secure Boot, vTPM.

    Phase 2 (-DeepCheck, optional, requires VM running):
      - Uses 'az vm run-command invoke' to query the in-guest Secure Boot DB and
        check whether the "Windows UEFI CA 2023" certificate is present.

    Official references:
      - https://support.microsoft.com/topic/kb5025885
      - https://learn.microsoft.com/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance
      - https://techcommunity.microsoft.com/category/azure (Action recommended bulletins)

.PARAMETER TenantId
    (Required) Azure tenant ID. The script authenticates against this tenant and only
    evaluates subscriptions belonging to it.

.PARAMETER SubscriptionId
    One or more subscription IDs within the tenant. If omitted, every enabled subscription
    in the tenant is evaluated.

.PARAMETER OutputCsvPath
    (Optional) Path to a CSV file where the report will be written.

.PARAMETER IncludeStopped
    Include deallocated/stopped VMs in the report (enabled by default).

.PARAMETER DeepCheck
    Run an in-guest Secure Boot DB check on each running Windows VM via 'az vm run-command invoke'.
    This requires VM Agent connectivity and Contributor-level permissions; it is slower and
    chargeable depending on Run Command usage.

.EXAMPLE
    .\Test-AzVmSecureBoot2023Readiness.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -OutputCsvPath .\sb2023-report.csv

.EXAMPLE
    .\Test-AzVmSecureBoot2023Readiness.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -DeepCheck -Verbose

.NOTES
    Requires an authenticated Azure CLI (az): run 'az login' first.
    Read-only by default. -DeepCheck issues guest commands via Run Command (read-only script).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $TenantId,

    [Parameter()]
    [string[]] $SubscriptionId,

    [Parameter()]
    [string] $OutputCsvPath,

    [Parameter()]
    [switch] $IncludeStopped = $true,

    [Parameter()]
    [switch] $DeepCheck
)

#region --- Constants ---

# VMs created before this date may lack the "Windows UEFI CA 2023" cert in Secure Boot DB.
$Script:CutoffDate = [datetime]'2024-04-01T00:00:00Z'

# In-guest PowerShell script used by -DeepCheck. Reports whether the 2023 cert is present.
$Script:InGuestCheckScript = @'
try {
    $db = Get-SecureBootUEFI db -ErrorAction Stop
    $txt = [System.Text.Encoding]::ASCII.GetString($db.bytes)
    $has2023 = $txt -match 'Windows UEFI CA 2023'
    $hasKEK2023 = $false
    try {
        $kek = Get-SecureBootUEFI KEK -ErrorAction Stop
        $kekTxt = [System.Text.Encoding]::ASCII.GetString($kek.bytes)
        $hasKEK2023 = $kekTxt -match 'Microsoft Corporation KEK 2K CA 2023'
    } catch {}
    [pscustomobject]@{
        SecureBootEnabled = (Confirm-SecureBootUEFI)
        HasUefiCa2023     = $has2023
        HasKek2023        = $hasKEK2023
    } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{
        SecureBootEnabled = $false
        HasUefiCa2023     = $false
        HasKek2023        = $false
        Error             = $_.Exception.Message
    } | ConvertTo-Json -Compress
}
'@

#endregion

#region --- Helpers ---

function Assert-AzCli {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $TenantId)
    $cmd = Get-Command az -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Azure CLI (az) not found. Install it from: https://aka.ms/installazurecli"
    }
    $current = & az account show --only-show-errors -o json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    if (-not $current -or $current.tenantId -ne $TenantId) {
        Write-Host "Authenticating to tenant $TenantId ..." -ForegroundColor Yellow
        & az login --tenant $TenantId --only-show-errors -o none
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to authenticate to tenant $TenantId."
        }
    } else {
        Write-Verbose "Already authenticated to tenant $TenantId as $($current.user.name)."
    }
}

function Invoke-Az {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Args)
    $raw = & az @Args --only-show-errors -o json 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Verbose "az $($Args -join ' ') failed (exit=$LASTEXITCODE)"
        return $null
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try { return $raw | ConvertFrom-Json -Depth 100 } catch { return $null }
}

function Get-TargetSubscriptions {
    param(
        [Parameter(Mandatory)] [string] $TenantId,
        [string[]] $SubscriptionId
    )
    $all = Invoke-Az -Args @('account','list','--all','--query', "[?tenantId=='$TenantId']")
    if (-not $all) { return @() }
    $enabled = $all | Where-Object { $_.state -eq 'Enabled' }
    if ($SubscriptionId) {
        return $enabled | Where-Object { $SubscriptionId -contains $_.id }
    }
    return $enabled
}

function Invoke-InGuestSecureBootCheck {
    <#
    .SYNOPSIS
        Runs the in-guest check via 'az vm run-command invoke' and parses the JSON output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ResourceGroup,
        [Parameter(Mandatory)] [string] $VmName
    )

    $tmp = New-TemporaryFile
    try {
        Set-Content -Path $tmp -Value $Script:InGuestCheckScript -Encoding UTF8
        $result = Invoke-Az -Args @(
            'vm','run-command','invoke',
            '--resource-group', $ResourceGroup,
            '--name', $VmName,
            '--command-id', 'RunPowerShellScript',
            '--scripts', "@$tmp"
        )
        if (-not $result) { return $null }

        $stdout = ($result.value | Where-Object { $_.code -match 'StdOut' } | Select-Object -First 1).message
        if (-not $stdout) { return $null }

        # Run Command wraps output in "[stdout]\n<content>\n\n[stderr]\n..." for newer CLI versions.
        $jsonLine = ($stdout -split "`r?`n") |
            Where-Object { $_.Trim().StartsWith('{') -and $_.Trim().EndsWith('}') } |
            Select-Object -Last 1
        if (-not $jsonLine) { return $null }
        return $jsonLine | ConvertFrom-Json
    }
    finally {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-VmSecureBootReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Subscription,
        [switch] $IncludeStopped,
        [switch] $DeepCheck,
        [int]    $SubscriptionIndex = 1,
        [int]    $SubscriptionTotal = 1
    )

    Write-Host ""
    Write-Host ("[{0}/{1}] Subscription: " -f $SubscriptionIndex, $SubscriptionTotal) -ForegroundColor Cyan -NoNewline
    Write-Host ("{0} " -f $Subscription.name) -ForegroundColor White -NoNewline
    Write-Host ("({0})" -f $Subscription.id) -ForegroundColor DarkGray

    $null = az account set --subscription $Subscription.id --only-show-errors
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to select subscription $($Subscription.id)."
        return
    }

    Write-Host "  -> Listing VMs..." -ForegroundColor DarkGray
    $vms = Invoke-Az -Args @('vm','list','--show-details')
    if (-not $vms) {
        Write-Host "     No VMs found." -ForegroundColor DarkGray
        return
    }

    $winVms = @($vms | Where-Object { $_.storageProfile.osDisk.osType -eq 'Windows' })
    Write-Host ("     {0} VM(s) total, {1} Windows VM(s)." -f $vms.Count, $winVms.Count) -ForegroundColor Gray
    if ($winVms.Count -eq 0) { return }

    $i = 0
    foreach ($vm in $winVms) {
        $i++
        Write-Progress -Activity ("Subscription {0}/{1}: {2}" -f $SubscriptionIndex, $SubscriptionTotal, $Subscription.name) `
                       -Status   ("Checking VM {0}/{1}: {2}" -f $i, $winVms.Count, $vm.name) `
                       -PercentComplete ([int](($i / [Math]::Max($winVms.Count,1)) * 100))

        if (-not $IncludeStopped -and $vm.powerState -ne 'VM running') {
            Write-Host ("  - {0} [skipped: {1}]" -f $vm.name, $vm.powerState) -ForegroundColor DarkGray
            continue
        }

        # Fetch full VM resource to get timeCreated + full securityProfile.
        $full = Invoke-Az -Args @('vm','show','--ids', $vm.id)
        if (-not $full) { continue }

        $created      = $null
        if ($full.timeCreated) { $created = [datetime]$full.timeCreated }
        $secProfile   = $full.securityProfile
        $securityType = $secProfile.securityType
        $secureBoot   = [bool]($secProfile.uefiSettings.secureBootEnabled)
        $vTpm         = [bool]($secProfile.uefiSettings.vTpmEnabled)

        $createdBeforeCutoff = ($created -ne $null) -and ($created -lt $Script:CutoffDate)

        # Risk heuristic: Windows + Secure Boot enabled + created before cutoff.
        $atRisk = $createdBeforeCutoff -and $secureBoot

        $inGuestSecureBoot = $null
        $hasUefiCa2023     = $null
        $hasKek2023        = $null
        $deepStatus        = 'N/A'
        if ($DeepCheck) {
            if ($vm.powerState -ne 'VM running') {
                $deepStatus = 'Skipped (not running)'
            } else {
                Write-Host ("    -> Deep check on {0}..." -f $vm.name) -ForegroundColor DarkGray
                $r = Invoke-InGuestSecureBootCheck -ResourceGroup $vm.resourceGroup -VmName $vm.name
                if ($r) {
                    $inGuestSecureBoot = [bool]$r.SecureBootEnabled
                    $hasUefiCa2023     = [bool]$r.HasUefiCa2023
                    $hasKek2023        = [bool]$r.HasKek2023
                    $deepStatus        = 'OK'
                    if ($hasUefiCa2023) { $atRisk = $false } else { $atRisk = $secureBoot }
                } else {
                    $deepStatus = 'Failed'
                }
            }
        }

        $icon  = if ($atRisk) { '[!!]' } else { '[OK]' }
        $color = if ($atRisk) { 'Yellow' } else { 'Green' }
        $tags  = @()
        $tags += "type:$($securityType ?? 'Standard')"
        $tags += if ($secureBoot) { 'sb:on' } else { 'sb:off' }
        $tags += if ($vTpm)       { 'vtpm:on' } else { 'vtpm:off' }
        if ($created) { $tags += "created:$($created.ToString('yyyy-MM-dd'))" }
        if ($DeepCheck) { $tags += "ca2023:$([string]$hasUefiCa2023)" }
        Write-Host ("  {0} {1,-40} {2}" -f $icon, $vm.name, ($tags -join ' ')) -ForegroundColor $color

        [pscustomobject][ordered]@{
            SubscriptionName  = $Subscription.name
            SubscriptionId    = $Subscription.id
            ResourceGroup     = $vm.resourceGroup
            VmName            = $vm.name
            Location          = $vm.location
            PowerState        = $vm.powerState
            OsType            = $vm.storageProfile.osDisk.osType
            VmSize            = $vm.hardwareProfile.vmSize
            TimeCreated       = $created
            CreatedBeforeCutoff = $createdBeforeCutoff
            SecurityType      = $securityType
            SecureBootEnabled = $secureBoot
            VTpmEnabled       = $vTpm
            DeepCheckStatus   = $deepStatus
            InGuestSecureBoot = $inGuestSecureBoot
            HasUefiCa2023     = $hasUefiCa2023
            HasKek2023        = $hasKek2023
            AtRisk            = $atRisk
        }
    }
    Write-Progress -Activity ("Subscription {0}/{1}: {2}" -f $SubscriptionIndex, $SubscriptionTotal, $Subscription.name) -Completed
}

#endregion

#region --- Main ---

try {
    Assert-AzCli -TenantId $TenantId

    $subs = Get-TargetSubscriptions -TenantId $TenantId -SubscriptionId $SubscriptionId
    if (-not $subs -or $subs.Count -eq 0) {
        Write-Warning "No enabled subscription found in tenant $TenantId for evaluation."
        return
    }

    Write-Host ""
    Write-Host "Starting Secure Boot 2023 readiness scan..." -ForegroundColor Cyan
    Write-Host ("Subscriptions to evaluate: {0}" -f $subs.Count) -ForegroundColor Gray
    if ($DeepCheck) { Write-Host "DeepCheck ENABLED (in-guest Run Command on running Windows VMs)." -ForegroundColor Magenta }

    $report = @()
    $idx = 0
    foreach ($sub in $subs) {
        $idx++
        $report += Get-VmSecureBootReport -Subscription $sub -IncludeStopped:$IncludeStopped `
                                          -DeepCheck:$DeepCheck `
                                          -SubscriptionIndex $idx -SubscriptionTotal $subs.Count
    }

    if ($OutputCsvPath) {
        $report | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Report saved to: $OutputCsvPath" -ForegroundColor Green
    }

    $total    = ($report | Measure-Object).Count
    $risk     = ($report | Where-Object AtRisk).Count
    $sbOn     = ($report | Where-Object SecureBootEnabled).Count
    $oldVms   = ($report | Where-Object CreatedBeforeCutoff).Count

    Write-Host ''
    Write-Host '=== Secure Boot 2023 Readiness Summary ===' -ForegroundColor Cyan
    Write-Host ("Windows VMs evaluated     : {0}" -f $total)
    Write-Host ("Created before 2024-04-01 : {0}" -f $oldVms)
    Write-Host ("Secure Boot enabled       : {0}" -f $sbOn)
    Write-Host ("VMs flagged AT RISK       : {0}" -f $risk) -ForegroundColor Yellow
    Write-Host ''

    $report
}
catch {
    Write-Error $_
    exit 1
}

#endregion
