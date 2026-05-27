# Azure VM Secure Boot 2023 Readiness Check

A reusable PowerShell script that scans your entire Azure tenant and identifies **Windows VMs at risk** for the **Secure Boot 2023 certificate update** ("Windows UEFI CA 2023" / KB5025885).

Microsoft is rotating the Secure Boot certificates that expire in 2026. Windows VMs **created before April 2024** that have Secure Boot enabled may not have the new certificate provisioned and require the update.

## What it checks

For every **Windows** VM in every accessible subscription:

### Phase 1 — Control-plane (default, fast, read-only)
- VM is Windows.
- `timeCreated < 2024-04-01` (created before the cutoff).
- `securityProfile.securityType` (Standard / TrustedLaunch / ConfidentialVM).
- `securityProfile.uefiSettings.secureBootEnabled`.
- `securityProfile.uefiSettings.vTpmEnabled`.

A VM is flagged **AtRisk = true** when: created before cutoff **AND** Secure Boot is enabled.

### Phase 2 — `-DeepCheck` (optional, in-guest)
For each **running** Windows VM, runs `Get-SecureBootUEFI db` via `az vm run-command invoke` to check whether the **"Windows UEFI CA 2023"** certificate is already present in the Secure Boot DB (and "Microsoft Corporation KEK 2K CA 2023" in KEK).
If the 2023 CA is present, the VM is no longer flagged at risk.

## Requirements

- [Azure CLI](https://aka.ms/installazurecli) (`az`) installed and signed in (`az login`).
- PowerShell 7+ recommended.
- Read access for Phase 1 (`Reader` role).
- `Virtual Machine Contributor` (or equivalent Run Command permissions) on subscriptions you want to scan with `-DeepCheck`.

## Usage

```powershell
# Fast scan (control plane only)
.\Test-AzVmSecureBoot2023Readiness.ps1 -TenantId <tenant-guid> -OutputCsvPath .\sb2023-report.csv

# Limit to specific subscriptions inside the tenant
.\Test-AzVmSecureBoot2023Readiness.ps1 -TenantId <tenant-guid> -SubscriptionId <sub-guid>

# Deep in-guest verification (slower, requires VMs running)
.\Test-AzVmSecureBoot2023Readiness.ps1 -TenantId <tenant-guid> -DeepCheck -OutputCsvPath .\sb2023-report.csv

# Pipe results: only at-risk VMs
.\Test-AzVmSecureBoot2023Readiness.ps1 -TenantId <tenant-guid> | Where-Object AtRisk | Format-Table
```

> The script validates that `az` is signed in to the specified tenant. If not, it runs
> `az login --tenant <TenantId>` automatically.

### Parameters

| Parameter         | Required | Description                                                       |
|-------------------|----------|-------------------------------------------------------------------|
| `-TenantId`       | Yes      | Azure tenant to authenticate against and scope subscriptions to.  |
| `-SubscriptionId` | No       | One or more subscription IDs within the tenant.                   |
| `-OutputCsvPath`  | No       | Path to write the report as CSV.                                  |
| `-IncludeStopped` | No       | Include deallocated/stopped VMs (default: on).                    |
| `-DeepCheck`      | No       | Run in-guest Secure Boot DB inspection via Run Command.           |

## Sample run

```
PS> .\Test-AzVmSecureBoot2023Readiness.ps1 -TenantId 1d70d939-06d2-4348-b658-58cb38886348

Starting Secure Boot 2023 readiness scan...
Subscriptions to evaluate: 4

[1/4] Subscription: ME-MngEnvMCAP266581-lramoscostah-3 (...)
  -> Listing VMs...
     No VMs found.
[2/4] Subscription: ME-MngEnvMCAP266581-lramoscostah-4 (...)
  -> Listing VMs...
     1 VM(s) total, 1 Windows VM(s).
  [OK] Kami-Vm                                  type:TrustedLaunch sb:on vtpm:on created:2025-06-12

=== Secure Boot 2023 Readiness Summary ===
Windows VMs evaluated     : 1
Created before 2024-04-01 : 0
Secure Boot enabled       : 1
VMs flagged AT RISK       : 0
```

## Output fields

`SubscriptionName, SubscriptionId, ResourceGroup, VmName, Location, PowerState, OsType, VmSize, TimeCreated, CreatedBeforeCutoff, SecurityType, SecureBootEnabled, VTpmEnabled, DeepCheckStatus, InGuestSecureBoot, HasUefiCa2023, HasKek2023, AtRisk`

Summary printed at the end:

```
=== Secure Boot 2023 Readiness Summary ===
Windows VMs evaluated     : 42
Created before 2024-04-01 : 28
Secure Boot enabled       : 18
VMs flagged AT RISK       : 14
```

## Notes & limitations

- Read-only by default. `-DeepCheck` invokes a read-only PowerShell script inside the guest via Run Command (no changes are made).
- Run Command requires VM Agent connectivity and may incur small charges.
- VMs without Secure Boot enabled are not affected by the 2023 certificate update.
- The control-plane phase cannot determine the actual in-guest cert state — use `-DeepCheck` for definitive answers on running VMs.

## References

- [KB5025885 — How to manage the Windows Boot Manager revocations for Secure Boot changes](https://support.microsoft.com/topic/kb5025885)
- [Windows Secure Boot key creation and management guidance](https://learn.microsoft.com/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance)
- [Trusted Launch for Azure VMs](https://learn.microsoft.com/azure/virtual-machines/trusted-launch)
