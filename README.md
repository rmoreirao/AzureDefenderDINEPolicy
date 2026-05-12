# Azure Defender DINE Policy — Sequential Plan Enablement

A custom Azure Policy (DeployIfNotExists) that enables all required **Microsoft Defender for Cloud** plans on a subscription **sequentially**, in a single ARM deployment, to avoid concurrent-write conflicts on the `Microsoft.Security/pricings` resource provider.

## Why this exists

The built-in Defender for Cloud initiative assigns one DINE policy per plan (VirtualMachines, SqlServers, StorageAccounts, KeyVaults, …). When a subscription is non-compliant for several plans at once, Azure Policy triggers those remediations **in parallel**. The `Microsoft.Security` RP does not handle concurrent PUTs to different `pricings` resources well — remediations intermittently fail with conflict / throttling errors.

This policy works around that by:

- Bundling **all** plan enablements into **one** subscription-scope ARM template.
- Chaining each `Microsoft.Security/pricings` resource with `dependsOn` so they deploy **one after another**.
- Using a single sentinel plan (`VirtualMachines`) in the policy's `existenceCondition` to detect non-compliance.

Result: a single remediation deployment that enables every plan in a deterministic order, with no concurrent calls to the Security RP.

## What it deploys

Plans enabled (in order), all at `pricingTier = Standard`:

1. VirtualMachines (sub-plan configurable: `P1` or `P2`, default `P2`)
2. SqlServers
3. SqlServerVirtualMachines
4. StorageAccounts
5. KeyVaults
6. AppServices
7. Containers
8. Arm
9. Dns
10. Api (sub-plan `P1`)
11. CosmosDbs
12. OpenSourceRelationalDatabases

## Repository layout

| File | Purpose |
| --- | --- |
| [policy/deploy-defender-plans-sequential.json](policy/deploy-defender-plans-sequential.json) | The custom policy definition (DINE) with the embedded sequential ARM template. |
| [policy/DeployAndValidatePolicy.ps1](policy/DeployAndValidatePolicy.ps1) | End-to-end script: create the policy, assign it, force non-compliance, trigger remediation, and inspect results. |

## Policy parameters

| Name | Allowed values | Default | Description |
| --- | --- | --- | --- |
| `effect` | `DeployIfNotExists`, `Disabled` | `DeployIfNotExists` | Standard Azure Policy effect toggle. |
| `serversSubPlan` | `P1`, `P2` | `P2` | Sub-plan for Defender for Servers. |

## Prerequisites

- An Azure subscription where you can create policy definitions and role assignments.
- PowerShell 7+ with the `Az` modules installed:
  ```powershell
  Install-Module Az -Scope CurrentUser
  ```
- Signed in to Azure: `Connect-AzAccount`.
- Permission to assign the **Security Admin** role (`fb1c8493-542b-48eb-b624-b4c8fea62acd`) on the subscription (e.g., Owner or User Access Administrator).

## Quick start — test the policy end-to-end

The script [policy/DeployAndValidatePolicy.ps1](policy/DeployAndValidatePolicy.ps1) does everything for you. Open it and replace the `$subId` value at the top with your target subscription ID, then run it:

```powershell
cd policy
./DeployAndValidatePolicy.ps1
```

### Expected outcome

- The remediation finishes in `Succeeded` state.
- `Get-AzSecurityPricing` shows all plans listed above at `Standard` (and the Servers/Api sub-plans set as configured).
- `DeploymentSummary` shows the inner template ran once and completed without conflict errors.

## Re-running the test

To re-trigger remediation later without recreating everything, just downgrade one or more plans to `Free` again and re-run from step 4 of the script (compliance scan + new remediation).

## Cleanup

```powershell
$subId = "b0dfd5b3-9f3c-4fb5-ae5e-0e7f81eab970"

# Remove role assignment, policy assignment, and definition
$assignment = Get-AzPolicyAssignment -Name 'deploy-defender-seq' -Scope "/subscriptions/$subId"
Remove-AzRoleAssignment -ObjectId $assignment.IdentityPrincipalId `
  -RoleDefinitionId 'fb1c8493-542b-48eb-b624-b4c8fea62acd' `
  -Scope "/subscriptions/$subId"
Remove-AzPolicyAssignment -Name 'deploy-defender-seq' -Scope "/subscriptions/$subId"
Remove-AzPolicyDefinition -Name 'deploy-defender-seq' -SubscriptionId $subId -Force
```

> Note: this does **not** disable Defender plans. To revert pricing, use `Set-AzSecurityPricing -Name <Plan> -PricingTier 'Free'` for each plan you want to turn off.

## Troubleshooting

- **Remediation fails with `AuthorizationFailed`** — the managed identity is missing the Security Admin role. Re-run the `New-AzRoleAssignment` step and wait ~1 minute for propagation.
- **`Start-AzPolicyRemediation` reports 0 resources** — compliance state hasn't refreshed yet. Wait for the compliance scan to progress, or downgrade a plan again to ensure non-compliance.
- **Per-step error details** — the script's `listDeployments` block prints the failing step's `code` and `message`, which map directly to one of the `Microsoft.Security/pricings` entries in the inner template.
