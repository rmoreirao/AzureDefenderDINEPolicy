# Subscription ID = 74f7fd0f-5456-4985-b3ef-4f3c5aaf7a4f
$subId = "b0dfd5b3-9f3c-4fb5-ae5e-0e7f81eab970"

# 1. Create + assign
$def = New-AzPolicyDefinition -Name 'deploy-defender-seq' `
  -Policy .\policy\deploy-defender-plans-sequential.json -SubscriptionId $subId

$assignment = New-AzPolicyAssignment -Name 'deploy-defender-seq' `
  -PolicyDefinition $def -Scope "/subscriptions/$subId" `
  -IdentityType SystemAssigned -Location westeurope

# 2. Grant the MI 'Security Admin' (role id in the policy)
New-AzRoleAssignment -ObjectId $assignment.IdentityPrincipalId  `
  -RoleDefinitionId 'fb1c8493-542b-48eb-b624-b4c8fea62acd' `
  -Scope "/subscriptions/$subId"

# 2b. Force non-compliance so DINE actually deploys.
#     Downgrade the sentinel plans (VirtualMachines, SqlServers, AppServices, API, KeyVaults and Dns) to Free; the policy's
#     existenceCondition (pricingTier == Standard) will fail and remediation
#     will run the inner sequential template.
Write-Host "Current Defender plans BEFORE forcing non-compliance:"
Get-AzSecurityPricing | Select-Object Name, PricingTier, SubPlan | Format-Table

Set-AzSecurityPricing -Name 'VirtualMachines' -PricingTier 'Free' | Out-Null
Set-AzSecurityPricing -Name 'SqlServers' -PricingTier 'Free' | Out-Null
Set-AzSecurityPricing -Name 'AppServices' -PricingTier 'Free' | Out-Null
Set-AzSecurityPricing -Name 'API' -PricingTier 'Free' | Out-Null
Set-AzSecurityPricing -Name 'KeyVaults' -PricingTier 'Free' | Out-Null
Set-AzSecurityPricing -Name 'Dns' -PricingTier 'Free' | Out-Null
Write-Host "VirtualMachines, SqlServers, AppServices, API, KeyVaults, and Dns plans set to Free to trigger remediation."

# Give RP a few seconds to settle before re-evaluation
Start-Sleep -Seconds 15

# 3. Force evaluation + remediation
Set-AzContext -SubscriptionId $subId | Out-Null
# -AsJob: scan runs server-side (10-30+ min); we don't need to block on it
# because Start-AzPolicyRemediation -ResourceDiscoveryMode ReEvaluateCompliance
# triggers its own evaluation.
$scanJob = Start-AzPolicyComplianceScan -AsJob
Write-Host "Compliance scan job started (Id=$($scanJob.Id)). Continuing without waiting."

# Re-fetch assignment to ensure Id/Identity are populated
$assignment = Get-AzPolicyAssignment -Name 'deploy-defender-seq' -Scope "/subscriptions/$subId"
$assignmentId = $assignment.Id
if (-not $assignmentId) { $assignmentId = $assignment.ResourceId }
if (-not $assignmentId) { $assignmentId = $assignment.PolicyAssignmentId }

$remediationName = "remediate-defender-seq-$(Get-Date -Format 'yyyyMMddHHmmss')"
Start-AzPolicyRemediation -Name $remediationName `
  -PolicyAssignmentId $assignmentId `
  -ResourceDiscoveryMode ReEvaluateCompliance

Start-Sleep -Seconds 30 # Give remediation a few seconds to start before polling status

# 4. Check status of remediation

# Wait until remediation is no longer 'NotStarted' or 'Running' or 'Evaluating'
do {
    $remediation = Get-AzPolicyRemediation -Name $remediationName -Scope "/subscriptions/$subId"
    # Output status to console
    Write-Host "Remediation status: $($remediation.ProvisioningState) at $(Get-Date)"
    
    Start-Sleep -Seconds 10
} while ($remediation.ProvisioningState -in @('NotStarted', 'Running', 'Evaluating'))


$remediation = Get-AzPolicyRemediation -Name $remediationName -Scope "/subscriptions/$subId"
$remediation | Format-List *
$remediation.DeploymentSummary

# In case of failure, query remediation deployments for error details. Each deployment corresponds to a sequential step in the policy.
$remDeploymentsUri = "/subscriptions/$subId/providers/Microsoft.PolicyInsights/remediations/$remediationName/listDeployments?api-version=2021-10-01"
$resp = Invoke-AzRestMethod -Path $remDeploymentsUri -Method POST
$remDeployments = ($resp.Content | ConvertFrom-Json).value
$remDeployments | Select-Object `
    @{n='ResourceId';e={$_.remediatedResourceId}},
    @{n='Status';e={$_.status}},
    @{n='Code';e={$_.error.code}},
    @{n='Error';e={$_.error.message}},
    @{n='DeploymentId';e={$_.deploymentId}} |
  Format-List

$remediation | Select-Object ProvisioningState -ExpandProperty DeploymentSummary
# Expect TotalDeployments = 0 → policy is "compliant", nothing deployed

# 5. Check activity log for the assignment operations
Get-AzLog -StartTime (Get-Date).AddHours(-2) -MaxRecord 1000 |
  Where-Object { $_.ResourceId -match 'Microsoft.Security/pricings/' } |
  Select-Object EventTimestamp,
                @{n='Status';e={$_.Status.Value}},
                @{n='Op';e={$_.OperationName.Value}},
                @{n='Plan';e={($_.ResourceId -split '/')[-1]}} |
  Sort-Object EventTimestamp | Format-Table




# 6. Cleanup (optional)

# $assignment = Get-AzPolicyAssignment -Name 'deploy-defender-seq' -Scope "/subscriptions/$subId"
# Remove-AzRoleAssignment -ObjectId $assignment.IdentityPrincipalId `
#   -RoleDefinitionId 'fb1c8493-542b-48eb-b624-b4c8fea62acd' `
#   -Scope "/subscriptions/$subId"
# Remove-AzPolicyAssignment -Name 'deploy-defender-seq' -Scope "/subscriptions/$subId"
# Remove-AzPolicyDefinition -Name 'deploy-defender-seq' -SubscriptionId $subId -Force