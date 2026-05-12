# Retry-FailedDefenderRemediation.ps1
# Retries only the resources that failed in the most recent remediation
# task for the 'deploy-defender-seq' policy assignment.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [string]$AssignmentName   = 'deploy-defender-seq',
    [string]$RemediationName,                       # optional; defaults to latest
    [int]   $PollIntervalSec  = 10
)

$ErrorActionPreference = 'Stop'
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
$scope = "/subscriptions/$SubscriptionId"

# 1. Resolve the policy assignment ID
$assignment = Get-AzPolicyAssignment -Name $AssignmentName -Scope $scope
$assignmentId = $assignment.Id
if (-not $assignmentId) { $assignmentId = $assignment.ResourceId }
if (-not $assignmentId) { $assignmentId = $assignment.PolicyAssignmentId }
if (-not $assignmentId) { throw "Could not resolve policy assignment '$AssignmentName' at $scope." }
Write-Host "Assignment: $assignmentId"

# 2. Pick the target remediation task (latest if not specified)
if (-not $RemediationName) {
    $latest = Get-AzPolicyRemediation -Scope $scope |
        Where-Object { $_.PolicyAssignmentId -eq $assignmentId } |
        Sort-Object -Property CreatedOn -Descending |
        Select-Object -First 1
    if (-not $latest) { throw "No prior remediation tasks found for assignment '$AssignmentName'." }
    $RemediationName = $latest.Name
}
Write-Host "Inspecting remediation: $RemediationName"

# 3. List per-resource deployments and pick the failed ones
$listUri = "$scope/providers/Microsoft.PolicyInsights/remediations/$RemediationName/listDeployments?api-version=2021-10-01"
$resp = Invoke-AzRestMethod -Path $listUri -Method POST
if ($resp.StatusCode -ge 400) { throw "listDeployments failed: $($resp.StatusCode) $($resp.Content)" }

$remDeployments = ($resp.Content | ConvertFrom-Json).value
if (-not $remDeployments) {
    Write-Host "No deployments recorded on '$RemediationName'."
    return
}

$remDeployments |
    Select-Object @{n='Resource';e={$_.remediatedResourceId}},
                  @{n='Status';e={$_.status}},
                  @{n='Code';e={$_.error.code}},
                  @{n='Error';e={$_.error.message}} |
    Format-List

$failed = $remDeployments |
    Where-Object { $_.status -ne 'Succeeded' } |
    Select-Object -ExpandProperty remediatedResourceId -Unique

if (-not $failed) {
    Write-Host "Nothing to retry - all deployments succeeded."
    return
}
Write-Host ("Retrying {0} failed resource(s):" -f $failed.Count)
$failed | ForEach-Object { Write-Host "  $_" }

# 4. Start a scoped retry remediation
$retryName = "retry-defender-seq-$(Get-Date -Format 'yyyyMMddHHmmss')"
Start-AzPolicyRemediation -Name $retryName `
    -Scope $scope `
    -PolicyAssignmentId $assignmentId `
    -ResourceDiscoveryMode ExistingNonCompliant `
    -ResourceId $failed | Out-Null
Write-Host "Started retry remediation: $retryName"

# 5. Poll until it leaves transient states
do {
    Start-Sleep -Seconds $PollIntervalSec
    $retry = Get-AzPolicyRemediation -Name $retryName -Scope $scope
    Write-Host "[$(Get-Date -Format HH:mm:ss)] $retryName : $($retry.ProvisioningState)"
} while ($retry.ProvisioningState -in @('NotStarted','Running','Evaluating','Accepted'))

# 6. Report final state
$retry | Format-List Name, ProvisioningState, CreatedOn, LastUpdatedOn
$retry.DeploymentSummary

$retryUri = "$scope/providers/Microsoft.PolicyInsights/remediations/$retryName/listDeployments?api-version=2021-10-01"
$retryResp = Invoke-AzRestMethod -Path $retryUri -Method POST
($retryResp.Content | ConvertFrom-Json).value |
    Select-Object @{n='Resource';e={$_.remediatedResourceId}},
                  @{n='Status';e={$_.status}},
                  @{n='Code';e={$_.error.code}},
                  @{n='Error';e={$_.error.message}} |
    Format-List
