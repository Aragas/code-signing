<#
.SYNOPSIS
  Evaluates whether a code-signing request meets all security requirements and configuration rules.
  All validation details are retrieved directly from GitHub; input parameters from the caller are
  treated as untrusted metadata beyond identifying the target run and artifact.

.DESCRIPTION
  A signing request specifies a repository, a workflow run ID, and an artifact name.
  Signing is approved only when all of the following conditions are met:
  - The repository, workflow, artifact, and triggering event are explicitly permitted in config.json.
  - The workflow run executed on a configured protected branch, or on a configured tag that resolves
    to a commit on that branch.
  - An authorized approver listed in config.json either initiated the run directly (pushed, merged,
    dispatched, or reran) or approved the pull request merge commit on its latest commit.
  - The specified artifact belongs to the workflow run and has not expired.

  Outputs required by the signing job are written to $env:GITHUB_OUTPUT.
  Requires GH_TOKEN with read access to repository Actions, Contents, and Pull Requests.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Repository,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$ArtifactName,
    [Parameter(Mandatory)][string]$ConfigPath
)

$ErrorActionPreference = 'Stop'

# Executes a GitHub API request and returns the deserialized JSON response.
function Invoke-GitHubApi([string]$Path) {
    $json = gh api -H 'X-GitHub-Api-Version: 2022-11-28' $Path
    if ($LASTEXITCODE -ne 0) { throw "GitHub API request failed for path: $Path" }
    return $json | ConvertFrom-Json
}

# Executes a GitHub API request, returning $null if the resource does not exist (404).
function Find-GitHubApi([string]$Path) {
    $json = gh api -H 'X-GitHub-Api-Version: 2022-11-28' $Path 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return $json | ConvertFrom-Json
}

# Executes a paginated GitHub API request and returns all items across pages as an array of objects.
function Invoke-GitHubApiPaginated([string]$Path, [string]$Filter = '.[]') {
    $lines = gh api -H 'X-GitHub-Api-Version: 2022-11-28' --paginate --jq $Filter $Path
    if ($LASTEXITCODE -ne 0) { throw "GitHub API request failed for path: $Path" }
    return @($lines | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}

function Deny([string]$Reason) {
    Write-Error "Signing denied: $Reason"
    exit 1
}

# --- Validate request parameters and configuration ---
if ($Repository -notmatch '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$') { Deny "Invalid repository name format: '$Repository'. Expected 'owner/repo'." }
if ($RunId -notmatch '^[0-9]+$') { Deny "Invalid workflow run ID: '$RunId'. Expected a numeric ID." }
if ([string]::IsNullOrWhiteSpace($ArtifactName)) { Deny "Artifact name must not be empty." }

$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$approvers = @($config.approvers)
if ($approvers.Count -eq 0) { Deny "config.json does not define any authorized approvers." }

$entry = $config.repositories.PSObject.Properties | Where-Object { $_.Name -ieq $Repository } | Select-Object -First 1
if (-not $entry) { Deny "Repository '$Repository' is not listed in config.json." }
$repository = $entry.Name
$allowed = $entry.Value
if (@($allowed.events).Count -eq 0) { Deny "config.json specifies no allowed events for '$repository'." }
if (@($allowed.branches).Count -eq 0) { Deny "config.json specifies no allowed branches for '$repository'." }

# --- Validate workflow run properties ---
$run = Invoke-GitHubApi "repos/$repository/actions/runs/$RunId"
if ($run.repository.full_name -ine $repository) { Deny "Workflow run $RunId does not belong to '$repository' (belongs to '$($run.repository.full_name)')." }
if ($run.head_repository.full_name -ine $repository) { Deny "Workflow run $RunId built code from external repository/fork '$($run.head_repository.full_name)', not from '$repository'." }
if ($run.status -ne 'in_progress') { Deny "Workflow run $RunId is in '$($run.status)' state; only active ('in_progress') workflows can request signing." }
if ($run.event -notin @($allowed.events)) { Deny "Workflow run $RunId was triggered by event '$($run.event)', which is not permitted for '$repository' in config.json." }

$workflow = $allowed.workflows.PSObject.Properties | Where-Object { $_.Name -ceq $run.path } | Select-Object -First 1
if (-not $workflow) { Deny "Workflow run $RunId executed workflow '$($run.path)', which is not permitted for '$repository' in config.json." }
$artifactFiles = $workflow.Value.PSObject.Properties | Where-Object { $_.Name -ceq $ArtifactName } | Select-Object -First 1
if (-not $artifactFiles -or @($artifactFiles.Value).Count -eq 0) { Deny "config.json defines no files to sign for artifact '$ArtifactName' in workflow '$($run.path)' of '$repository'." }
$sha = $run.head_sha

# --- Validate branch and protection ---
# A branch run must target an allowed branch.
# A tag run must match an allowed tag pattern, point to the run commit, and that commit must exist on an allowed branch.
# In both cases, the target branch must be configured with branch protection.
$ref = $run.head_branch
$branch = $null
$tagPattern = @($allowed.tags) | Where-Object { $_ -and $ref -like $_ } | Select-Object -First 1
if ($tagPattern -and ($tag = Find-GitHubApi "repos/$repository/git/ref/tags/$ref")) {
    $tagSha = $tag.object.sha
    if ($tag.object.type -eq 'tag') { $tagSha = (Invoke-GitHubApi "repos/$repository/git/tags/$tagSha").object.sha }
    if ($tagSha -ne $sha) { Deny "Tag '$ref' in '$repository' points to commit $tagSha, but workflow run $RunId built commit $sha." }
    foreach ($candidate in @($allowed.branches)) {
        $comparison = Find-GitHubApi "repos/$repository/compare/$([Uri]::EscapeDataString($candidate))...$sha"
        if ($comparison -and $comparison.status -in @('identical', 'behind')) { $branch = $candidate; break }
    }
    if (-not $branch) { Deny "Tag '$ref' in '$repository' points to commit $sha, which does not exist on any allowed branch ($(@($allowed.branches) -join ', '))." }
    Write-Host "Verified run $RunId ($repository, workflow: $($run.path)) on tag '$ref' at commit $sha (anchored to branch '$branch')."
} else {
    if ($ref -notin @($allowed.branches)) { Deny "Workflow run $RunId ran on ref '$ref', which is not in the allowed branches list for '$repository'." }
    $branch = $ref
    Write-Host "Verified run $RunId ($repository, workflow: $($run.path)) on branch '$branch' at commit $sha."
}

$protected = Invoke-GitHubApi "repos/$repository/branches/$([Uri]::EscapeDataString($branch))"
if (-not $protected.protected) { Deny "Branch '$branch' in '$repository' is not configured as a protected branch." }

# --- Validate authorization and approval ---
# An authorized approver who directly initiated the run is treated as having approved it.
# Direct triggers include pushing commits, merging PRs, creating tags, dispatching workflows,
# publishing releases, or re-running a workflow (re-runs report the triggering actor as whoever initiated the rerun).
# Automated events like repository_dispatch run under token permissions and do not represent human approval.
$personEvents = @('push', 'workflow_dispatch', 'release')
$startedBy = $run.triggering_actor.login
$approvedBy = $null
if ($run.event -in $personEvents -and $approvers -contains $startedBy) {
    $approvedBy = $startedBy
    Write-Host "Run directly authorized by approver: $startedBy (event: $($run.event))."
}

# If the run was not directly started by an approver, it must be the merge commit of an approved pull request.
# The PR must have been approved on its latest commit by an authorized approver (excluding the PR author),
# ensuring that no subsequent unapproved changes were merged.
if (-not $approvedBy) {
    $pulls = @(Invoke-GitHubApi "repos/$repository/commits/$sha/pulls")
    $pull = $pulls | Where-Object { $_.merged_at -and $_.merge_commit_sha -eq $sha -and $_.base.ref -eq $branch } | Select-Object -First 1
    if (-not $pull) { Deny "Run $RunId was initiated by '$startedBy', and commit $sha is not the merge commit of a pull request into '$branch'." }
    Write-Host "Run associated with pull request #$($pull.number) by '$($pull.user.login)' (head commit: $($pull.head.sha))."

    $reviews = Invoke-GitHubApiPaginated "repos/$repository/pulls/$($pull.number)/reviews"
    $latest = $reviews |
        Where-Object { $_.state -in @('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED') -and $_.user } |
        Group-Object { $_.user.login } |
        ForEach-Object { $_.Group | Sort-Object { [DateTimeOffset]$_.submitted_at } | Select-Object -Last 1 }
    $approval = $latest | Where-Object {
        $_.state -eq 'APPROVED' -and
        $_.commit_id -eq $pull.head.sha -and
        $_.user.login -ne $pull.user.login -and
        ($approvers -contains $_.user.login)
    } | Select-Object -First 1
    if (-not $approval) { Deny "Run $RunId was initiated by '$startedBy', and pull request #$($pull.number) does not have an approval on its latest commit from an authorized approver ($($approvers -join ', '))." }
    $approvedBy = $approval.user.login
}
Write-Host "Verified approval by: $approvedBy"

# --- Validate artifact ---
$artifacts = Invoke-GitHubApiPaginated "repos/$repository/actions/runs/$RunId/artifacts" '.artifacts[]'
$artifact = @($artifacts | Where-Object { $_.name -ceq $ArtifactName -and -not $_.expired })
if ($artifact.Count -ne 1) { Deny "Found $($artifact.Count) unexpired artifacts named '$ArtifactName' for run $RunId; expected exactly 1." }
$artifact = $artifact[0]
if ($artifact.workflow_run.id -ne [long]$RunId) { Deny "Artifact $($artifact.id) does not belong to workflow run $RunId." }
Write-Host "Verified artifact $($artifact.id) ('$ArtifactName', $($artifact.size_in_bytes) bytes)."

# --- Validate certificate configuration ---
$certSha1 = ($config.certificate.sha1 -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
if ($certSha1.Length -ne 40) { Deny "config.json does not contain a valid 40-character SHA-1 certificate thumbprint." }

$files = ConvertTo-Json -InputObject @($artifactFiles.Value) -Compress
@(
    "repository=$repository"
    "repository_owner=$($repository.Split('/')[0])"
    "repository_name=$($repository.Split('/')[1])"
    "artifact_id=$($artifact.id)"
    "files=$files"
    "cert_sha1=$certSha1"
    "totp_algorithm=$($config.certificate.totpAlgorithm)"
) | Add-Content -Path $env:GITHUB_OUTPUT
Write-Host "Signing request successfully validated and approved."
