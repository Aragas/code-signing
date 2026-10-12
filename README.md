# Code Signing

This repository provides an automated, secure code-signing service for Windows binaries and NuGet packages using Aragas' **Certum Code Signing in the Cloud** (SimplySign) certificate.

Because the certificate is issued directly to Aragas, all sensitive signing credentials and secrets are isolated exclusively within this repository under his personal GitHub account. Client repositories request code signing via the reusable workflow [`BUTR/workflows/sign-certum.yml`](https://github.com/BUTR/workflows). This repository acts as an independent authority that independently inspects, validates, and approves or denies each signing request before any secret is accessed.

---

## How a Request Is Handled

The verification process follows a strict zero-trust model: a client request provides only metadata identifying a workflow run and an artifact. All authorization rules, allowed files, and commit histories are resolved and verified independently using GitHub's API and the local [`config.json`](config.json).

```
[Client Repository]                [This Repository]
        │                                  │
 1. Upload unsigned artifact               │
        │                                  │
 2. Call sign-certum.yml ─────────────────>│ Dispatches sign.yml
                                           │
                                           ├─ 3. 'verify' job (No secrets)
                                           │     - Validate repository in config.json
                                           │     - Check run is active on protected branch/tag
                                           │     - Verify approver authorization
                                           │     - Confirm artifact ownership & integrity
                                           │
                                           ├─ 4. 'sign' job (Code Signing environment)
                                           │     - Download verified artifact by ID
                                           │     - Extract binaries & NuGet package contents
                                           │     - Sign files using Certum SimplySign
                                           │     - Verify signatures with SignTool
                                           │     - Repackage NuGet archives
                                           │     - Upload signed artifact
                                           │
 5. Download signed artifact <─────────────┤
    and overwrite local artifact           │
```

### Workflow Steps

1. **Request Dispatch**:
   A client workflow uploads its unsigned build output as a GitHub Actions artifact and calls `sign-certum.yml`. This triggers [`sign.yml`](.github/workflows/sign.yml) in this repository and waits for completion.

2. **Verification (`verify` job)**:
   The `verify` job runs in an unprivileged environment with **no access** to signing secrets. Using [`Test-SigningRequest.ps1`](scripts/Test-SigningRequest.ps1), it verifies against the GitHub API that:
   * **The repository is registered**: The requesting repository is explicitly listed in [`config.json`](config.json).
   * **Workflow and run state**: The requesting workflow run is currently in progress (`in_progress`), executed an allowed workflow file path, and was triggered by an allowed event.
   * **Branch or tag protection**: The run executed on a listed protected branch, or on a listed tag pointing directly to a commit on an allowed branch.
   * **Approver authorization**: An authorized approver from `config.json` vetted the run:
     * Either the approver initiated the run directly (pushed the commit, merged the branch, pushed the tag, dispatched the workflow, published the release, or triggered a rerun). *Note: Automated `repository_dispatch` events do not qualify, as they run under token identity rather than explicit human intent.*
     * Or the run built the merge commit of a pull request approved on its latest commit by an authorized approver (with no subsequent unreviewed commits or requested changes).
   * **Artifact integrity**: The targeted artifact exists, belongs to the verified run, and has not expired.

3. **Signing (`sign` job)**:
   Only after verification succeeds does the `sign` job execute inside the protected `Code Signing` GitHub environment:
   * Downloads the verified artifact by its immutable artifact ID.
   * Locates and extracts matching binaries and files inside NuGet packages based on [`config.json`](config.json) using [`Expand-SigningFiles.ps1`](scripts/Expand-SigningFiles.ps1).
   * Authenticates with Certum SimplySign Desktop and signs the files using Microsoft `signtool.exe`.
   * Verifies the applied signatures using `signtool verify`.
   * Repackages signed binaries back into their respective `.nupkg` archives using [`Update-SignedPackages.ps1`](scripts/Update-SignedPackages.ps1).
   * Uploads the result as a new artifact named `signed`.

4. **Artifact Replacement**:
   `sign-certum.yml` downloads the `signed` artifact and replaces the client workflow's local artifact, ensuring that subsequent publishing jobs distribute the verified, signed binaries.

---

## Configuration (`config.json`)

All signing permissions and file patterns are centralized in [`config.json`](config.json):

```json
{
  "approvers": ["Aragas"],
  "certificate": {
    "sha1": "<certificate SHA-1 thumbprint>",
    "totpAlgorithm": "SHA-256"
  },
  "repositories": {
    "BUTR/Bannerlord.ButterLib": {
      "events": ["push"],
      "branches": ["master"],
      "tags": ["v*"],
      "workflows": {
        ".github/workflows/publish.yml": {
          "bannerlord": ["Modules/Bannerlord.ButterLib/bin/*/Bannerlord.ButterLib*.dll"],
          "nuget": ["*.nupkg!lib/*/Bannerlord.ButterLib.dll"]
        }
      }
    }
  }
}
```

### Configuration Fields

* **`approvers`**: An array of GitHub usernames authorized to approve signing runs.
* **`certificate.sha1`**: The 40-character SHA-1 thumbprint of the Certum certificate (without colons or spaces). For example: `openssl x509 -in cert.pem -noout -fingerprint -sha1`.
* **`certificate.totpAlgorithm`**: The hash algorithm used by the SimplySign authenticator (found in the `algorithm` parameter of the `otpauth://` link, typically `SHA-256`).
* **`repositories`**: A mapping of repository names (`owner/repo`) allowed to request signing.
  * **`events`**: Allowed GitHub Actions event triggers (e.g., `["push", "workflow_dispatch"]`).
  * **`branches`**: Allowed branch names (must be protected branches in the target repository).
  * **`tags`**: *(Optional)* Glob patterns for allowed release tags (e.g., `["v*"]`). The tag must point to a commit that exists on one of the configured `branches`.
  * **`workflows`**: A mapping of workflow file paths to the artifacts and files to sign:
    * Each key corresponds to an artifact name produced by the client workflow (e.g., `bannerlord`, `nuget`).
    * Values are arrays of file path glob patterns relative to the artifact root (using `/` as path separators). Wildcards `*` and `?` match any characters, including directory separators.
    * **NuGet package syntax (`<package>!<entry>`)**: Signs binaries packaged inside NuGet archives. `<package>` matches `.nupkg` files in the artifact, and `<entry>` matches file entries within the package (e.g., `*.nupkg!lib/*/Bannerlord.ButterLib.dll`). Matching entries are extracted, signed, and updated back into the package while preserving other package contents and timestamps.
    * **Strict matching**: Every defined pattern must match at least one file during execution. If a pattern matches nothing (e.g., if a binary was renamed or omitted), the signing job fails immediately to prevent unverified releases.

---

## Setup and Architecture

### 1. This Repository (`code-signing`)

* Restricted strictly to Aragas with no external collaborator access.
* The `master` branch is protected.
* Configured with a dedicated GitHub Environment named **`Code Signing`**:
  * **Deployment branches**: Restricted to protected branches only.
  * **Secrets**:
    * `CERTUM_USERNAME`: The email address associated with the Certum SimplySign account.
    * `CERTUM_TOTP_SECRET`: The Base32 secret key from the SimplySign QR code / `otpauth://` URI.
  * **Required reviewers**: *(Optional)* Adding environment reviewers introduces a manual approval step before secrets are released.

### 2. GitHub Apps

Access is strictly partitioned between two custom GitHub Apps owned by Aragas:

* **Code Signing Requester**:
  * **Permissions**: `Actions: Read and write`.
  * **Installation**: Installed exclusively on this `code-signing` repository under Aragas' account.
  * **Usage**: The App's Client ID and private key are provided to client repositories (via organization or repository secrets). This allows client workflows to dispatch `sign.yml` and retrieve the signed artifact. The requester key confers no access to signing certificates or secrets.
* **Code Signing Verifier**:
  * **Permissions**: `Actions: Read`, `Contents: Read`, `Pull requests: Read`.
  * **Installation**: Installed on all participating repositories that request signing.
  * **Usage**: The App's Client ID (`VERIFIER_CLIENT_ID`) and private key (`VERIFIER_PRIVATE_KEY`) are stored in this repository. They allow `sign.yml` to authenticate back to GitHub to inspect workflow runs, branches, pull request reviews, and download artifacts.

### 3. Integrating a Client Repository

To enable signing for a new or existing repository:

1. **Register the repository**: Add its configuration entry and signing patterns to [`config.json`](config.json).
2. **Install the GitHub App**: Install the **Code Signing Verifier** app on the repository.
3. **Update the client workflow**: In the client repository's workflow, add the signing job after the build job:

   ```yaml
     sign:
       needs: ["build"]
       uses: BUTR/workflows/.github/workflows/sign-certum.yml@master
       with:
         artifact_name: bannerlord
       secrets:
         CODE_SIGNING_CLIENT_ID: ${{ secrets.CODE_SIGNING_CLIENT_ID }}
         CODE_SIGNING_PRIVATE_KEY: ${{ secrets.CODE_SIGNING_PRIVATE_KEY }}
   ```

   Publishing jobs should depend on `needs: ["sign"]` so they consume the signed artifacts.

#### Standard Artifact Conventions

* **`bannerlord`**: Module folder layout containing game assemblies and executables.
* **`nuget`**: NuGet package files (`.nupkg`) produced by `dotnet pack`. Internal assemblies are signed in place, ensuring symbol packages (`.snupkg`) remain aligned.
* **`npm`**: Distribution packages published to npm.

---

## Operational Notes

* **Concurrency & Queueing**:
  Because each TOTP code can only be used once and Certum does not support simultaneous sessions, the `sign` job is limited to a concurrency group of 1 (`concurrency: certum-code-signing`). If GitHub cancels a queued run when a new request arrives, `sign-certum.yml` automatically retries up to three times.
* **Security & Action Pinning**:
  The Certum login action ([jay0lee/certum-cloud-code-sign](https://github.com/jay0lee/certum-cloud-code-sign)) handles the sensitive TOTP secret and credentials. All external GitHub Actions in this repository are pinned to specific, immutable commit SHAs for supply chain security. Always review upstream changes prior to updating pinned commits.
