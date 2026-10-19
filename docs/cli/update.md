# `pipelock update`

Update Pipelock to the latest verified release (alias: `pipelock upgrade`).

`pipelock update` checks GitHub Releases for a newer build, downloads the
archive for the current OS/architecture, verifies it, and atomically replaces
the running binary in place. The previous binary is saved next to the new one
as `<binary>.bak` so a bad update can be rolled back.

The command is **fail-closed**: any failure in the verification chain aborts
the update and leaves the installed binary untouched.

## Usage

```bash
pipelock update              # interactive update to the latest release
pipelock update --check      # report current vs latest; change nothing
pipelock update --yes        # update without the confirmation prompt
pipelock update --version v3.1.0   # install a specific release tag
pipelock update --rollback   # restore the previous binary from <binary>.bak
pipelock update --json       # machine-readable status
pipelock update --insecure-skip-signature   # deprecated no-op (native signature verification is always required)
```

## Flags

| Flag | Description |
|------|-------------|
| `--check` | Report the current and latest versions and whether an update is available. Makes no changes. Exits 0. |
| `--version <vX.Y.Z>` | Target a specific release tag instead of the latest. |
| `--yes`, `-y` | Skip the interactive confirmation prompt. |
| `--rollback` | Restore the previous binary from the `.bak` backup saved by a prior update. |
| `--json` | Emit machine-readable JSON status (consistent with `doctor` / `keys`). |
| `--insecure-skip-signature` | **Deprecated no-op**, kept for backward compatibility. Native Ed25519 verification of the signed release manifest is always required; this flag no longer relaxes any check. |

## Verification chain

Every step below must succeed; **any failure aborts the update with the
installed binary unchanged**:

1. **Resolve the release.** Fetch `releases/latest` (or `releases/tags/<tag>`
   with `--version`) from the GitHub API for `luckyPipewrench/pipelock`. The
   HTTP client honors `HTTPS_PROXY` / `HTTP_PROXY` from the environment, so the
   updater works inside a contained Pipelock deployment.
2. **Publisher authenticity (native, mandatory).** Download the signed release
   manifest (`release.json` + `release.json.sig`) and verify its Ed25519
   signature against the release keyring embedded in the running binary at build
   time (`RELEASE_KEYRING_HEX`). This check is **always required** and runs
   **before** any download is trusted; a missing, malformed, or wrong-key
   signature aborts the update. The manifest's tag must also match the resolved
   release.
3. **Integrity, anchored by the signed manifest.** Download `checksums.txt` and
   require it to agree with the digests in the verified manifest; download the
   release archive (`pipelock_<version>_<os>_<arch>.tar.gz`, or `.zip` on
   Windows), compute its SHA256, and require an **exact match** to the entry in
   `checksums.txt`. Any mismatch aborts the update.
4. **Optional cosign cross-check.** If a `cosign` binary is on `PATH`, also run
   `cosign verify-blob` against `checksums.txt.sig`/`checksums.txt.pem`, pinned
   to the GitHub Actions OIDC issuer
   (`https://token.actions.githubusercontent.com`) and the release workflow
   identity for the target tag. Two exact identities are accepted: the
   `luckyPipewrench/pipelock` release workflow and the same workflow under
   `pipelab-org/pipelock`, where the repository is moving. No pattern is
   accepted. If cosign is present and rejects the signature under both
   identities, the update **aborts**. If cosign
   is **absent**, this step is skipped — it is a secondary ecosystem check, not
   the publisher-authentication path, so its absence is **not** a bypass (native
   verification in step 2 already proved authenticity).
5. **Extract.** Extract only the `pipelock` binary from the archive into a temp
   file in the **same directory** as the target binary (so the final rename is
   atomic on one filesystem). Archive entries are validated: any entry with a
   `..` traversal segment or an absolute path is rejected (zip-slip /
   tar-traversal protection).
6. **Install.** Back up the current binary to `<binary>.bak` (overwriting any
   prior backup), then install the verified temp binary.
   On Linux and macOS, renaming over a running executable is allowed, and a
   failed rename leaves the original untouched.

   Windows cannot delete a running executable but can rename it. There the
   updater moves the running image into a recovery directory named
   `<binary>.pipelock-update`, then moves the verified binary into place. These
   are two renames, not one atomic step. If the second fails, the original is
   moved back; the error states whether the original is intact, restored, or
   needs manual recovery and where the saved image is. The next start of the
   new binary removes the recovery directory once it can prove it holds only
   the files the updater recorded; anything else is kept, with a warning. If
   the process or machine stops between the two renames, the binary is missing:
   move `previous.exe` from the recovery directory back, or copy `<binary>.bak`
   into place. Update, rollback, and cleanup share an exclusive lock; an update
   that encounters a busy lock stops before changing the binary or its backup.
   The `<binary>.pipelock-update.lock` file remains between runs and must not
   be deleted while a command is running.
   A retained recovery directory blocks the next update before it changes
   `<binary>.bak`. Rollback can reuse a valid retained directory when the backup
   matches the recorded original. It keeps `previous.exe` and moves the updated
   image to the fixed `replaced.exe` slot before restoring the backup. Both
   images may stay mapped by running processes; neither is overwritten. Repeated
   rollback uses the same state. Cleanup verifies both images against the
   original record; later startups retry after the processes exit. Malformed records,
   changed images, or unknown entries block rollback and remain for inspection.
   If rollback stops between its two renames, restore `replaced.exe` to the
   missing binary path to keep the updated version, or copy `<binary>.bak` to
   restore the original. After confirming the installed binary works, stop
   processes still running either saved image before removing the directory;
   Windows won't delete an image while a process maps it. `<binary>.bak` is
   never touched by cleanup.

### Authenticity model (native vs cosign)

Publisher authenticity is proven by the **native Ed25519 verification of the
signed release manifest** (step 2), which is mandatory and needs no external
tools — the trusted public keyring is embedded in the binary at build time. The
`cosign` cross-check (step 4) is an **optional** secondary ecosystem signal: if
`cosign` is present it must pass, and if it is absent it is simply skipped.
Cosign absence is **not** a downgrade and **not** a bypass, because native
verification has already authenticated the release before any binary is touched.

The `--insecure-skip-signature` flag is a **deprecated no-op** retained only for
backward compatibility; it does not relax native verification or any other
check.

> **Upgrading from a pre-3.0.0 binary:** releases before 3.0.0 used a
> cosign-only verification path and had no embedded release keyring, so a stock
> pre-3.0.0 binary running `pipelock update` follows that older path. The
> mandatory native-manifest verification described here applies once you are
> running 3.0.0 or later.

## Rollback

`pipelock update --rollback` restores `<binary>.bak` over the current binary
using the same replacement as an update (the Windows recovery directory
applies here too). If no backup exists, it reports a clear error.

## Privileged install paths

Before making any change, the updater checks that the target binary's
**directory** can accept the temp-write-and-rename it uses to apply the update.
It probes the directory because that is what the atomic replace actually
requires; a writable binary in a non-writable directory could not be replaced
anyway. If Pipelock is installed to a root-owned location (for example
`/usr/local/bin`), the update aborts early with a message to re-run with
appropriate privileges (for example via `sudo`). The update is never partially
applied.

## Unsupported platforms

If there is no published archive for the current OS/architecture, the command
reports a clear error and makes no changes. Supported targets follow the release
matrix (Linux and macOS on amd64/arm64; Windows archives are `.zip`).
