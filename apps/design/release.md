# Release Process

## Pre-release checks

1. Update the version in `apps/internal/version/version.go` and include any required retraction in the root `go.mod`.
2. Merge the release preparation PR and ensure CI passes on the intended release commit on `main`.
3. Run Azure SDK's tests against that same commit.

```
git clone github.com/Azure/azure-sdk-for-go --single-branch --depth=1
cd azure-sdk-for-go/sdk/azidentity
go mod edit -replace=github.com/AzureAD/microsoft-authentication-library-for-go="TODO: disk path to MSAL repo"
go mod tidy
go test -v ./...
```

## Publishing a release

1. Record the exact reviewed and tested commit SHA. Confirm that it contains the intended SDK version and any retraction directive.
2. Ensure the release protections below are enabled.
3. Create a new version tag at that commit. Do not rely on a moving branch tip when publishing.
4. On GitHub, select the tag under **Releases > Draft a new release**. Save a draft, complete the release notes and any assets, then publish.
5. Verify the published module with `go mod download -json <module>@<version>`, using `github.com/AzureAD/microsoft-authentication-library-for-go` as the module path. Run once with `GOPROXY=direct` and once with `GOPROXY=https://proxy.golang.org`, using a separate, empty `GOMODCACHE` for each. Keep `GOSUMDB=sum.golang.org` enabled and ensure `GOPRIVATE` and `GONOSUMDB` do not exempt this module. Both downloads must succeed and report identical `Sum` and `GoModSum` values.

A version is published as soon as its tag is available to Go tooling, even before a GitHub release is published. Never move or reuse a published version tag to fix code or metadata, including the SDK version string. Publish a new patch version instead.

## Protecting release tags

Have a repository administrator configure these protections:

- Under **Settings > Rules > Rulesets**, create an **active tag ruleset** targeting `v*`. Enable **Restrict updates** and **Restrict deletions**. Leave **Restrict creations** unchecked unless tag creation is separately controlled, and avoid routine bypass permissions.
- Under **Settings > General > Releases**, select **Enable release immutability** before publishing future releases. Finalize assets in a draft before publishing.

Tag rulesets can protect existing tags. Release immutability only applies to future releases; enabling it does not retroactively lock existing releases. See GitHub's [ruleset guide](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository) and [release immutability guide](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes).

## Retracting a version

When consumers should avoid a published version, add a top-level `retract` directive to the root `go.mod`, after the `go` directive and outside any `require` block. For example, to retract `v1.10.0` in the `v1.10.1` release:

```go
// v1.10.0 was re-tagged after publication; use v1.10.1.
retract v1.10.0
```

Include the directive and the updated SDK version in the new release commit. Merging the directive to `main` alone is insufficient for normal Go version discovery; publish it in a new highest release version.

Retraction discourages automatic version selection but does not remove the old version, update consumers already pinned to it, or repair checksum mismatches. After publication, confirm the explanation appears in the `Retracted` field from `go list -m -json -retracted <module>@<retracted-version>`. See the [Go retraction reference](https://go.dev/ref/mod#go-mod-file-retract).

## Recovering from an accidentally moved tag

1. Pause concurrent release/tag changes. Compare the current GitHub tag target with the Go proxy's recorded origin commit in the version's `.info` metadata, and inspect the corresponding checksum database record.
2. If the tag moved, coordinate an exceptional restoration to the original published commit. Use a conditional update, such as `git push --force-with-lease` with the exact expected remote tag object ID, rather than an unconditional force-push. Investigate if the remote value changed. Do not delete and recreate the release or attempt to move the tag by editing the release's **Target** field.
3. Verify the restored version with a fresh direct-VCS download against `sum.golang.org`, as described above. Do not disable checksum verification or ask consumers to replace checksums to accept changed content.
4. Prepare a new patch release with the intended changes and, if appropriate, a retraction of the affected version. Do not move the old tag to the commit containing the retraction.
5. Document the incident and replacement version in the release notes. Complete the restoration before adding protections that would block it, then protect the tags before publishing the replacement.
