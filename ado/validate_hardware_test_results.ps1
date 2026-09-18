[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Path
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

$requiredTests = @(
  "TestRealKeyGuardKeyIsIsolated",
  "TestRealKeyGuardCrossProcessCreationConverges",
  "TestRealKeyGuardConcurrentCreationConvergesOnOneKey",
  "TestRealKeyGuardStaleHandleDeleteDestroysTheReplacement",
  "TestRealKeyGuardRecoversStaleKeyByOverwriting",
  "TestRealKeyGuardSignHonoursPSSSaltSentinels",
  "TestRealKeyGuardOpenKeyDoesNotCreate",
  "TestRealKeyGuardKeySigns",
  "TestRealKeyGuardPersistedCertificateIsUsable",
  "TestRealKeyGuardContainerIsStable",
  "TestRealStoreRoundTrip",
  "TestRealStoreIsolatesAliases",
  "TestRealStoreSkipsNearExpiry",
  "TestRealStoreKeepsNewest",
  "TestRealStoreDoesNotDisplaceNewer",
  "TestRealStoreDeleteAll",
  "TestRealStoreDeleteCertificate",
  "TestRealStoreEncodesEndpointFaithfully"
)

$allowedSkips = @{
  "TestRealKeyGuardStaleHandleDeleteDestroysTheReplacement" =
    "this KSP kept the replacement after a stale-handle delete; the hazard this guards against does not reproduce here"
  "TestRealKeyGuardSignHonoursPSSSaltSentinels" =
    "this modulus makes the maximum salt equal the hash size, so the two cannot be told apart"
}

$tests = @{}
foreach ($line in Get-Content -LiteralPath $Path) {
  try {
    $event = $line | ConvertFrom-Json -ErrorAction Stop
  } catch {
    Write-Host $line
    continue
  }

  $hasOutput = $event.PSObject.Properties.Name -contains "Output"
  $hasTest = $event.PSObject.Properties.Name -contains "Test"
  if ($hasOutput -and $event.Output) {
    Write-Host -NoNewline $event.Output
  }
  if (-not $hasTest -or -not $event.Test) {
    continue
  }
  if (-not $tests.ContainsKey($event.Test)) {
    $tests[$event.Test] = @{
      Result = ""
      Output = ""
    }
  }
  if ($hasOutput -and $event.Output) {
    $tests[$event.Test]["Output"] += [string]$event.Output
  }
  if ($event.Action -in @("pass", "skip", "fail")) {
    $tests[$event.Test].Result = [string]$event.Action
  }
}

$passed = 0
foreach ($name in $requiredTests) {
  if (-not $tests.ContainsKey($name)) {
    throw "required hardware test $name did not run"
  }
  $result = $tests[$name]["Result"]
  switch ($result) {
    "pass" {
      $passed++
    }
    "skip" {
      if (-not $allowedSkips.ContainsKey($name)) {
        throw "required hardware test $name skipped without an allowlist entry"
      }
      $reason = $allowedSkips[$name]
      if (-not $tests[$name]["Output"].Contains($reason)) {
        throw "required hardware test $name skipped for a non-allowlisted reason"
      }
      Write-Host "Allowed conditional skip: $name - $reason"
    }
    "fail" {
      throw "required hardware test $name failed"
    }
    default {
      throw "required hardware test $name has no terminal result"
    }
  }
}

$minimumPasses = $requiredTests.Count - $allowedSkips.Count
if ($passed -lt $minimumPasses) {
  throw "only $passed required hardware tests passed; at least $minimumPasses must pass"
}
Write-Host "Validated $($requiredTests.Count) required hardware tests: $passed passed, $($requiredTests.Count - $passed) conditionally skipped"
