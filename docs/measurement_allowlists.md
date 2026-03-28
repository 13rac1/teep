# TDX Measurement Allowlists

Teep can enforce allowlists for TDX measurement registers to verify that a CVM
booted the expected software stack. This document covers how allowlists work,
how to configure them, and where to find canonical values for cross-checking.

## Background

Intel TDX measures the CVM boot chain into several registers:

| Register | Measures | Varies With |
|----------|----------|-------------|
| MRSEAM   | Intel TDX module identity | TDX module version, platform generation |
| MRTD     | Virtual firmware (OVMF) image | dstack OS image version |
| RTMR0    | Hardware and boot policy config | vCPU count, memory, GPU count |
| RTMR1    | Linux kernel binary | dstack image build |
| RTMR2    | Kernel cmdline, initrd, rootfs | rootfs config per deployment |
| RTMR3    | Runtime events (compose hash, etc.) | Already verified via event log replay |

Without measurement allowlists, teep verifies the TDX quote structure and
application-layer bindings (compose file, nonce, TLS key) but cannot confirm
that the lower stack (firmware, kernel, rootfs) matches expected values. A
malicious lower stack could preserve application-layer metadata while running
different code.

Measurement allowlists close this gap by requiring that each register contains
one of a known set of values.

## Quickstart

### 1. Bootstrap allowlists from observed values

Run verification against each provider and model, saving observed measurements
to your config file:

```sh
export TEEP_CONFIG=~/.config/teep/config.toml

# First model adds initial values
teep verify venice --model e2ee-qwen3-32b --update-config

# Additional models append and deduplicate
teep verify venice --model e2ee-deepseek-r1-0528 --update-config
teep verify neardirect --model qwen2.5-72b-instruct --update-config
```

Each invocation:
- Fetches attestation and runs all verification factors
- Extracts MRSEAM, MRTD, and RTMR0-2 from the TDX quote and event log
- Appends new values to `[providers.X.policy]` in the config, deduplicating
- Sets `warn_measurements = false` to enable enforcement
- Creates a `.bak` backup of the original config

To write to a different file instead of `$TEEP_CONFIG`:

```sh
teep verify venice --model e2ee-qwen3-32b --config-out ./teep.toml
```

### 2. Cross-check values

Before deploying, verify that the observed values match canonical sources (see
[Canonical Value Sources](#canonical-value-sources) below). Observed values are
trustworthy only when they can be independently reproduced or verified.

### 3. Deploy

Once satisfied, ensure your proxy uses the config:

```sh
export TEEP_CONFIG=~/.config/teep/config.toml
teep serve venice
```

The proxy merges Go-coded defaults, global TOML policy, and per-provider TOML
policy (most specific wins) to produce the final allowlist for each provider.

## Configuration Reference

### Global policy

Applies to all providers that do not have a per-provider policy section:

```toml
[policy]
warn_measurements = false
mrseam_allow = [
  "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6",
  "7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d",
]
mrtd_allow = [
  "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
]
```

### Per-provider policy

Overrides global policy for a specific provider:

```toml
[providers.venice.policy]
warn_measurements = false
mrseam_allow = [
  "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6",
]
mrtd_allow = [
  "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
]
rtmr0_allow = [
  "0cb94dba1a9773d741efad49370e1e909557409a904a24a4620b6305651360952cb8111f851b03fc2a35a6c3b7bb05f6",
]
rtmr1_allow = [
  "c0445b704e4c4813a1a855d6aa2504bfe2c8f4f06d2c4df70cd655c64c7b92e13cfbafe91cf45d7e6e87db5b0bfb3d61",
]
rtmr2_allow = [
  "56462c01c59a66c998fa23e18f3d78fb56e24eb0293a64c65d15a080dd24d3b9c6a1e98c01dccd70b94e98f53c2f9a35",
]
```

### Gateway policy (nearcloud only)

For providers with a separate gateway CVM:

```toml
[providers.nearcloud.policy]
warn_measurements = false
gateway_mrseam_allow = ["..."]
gateway_mrtd_allow = ["..."]
gateway_rtmr0_allow = ["..."]
gateway_rtmr1_allow = ["..."]
gateway_rtmr2_allow = ["..."]
```

### Merge order

Each allowlist field is resolved independently using:

1. **Per-provider TOML** — if the field has values, use them
2. **Global TOML** — else if the global policy has values, use those
3. **Go-coded defaults** — else use the built-in defaults

`warn_measurements` follows the same precedence.

## Warn-Only Mode

Go-coded defaults ship with `warn_measurements = true`. In this mode,
measurement mismatches produce a PASS result annotated with `WARN:` instead of
blocking the request. This allows operators to:

1. Deploy teep and observe which measurement values appear in reports
2. Use `--update-config` to capture those values into the config
3. Cross-check against canonical sources
4. Set `warn_measurements = false` to enable enforcement

The `--update-config` flag sets `warn_measurements = false` automatically,
transitioning from observation to enforcement.

## Canonical Value Sources

### MRSEAM — Intel TDX Module

MRSEAM identifies the Intel TDX module version running on the host platform.
Values are deterministic per TDX module release and do not depend on the guest
image or provider.

**Primary source:** Intel publishes MRSEAM hashes in TDX module release notes:
- Repository: `github.com/intel/confidential-computing.tdx.tdx-module`
- Each release tag contains the MRSEAM hash for that version

**Secondary source:** Tinfoil maintains a curated list of accepted MRSEAM values:
- Repository: `github.com/tinfoilsh/tinfoil-python`

**Known values (as of this writing):**

| MRSEAM (truncated) | TDX Module | Platform |
|---------------------|------------|----------|
| `49b66faa451d19eb...` | 1.5.08 | Sapphire/Emerald Rapids |
| `7bf063280e94fb05...` | 1.5.16 | Sapphire/Emerald Rapids |
| `476a2997c62bccc7...` | 2.0.08 | Granite Rapids |
| `685f891ea5c20e8f...` | 2.0.02 | Granite Rapids |

A reasonable policy is to allow the set of non-deprecated module versions for
your target platform family. This does not require provider cooperation.

### MRTD — Virtual Firmware Image

MRTD measures the TD virtual firmware image (OVMF). It is deterministic for a
given dstack OS image version and does not vary with CPU count, memory, GPU
count, or provider.

**Compute from source:**

```sh
# Clone the dstack repository
git clone https://github.com/Dstack-TEE/dstack
cd dstack

# Compute MRTD for a specific dstack release
dstack-mr measure
```

**Reproducible builds:**
- `github.com/Dstack-TEE/meta-dstack` — upstream reproducible build system
- `github.com/nearai/private-ml-sdk` — Near's dstack image builds

**Reference documentation:**
- Atlas `BOOTCHAIN-VERIFICATION.md` documents how MRTD is derived from the
  OVMF binary in the dstack image

**Known values:**

| MRTD (truncated) | dstack Version |
|-------------------|---------------|
| `b24d3b24e9e3c160...` | dstack-nvidia-0.5.4.1 |
| `f06dfda6dce1cf90...` | dstack-nvidia-0.5.5 |

### RTMR0 — Hardware Configuration

RTMR0 measures the virtual hardware configuration: vCPU count, memory size,
GPU count, PCI hole size, NVSwitch count, hotplug capability, and QEMU version.

**This register varies per deployment class.** A provider running models on
different hardware configurations will produce different RTMR0 values.

**Compute with known hardware params:**

```sh
dstack-mr measure --cpu N --memory SIZE --num-gpus G
```

Requires knowing the exact hardware configuration, which providers should
publish per deployment class.

**If hardware params are unknown:** Pin observed values using
`teep verify --update-config`. The pinned values will detect unexpected
changes but cannot be independently verified without hardware specs.

### RTMR1 — Kernel and Boot Loader

RTMR1 measures the Linux kernel binary loaded during boot. It is deterministic
for a given dstack image build.

**Compute from source:**

```sh
dstack-mr measure  # from github.com/Dstack-TEE/dstack
```

Multiple values may exist across a provider's fleet if different dstack image
versions are deployed simultaneously (e.g., during rolling updates).

### RTMR2 — Root Filesystem and Command Line

RTMR2 measures the kernel command line, initrd, and root filesystem state.
Like RTMR0, it varies per deployment class.

**Compute from source:**

```sh
dstack-mr measure  # from github.com/Dstack-TEE/dstack
```

**If deployment config is unknown:** Pin observed values using
`teep verify --update-config`.

### RTMR3 — Runtime Events

RTMR3 is computed by the dstack runtime from the compose hash, instance ID,
key provider identity, and other runtime events. Teep already verifies RTMR3
by replaying the event log (`event_log_integrity` factor). No manual pinning
is needed.

## Security Considerations

### Observed values are not proofs

Bootstrapping allowlists from observed values (`--update-config`) detects
measurement drift but does not constitute proof that the observed values are
correct. An attacker who controls the environment during initial observation
could cause teep to pin malicious values.

For maximum assurance:
1. Observe values from multiple independent vantage points
2. Cross-check MRSEAM against Intel's published release notes
3. Reproduce MRTD and RTMR1 from source using `dstack-mr measure`
4. Require providers to publish authenticated measurement manifests

### Rolling updates

When a provider updates their dstack image, firmware, or kernel version, the
corresponding measurement values change. During a rolling update, both old and
new values may appear in attestation responses.

Recommended approach:
1. Before the update, add the new expected values to your allowlists
2. After the rollout completes, remove the old values
3. If unexpected values appear, the allowlist enforcement will block requests
   (with `warn_measurements = false`) or emit warnings

### Fail-closed enforcement

When `warn_measurements = false` and a measurement value is not in the
allowlist, the corresponding verification factor fails and the proxy blocks
the request. This is the intended behavior for production deployments.

If all values in the fleet are unknown, start with `warn_measurements = true`,
observe, pin, cross-check, then switch to enforcement.

## Related Documentation

- `docs/attestation_gaps/dstack_integrity.md` — detailed analysis of the dstack
  measurement trust chain and gaps
- `teep help measurements` — CLI quick reference
- `teep help verify` — documentation for `--update-config` and `--config-out`
- `teep.toml.example` — example configuration file
