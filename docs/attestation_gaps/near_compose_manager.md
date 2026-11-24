# NEAR Compose-Manager Deployments: Images Built in the CVM

NEAR starts the inference proxy and the model server of each model machine
after boot, and records each start in a log that the machine's attestation
binds. Most recorded logs name a deployment whose image the machine built
itself, so no published digest names the software that ran there. teep
reports this and does not block the model.

## The Problem

The attacker is NEAR, or a party that controls what NEAR deploys to a model
machine. After boot, the machine starts the software that decrypts and
answers prompts from deployment files, and some of those files build that
software on the machine instead of naming a published image. A user who does
every check available today can confirm which deployment files a machine ran,
but not which software a build produced.

## Impact

- **Who:** NEAR, or a party that controls a NEAR deployment file or the
  source that a build in it reads.
- **What they do:** deploys a file that builds its server image on the model
  machine, or names an image by a tag that can move.
- **What they get:** software that no published digest names, running in
  the machine that decrypts the prompts.
- **What stops it today:** the bound log names the deployment file and its
  hash, and the file is public, so a reader can see that it builds an image.
  The log does not record the image that the build produced.

The log keeps entries for seven days unless they anchor a deployed record, so
a machine can report an old deployment of this kind long after it stopped.

---

## Technical Background

The compose that the model CVM's MRConfigID binds runs compose-manager. It
deploys files of `nearai/cvm-compose-files` at a commit, records each
`compose_up` and `compose_stage` with the file's `file_sha256`, and serves the
log with a second TDX quote whose REPORTDATA is
`sha256(canonical actions) ‖ client nonce`. See
[compose-manager attestation](../providers/near/near_attestation.md#compose-manager-attestation).

## Detailed Gap Analysis

Over 14 recorded logs (GLM-5.3, Qwen3.8 and DeepSeek-V4.1 instances captured
13 to 22 November 2026, with actions back to 5 September) and their 203
distinct deployments, 166 deployments and 5 logs pass the rule of
`compose_manager_actions`. It refuses 34 files that build an image in the CVM
and 3 that pin an image by tag, so 9 of the 14 logs fail. Of the two instances
of the 2026-11-21 DeepSeek-V4.1-Flash-1017 response in
`internal/attestation/testdata`, `fccd496a` passes and `7bb9af0a` still
reports a 5 September GLM deployment whose file uses `build`.

## Remediation

- **NEAR:** pin every service image of a deployment file by digest.
- **teep:** enforce `compose_manager_actions` for both NEAR providers when
  live fleet data shows that every instance passes it.

## References

- [Compose-manager attestation in teep](../providers/near/near_attestation.md#compose-manager-attestation)
- [The rule in teep](../../internal/attestation/compose_manager.go)
- [nearai/cvm-compose-files](https://github.com/nearai/cvm-compose-files)

## Teep Status

`compose_manager_actions` is evaluated and reported for `neardirect` and
`nearcloud`, and is in the default `allow_fail` list of both. A configured
`allow_fail` list without it enforces it. `compose_manager_quote` and
`compose_manager_tcb` are enforced.
