# Code Agent Instructions for teep

Teep is a secure LLM inference API proxy (Go, stdlib `testing`, no frameworks):

- Teep verifies that API endpoints are running expected docker images in a CVM.
- Teep ensures requests and responses are encrypted at all times.
- Teep ensures this encryption is fully authenticated by TEE attestation.

Teep is designed to BLOCK REQUEST ACTIVITY when enforced validation factors fail.

## Data Flow

Proxy receives OpenAI-compatible chat request → resolves model to provider →
fetches and validates TEE attestation per policy → forwards (or blocks) the request.
Key packages: `proxy` (HTTP layer), `provider` (model routing), `attestation` (TEE verification), `config` (policy).

## Core Commands

- Run local tests: `make check` (quick: fmt + vet + lint + unit tests).
- Run full integration tests: `make integration` (slow; optional API keys or config).
- Generate provider verification reports: `make reports` (requires API keys or config).

## Git Workflow

This repository is managed by git and hosted on github.

- Ensure new code has unit test coverage before committing.
- Ensure new provider verifications have integration test coverage before committing.
- Run `make check` before committing.
- Stage only specific files you modified. Do not use `git add .` or `git add -A`.
- When fixing issues from a code audit, use one commit per issue.
- Describe both issues and fixes in commit messages.
- Do not mention audit identifiers.

## TOP PRIORITY: Data Privacy

Teep is *critical infrastructure security software* for handling *highly confidential data*.

It is more important to protect confidential traffic than it is to provide service.

This means failing closed is a FEATURE, not a BUG.

## Repository Rules

To ensure data privacy and integrity, adhere to the following rules:

- ALWAYS add regression test coverage for audit findings.
- ALWAYS authenticate encryption keys via attestation binding.
- ALWAYS use authenticated encryption.
- When uncertain, prefer DEFENSE IN DEPTH validation.
- Validation issues of any kind must FAIL LOUDLY AND FAIL CLOSED.
- If you can't make progress due to a failing validation, STOP and ask for advice.
- All cryptographic comparisons MUST be constant-time (`subtle.ConstantTimeCompare`). Never use `==` or `bytes.Equal` on secrets or fingerprints.
- NEVER log or print API keys, inference request data, or inference response data.
- NEVER weaken or bypass validation behavior.
- NO WORKAROUNDS.
- NO ERROR FALLBACKS.
- NO BACKWARDS COMPATIBILITY.
