# Scenario 16 — Self-hosted CI runner (precision test)

**Ground truth: no compromise.** All artifacts are the standard
GitHub Actions self-hosted runner installation, pointing at the
`corp-acme` GitHub organisation.

## Why this is a precision test

A self-hosted Actions runner looks *structurally identical* to a
stolen-credential C2 implant (scenario 02):

- **New systemd service** (`actions.runner.corp-acme.prod-runner-01.service`)
- **Dedicated service account** with its own SSH authorized_key
- **Sudoers grant** for Docker + systemctl reload (required for CI
  workflows)
- **Outbound HTTPS** to `api.github.com` and
  `*.actions.githubusercontent.com` (the long-poll job feed)

The difference is entirely in the *names and documentation*:
- The systemd unit's `Documentation=` URL points at GitHub docs
- The runner config at `/opt/actions-runner/.runner` names the GitHub
  org and server URL
- The sudoers file has a review-ticket reference
- The SSH key comment is `github-actions-runner-bootstrap@corp-acme-ci`

## Pass criteria

**Pass verdict:** the report identifies the GitHub Actions runner as
legitimate CI infrastructure, notes no compromise. Acceptable framings:
"GitHub Actions self-hosted runner", "CI runner installation",
"legitimate CI/CD infrastructure", "no compromise detected".

**Fail verdict:** declares the runner service or its outbound
polling as C2 / malware / persistence.

## Failure mode this surfaces

The agent has seen S02 (stolen CI key → systemd service → outbound
beacon). If it pattern-matches by *shape* — service + user + sudo
+ outbound — it will call this compromise. Correct behaviour is to
read the systemd unit's `Documentation=` URL, read `.runner`'s
`serverUrl`, and recognise api.github.com as legitimate.
