# Security Policy

## Reporting Security Vulnerabilities

We take the security of the Tikka platform seriously. If you discover a security vulnerability, we appreciate your help in disclosing it to us responsibly.

### Preferred Reporting Method

**GitHub Private Vulnerability Reporting** (Recommended)

- Use GitHub's private vulnerability reporting feature for this repository
- Navigate to the "Security" tab and click "Report a vulnerability"
- This ensures secure, private communication and proper tracking

### Alternative Reporting Methods

If GitHub private reporting is unavailable:

- **Email**: Send details to `security@crackedstudio.com`
- **Subject Line**: `[SECURITY] Tikka Vulnerability Report`

## Response Timeline

- **Initial Response**: Within 48 hours of report submission
- **Acknowledgment**: Within 72 hours with initial assessment
- **Status Updates**: Weekly updates on investigation progress
- **Resolution Target**: Critical vulnerabilities within 30 days, others within 90 days

## Scope

This security policy covers vulnerabilities in:

### In Scope

- **Client Application** (`./client/`) - React frontend, user authentication, wallet integration
- **SDK** (`./sdk/`) - Transaction building, contract interaction, cryptographic operations
- **Backend API** (`./backend/`) - Authentication (SIWS), metadata handling, user management
- **Indexer** (`./indexer/`) - Blockchain event processing, data validation
- **Oracle** (`./oracle/`) - Randomness generation, VRF operations
- **Infrastructure** - Docker configurations, CI/CD workflows, deployment scripts

### Out of Scope

- Soroban smart contracts (maintained in separate repository)
- Third-party dependencies (report directly to maintainers)
- Issues in personal development environments
- Social engineering attacks
- Physical security

## Vulnerability Types of Interest

We're particularly interested in vulnerabilities that could:

- Compromise user funds or raffle integrity
- Allow unauthorized access to user accounts or data
- Enable manipulation of raffle outcomes or randomness
- Bypass authentication or authorization controls
- Lead to data breaches or privacy violations
- Cause denial of service to critical platform functions

## Safe Harbor

We consider security research conducted under this policy to be:

- Authorized concerning the Computer Fraud and Abuse Act
- Authorized concerning applicable anti-hacking laws
- Exempt from DMCA takedown notices

### Safe Harbor Guidelines

When researching vulnerabilities, please:

- Only test against your own accounts and data
- Avoid accessing, modifying, or deleting data belonging to others
- Do not perform attacks that could harm platform availability
- Respect user privacy and do not access personal information
- Do not exploit vulnerabilities beyond demonstrating impact

## Disclosure Process

1. **Submit Report**: Use GitHub private vulnerability reporting or email
2. **Initial Review**: We assess and acknowledge receipt within 72 hours
3. **Investigation**: We investigate and may request additional information
4. **Validation**: We validate the vulnerability and determine severity
5. **Fix Development**: We develop and test fixes
6. **Coordinated Disclosure**: We coordinate public disclosure timing with you
7. **Recognition**: We provide public acknowledgment (if desired)

## Recognition

We believe in giving credit where it's due. With your permission, we will:

- Acknowledge your contribution in our security advisories
- List you in our Hall of Fame (if you consent)
- Provide a reference letter for responsible disclosure (upon request)

## Bug Bounty

While we don't currently offer a formal bug bounty program, we may provide:

- Public recognition and thanks
- Swag or tokens of appreciation for significant findings
- Priority consideration for future bounty programs

## Security Best Practices

For users of the Tikka platform:

- Always verify contract addresses before interacting
- Use hardware wallets for high-value transactions
- Keep your browser and wallet software updated
- Be cautious of phishing attempts
- Report suspicious activity immediately

## Repository supply-chain safeguards

In 2026 this repository was affected by a supply-chain campaign that spread
through merged pull requests across many GitHub projects. The payload was
removed; this section records how it worked and what now blocks it, so the
safeguards are not mistaken for red tape and removed.

### How the attack worked

1. An obfuscated Node script was committed as `public/fonts/fa-solid-600.eot`.
   It read as a font in review, but Font Awesome ships weights 400/900/300 and
   never 600, and the file's bytes were ASCII JavaScript rather than EOT data.
2. A hidden task in `.vscode/tasks.json`, labelled `eslint-check`, ran
   `node ./public/fonts/fa-solid-600.eot` with `"runOn": "folderOpen"` and
   `"reveal": "never"`, so nothing appeared in the terminal.
3. `"task.allowAutomaticTasks": true` in `.vscode/settings.json` suppressed the
   confirmation prompt, so simply opening the folder in VS Code executed the
   payload — no build, no install, no command run by the developer.

The payload was a loader: it polled a block explorer API for transactions from a
hardcoded attacker address, decompressed the response, and ran the retrieved
second stage with full `require` access. Because the second stage arrived at
runtime, what it did is not recoverable from the repository, and any machine
that opened the repository in VS Code should be treated as having run untrusted
code of unknown capability.

### What blocks it now

`scripts/check-supply-chain.js` fails the build on the shape of this attack
rather than on the specific filenames, so a renamed variant is still caught:

| Rule                   | What it rejects                                                                                     |
| ---------------------- | --------------------------------------------------------------------------------------------------- |
| `DISGUISED_EXECUTABLE` | Script text inside a media/binary-extension file                                                    |
| `EDITOR_AUTO_RUN`      | `runOn: folderOpen`, `task.allowAutomaticTasks` other than `"off"`, devcontainer lifecycle commands |
| `INSTALL_LIFECYCLE`    | `preinstall`/`install`/`postinstall`/`prepare` hooks outside the allowlist                          |
| `INTERPRETER_ON_ASSET` | Any command feeding a media file to `node`, `sh`, `python`, etc.                                    |

It runs in three places:

- **CI** — the `Supply-chain Guard` workflow, on every pull request and every
  push to `master`. It has no `paths:` filter (the attack can land anywhere) and
  installs no dependencies, so a malicious install hook cannot run before the
  check meant to catch it. Keep the script dependency-free for that reason.
- **Locally** — the `.husky/pre-commit` hook, and `pnpm check:supply-chain` on demand.
- **Review** — `.github/CODEOWNERS` routes `.vscode/`, `.devcontainer/`,
  every `package.json`, lockfiles, `.husky/`, workflows and binary assets to a
  maintainer. This is only mandatory when branch protection on `master` has
  "Require a pull request before merging" and "Require review from Code Owners"
  enabled; without those, CODEOWNERS is advisory and the CI guard is the real
  enforcement.

A finding is reported as a **notice** rather than a failure when it is not a
security problem — a PNG named `.ico`, for example. Keeping those out of the
failure path is deliberate: a check that cries wolf gets ignored.

### If you are reviewing a change to these paths

- Never run a file whose extension says data but whose contents are text.
- Treat any new `runOn: folderOpen` task or install-time hook as hostile until
  the author explains why it is needed.
- `git log --follow <path>` on a binary asset: assets that arrive in unrelated
  feature PRs deserve scrutiny.

## Contact Information

- **Security Team**: `security@crackedstudio.com`
- **General Contact**: See repository README for other contact methods
- **Response Languages**: English (primary), with translation support available

---

**Last Updated**: July 27, 2024  
**Policy Version**: 1.0

For questions about this security policy, please contact `security@crackedstudio.com`.
