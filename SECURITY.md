# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
"Report a vulnerability" (Security tab) on this repository rather than a public issue.

## Threat model in brief

`CHECK:` lines in a ledger are shell code. gatehouse never executes one without an approval
bound to the exact oracle, and `--status` and the Stop hook never execute anything. It is not a
sandbox: approved checks run with your permissions, environment, credentials and network access.
Approval does not hash scripts a command calls, and evidence is not tamper-proof against someone who
can edit the ledger. See the "Security model" section of the README.

In scope: bypassing approval, executing a check from `--status` or the hook, escaping the repository
root or approval-store checks, symlink/FIFO/hard-link handling, unbounded resource use in the parser or
regex matcher, and state-file corruption.
