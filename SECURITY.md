# Security and safe use

SSH Sentinel is a small **defensive, offline** parser for SSH authentication logs. It does not scan remote systems, exploit vulnerabilities, block traffic, or upload data.

- Use it only on logs and systems you own or are explicitly authorized to review.
- Treat source IPs, usernames, and timestamps in logs as sensitive. Do not post unredacted logs in public issues or pull requests.
- A generated alert is a heuristic, not proof of compromise. Confirm findings using your normal incident-response process.
- This project is not a replacement for a SIEM, endpoint detection, backups, or a professional security review.

To report a security issue, use GitHub's private vulnerability reporting feature for the repository if it is enabled. If it is unavailable, contact the repository maintainer privately; avoid disclosing sensitive details publicly before a fix is available.
