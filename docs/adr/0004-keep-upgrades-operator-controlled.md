---
status: accepted
---

# Keep upgrades Operator-controlled

Fyke will not update itself automatically. Its deployment workflow will instead perform preflight checks, create a recoverable backup, apply forward migrations, verify health, and give the Operator explicit rollback guidance. This preserves unattended operation between releases without allowing an internet-facing security appliance to change itself unexpectedly.
