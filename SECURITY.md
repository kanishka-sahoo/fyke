# Security policy

Fyke handles hostile input by design. Please report a vulnerability privately to the repository owner rather than testing it against an installation you do not own.

Security-sensitive invariants:

- No attacker-controlled input may reach `os/exec`, a shell, template execution, dynamic Go loading, or an outbound fetch.
- Only the controller may open SQLite for writes.
- Sensitive evidence must be age encrypted before durable controller storage.
- Sensors must remain unprivileged, read-only, capability-free, and disconnected from the Docker socket.
- Public artifact responses must remain attachment-only; previews must remain escaped text or hex.
- Firewall application must remain an explicit operator action.

Changes affecting these invariants should include an adversarial test and a clear threat-model note in the review.
