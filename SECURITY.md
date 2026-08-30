# Security policy

Fyke is designed to accept hostile input. Report a security problem privately to the repository owner.

Do not test for security problems on a Fyke server that you do not own.

The following security rules must always be true:

- Attacker input must not reach `os/exec`.
- Attacker input must not reach a shell or a template engine.
- Attacker input must not load Go code.
- Attacker input must not cause an outbound network request.
- Only the controller can write to SQLite.
- Fyke must encrypt sensitive evidence with age before it saves the evidence.
- Sensors must run without root privileges.
- Sensor file systems must stay read-only.
- Sensors must have no Linux capabilities.
- Sensors must not connect to the Docker socket.
- Public artifact responses must download as attachments.
- Artifact previews must contain escaped text or hexadecimal data.
- The operator must start each firewall change.

If a change affects one of these rules, add an attack test. Also describe the related threat in the code review.
