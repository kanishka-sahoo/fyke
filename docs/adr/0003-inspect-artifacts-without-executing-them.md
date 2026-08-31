---
status: accepted
---

# Inspect Artifacts without executing them

The controller may hash Artifacts, create bounded safe previews, and perform conservative type detection. Archive handlers, scanners, and other complex parsers must run in an optional hardened offline worker with no public or outbound network, Fyke identities, database access, or shared writable state; its only network is an internal point-to-point job channel from the controller. The worker receives bounded jobs and returns normalized results. The dashboard may create audited encrypted Investigation Bundles, and Findings survive ordinary Evidence expiry without silently extending retention. This permits deep Investigation while keeping hostile content outside Fyke's trusted processes.
