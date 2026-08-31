# Fyke

Fyke is a safety-first internet decoy for collecting and investigating hostile activity without executing attacker input.

## Language

**Deployment**:
A single self-hosted Fyke installation on a dedicated VPS.
_Avoid_: Fleet, cluster

**Operator**:
The technically capable individual responsible for a Deployment and its collected evidence. Small security teams and researchers may also consume the evidence, but they are not the primary operating model.
_Avoid_: Tenant, customer, administrator account

**Sensor**:
A public-facing protocol decoy that observes hostile activity as one part of a Deployment.
_Avoid_: Agent, sandbox, container

**Source**:
The remote network endpoint from which a Sensor observes activity. A Source groups observations for Investigation but does not establish an attacker identity.
_Avoid_: Attacker, actor, threat

**Persona**:
The versioned declarative fictional system identity and bounded behavior presented consistently by Sensors.
_Avoid_: Virtual machine, container image

**Session**:
A bounded interaction between one source and one Sensor using one Persona.
_Avoid_: Login, shell

**Web Conversation**:
A bounded, cookie-linked sequence of HTTP interactions that may span multiple network connections.
_Avoid_: Browser session, Session

**Event**:
A normalized observation made during a Session.
_Avoid_: Log line, alert

**Evidence**:
Protected attacker-supplied or interaction-derived material associated with an Event and retained for investigation.
_Avoid_: Telemetry, logs

**Artifact**:
A captured file or bounded body preserved as Evidence for safe inspection or export. An Artifact is never executed by Fyke.
_Avoid_: Sample, attachment

**Observable**:
A concrete value that can connect Events during an Investigation, such as a Source address, username, SSH fingerprint, URL, command, or Artifact hash. Shared Observables indicate correlation, not proof of one attacker identity.
_Avoid_: Actor, identity, indicator of compromise

**Investigation**:
The reconstruction and analysis of hostile behavior from Events and Evidence without executing captured content. An Investigation may be performed by the Operator or continued in an external security tool using a complete export.
_Avoid_: Case, incident response

**Investigation Bundle**:
An audited encrypted handoff containing selected Artifacts and related metadata for analysis outside Fyke.
_Avoid_: Case archive, unpacked artifact directory

**Finding**:
A durable, stateful, explainable analytical conclusion derived from one or more Events to help the Operator prioritize an Investigation.
_Avoid_: Alert, insight

**Emulation Gap**:
An observed attacker interaction that the Emulated Environment cannot yet model convincingly. It is recorded for product improvement without being disclosed to the Source.
_Avoid_: Error, unsupported command

**Alert**:
A notification-worthy occurrence delivered to the Operator or an external security tool. An Alert may be triggered directly by an Event or by a Finding.
_Avoid_: Finding, notification attempt

**Emulated Environment**:
The non-executing fictional environment presented during a Session. It interprets attacker input against Session-scoped virtual state without passing that input to a real operating-system shell or network destination.
_Avoid_: Container, virtual machine, sandbox
