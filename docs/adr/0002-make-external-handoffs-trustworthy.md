---
status: accepted
---

# Make external evidence handoffs trustworthy

Fyke's public-beta integrations will have explicit completeness and delivery guarantees. An export will contain every matching Event present when the export begins, without a hidden count limit; sensitive Evidence requires a separate explicit, audited action and encrypted output. Webhook Alerts will use signed, durable, at-least-once delivery with stable identifiers, visible status, manual retry, and restart-safe queues. Sensors will replay unacknowledged Events after controller or network recovery, and Fyke will expose degraded or capacity-exhausted states. Fyke accepts the storage and duplicate-delivery costs because silent omissions would make Investigations unreliable.
