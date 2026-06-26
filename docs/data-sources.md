# Data sources

A detection is only as good as the telemetry under it. This is what feeds the
rules in this repo and which events matter.

## Sysmon

The main source for endpoint visibility. See ../sysmon for the config approach and
the event IDs in use. Sysmon gives the detailed process creation, process access
and registry events that Windows does not log well on its own.

## Windows Security log

Some detections key off native Security events shipped alongside Sysmon:

| Event ID | Meaning | Used by |
|----------|---------|---------|
| 4625 | Failed logon | Brute force and password spray hunting |
| 4624 | Successful logon | Pairing with failures, logon type analysis |
| 4732 | Member added to a local group | New local admin detection |
| 4769 | Kerberos service ticket requested | Kerberoasting |
| 7045 | New service installed (System log) | PsExec lateral movement |
| 1102 | Security log cleared | Anti forensics detection |

## Shipping

Logs reach Elasticsearch through Winlogbeat or Elastic Agent, normalised to
Elastic Common Schema. ECS is what lets the same field names work across rules, so
it is worth getting the mapping right early.

## Coverage honesty

This is a lab, not a full enterprise estate. There is no proxy, EDR or cloud
telemetry feeding in, so the detections here lean on host and AD events. That is a
deliberate scope, and it covers the techniques I practise most: credential access,
lateral movement, persistence and basic anti forensics.
