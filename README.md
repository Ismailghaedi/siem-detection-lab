# SIEM detection lab

Detection rules I have built and tuned in my own Elastic SIEM lab, sorted by MITRE
ATT&CK tactic. Every rule here came from the same loop: run an attack against my
home Active Directory environment from a Kali box, find what it looked like in the
logs, then write a detection for it. If I could not see the attack, I fixed the
logging and tried again.

This repo is the blue team half of how I learn. The red team half is the attacks I
run on HackTheBox and in this same lab. Building both sides means I understand what
my own attacks look like to a defender, which is the whole point.

## What is in here

```
sigma/        vendor neutral detection rules, sorted by ATT&CK tactic
elastic/      the same detections as EQL rules and Kibana KQL hunting filters
sysmon/       the telemetry config that makes the detections possible
docs/         lab architecture and data sources
mitre-attack-mapping.md   full ATT&CK coverage table
```

## The detections

Seven rules covering the attack chain I practise most, from landing on a host to
covering tracks:

- LSASS memory access, the behaviour behind credential dumping (T1003.001)
- Kerberoasting via RC4 service ticket requests (T1558.003)
- Encoded PowerShell execution (T1059.001)
- PsExec service install, a common lateral movement step (T1021.002)
- Active Directory recon via built in net commands (T1087.002)
- Registry Run key persistence (T1547.001)
- Windows event log clearing, an anti forensics move (T1070.001)

Full mapping with technique IDs is in mitre-attack-mapping.md.

## Why Sigma plus Elastic

The detection logic lives once in Sigma, which converts to any backend. The
Elastic versions in `elastic/` are what I actually run, including an EQL sequence
rule that only fires when domain recon is followed by lateral movement from the
same host inside ten minutes. That kind of multi step detection is far higher
confidence than either event on its own, and it is the sort of thing a flat search
cannot do.

## The honest bit

This is a lab, not a production estate, and the repo says so where it matters. The
coverage leans on host and AD telemetry because that is what the lab feeds in.
There is no EDR, proxy or cloud data yet, so there are deliberate gaps around
initial access and command and control. Adding a network feed and an EDR source is
the next step. I would rather be straight about scope than dress a lab up as
something it is not.

## How the data flows

```
Windows hosts  ->  Sysmon  ->  Winlogbeat / Elastic Agent  ->  Elasticsearch  ->  Kibana
```

Sysmon does the heavy lifting on visibility. See `sysmon/` for the config approach
and the event IDs each detection depends on.

Built and maintained by Ismail Masoumabadi.
