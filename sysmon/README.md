# Sysmon

Sysmon is what gives the detections in this repo something to match on. Out of the
box Windows logging is thin, especially for process creation command lines and
process access events. Sysmon fills that gap.

## My approach

I run a config based on the well known SwiftOnSecurity baseline, then trim and
tune it for the events these detections actually need. I am not shipping a
thousand line XML here because the upstream baseline is better maintained than
anything I would freeze in a repo. What matters is knowing which event IDs to keep
switched on and why, so that is what this file documents.

Baseline I start from:
https://github.com/SwiftOnSecurity/sysmon-config

Install and update:

```cmd
sysmon64.exe -accepteula -i sysmonconfig.xml
sysmon64.exe -c sysmonconfig.xml
```

## Event IDs that drive this repo

| Event ID | What it captures | Detections that need it |
|----------|------------------|-------------------------|
| 1  | Process creation with full command line | Encoded PowerShell, AD recon, log clearing |
| 3  | Network connection | Beaconing and lateral movement hunts |
| 10 | Process access (handle opened to another process) | LSASS credential dumping |
| 11 | File create | Dropper and tooling artefacts |
| 13 | Registry value set | Run key persistence |

Windows also raises some of these natively in the Security and System logs, which
is why a few rules in this repo key off Security Event IDs like 4769, 4732, 7045
and 1102 rather than Sysmon. Both sources get shipped to Elastic.

## Tuning notes

The biggest win is making sure command line logging is on and not being truncated,
since most of the process based rules read `process.command_line`. After that, the
work is allowlisting your own noisy but legitimate software so the alerts stay
sharp. Every `filter_known_good` block in the Sigma rules is there because I hit
that noise in the lab and tuned it out.
