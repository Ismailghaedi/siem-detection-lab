# Sigma rules

Vendor neutral detection rules in Sigma format, sorted by ATT&CK tactic. Sigma is
the right place to start because one rule converts to whatever backend you run,
Elastic, Splunk, Sentinel and others, so the logic lives in one place and is not
tied to a single SIEM.

## Layout

```
credential_access/   LSASS dumping, Kerberoasting
execution/           encoded PowerShell
lateral_movement/    PsExec service install
discovery/           AD recon via net commands
persistence/         registry Run key
defense_evasion/     event log clearing
```

## Converting to your backend

Install the Sigma CLI and point it at a rule:

```bash
pip install sigma-cli
sigma convert -t elasticsearch -p ecs_windows sigma/credential_access/lsass_memory_access.yml
```

Swap the target for `splunk`, `microsoft365defender` or others as needed. The
Elastic versions I actually run in the lab are already written out in
../elastic/eql.

## On the falsepositives sections

Every rule lists realistic false positives and most have a tuning filter. Those
are not boilerplate. They come from running the matching attack in my lab, seeing
what legitimate activity also tripped the rule, and tuning it down. A detection
with no thought given to false positives is a detection that gets switched off in
week one.
