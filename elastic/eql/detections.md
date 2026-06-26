# Elastic EQL detection queries

These are the same detections as the Sigma rules, written in EQL for the Elastic
Security detection engine. EQL shines for the sequence based ones where you care
about order, for example recon followed by lateral movement. Field names assume
Elastic Common Schema (ECS) with Sysmon shipped by Winlogbeat or Elastic Agent.

Paste a query into Security, Rules, Create new rule, Event Correlation.

---

## LSASS memory access (T1003.001)

```eql
process where event.code == "10" and
  winlog.event_data.TargetImage : "*\\lsass.exe" and
  winlog.event_data.GrantedAccess in ("0x1010","0x1410","0x1438","0x143a","0x1fffff") and
  not winlog.event_data.SourceImage : ("*\\MsMpEng.exe","*\\wininit.exe","*\\csrss.exe")
```

## Encoded PowerShell (T1059.001)

```eql
process where event.type == "start" and
  process.name : ("powershell.exe","pwsh.exe") and
  process.command_line : ("* -enc *","* -encodedcommand*","* -ec *")
```

## PsExec service install (T1021.002)

```eql
any where event.code == "7045" and
  (winlog.event_data.ServiceName : ("PSEXESVC*","PAExec*","RemCom*") or
   winlog.event_data.ImagePath : "*PSEXESVC*")
```

## AD recon via net commands (T1087.002)

```eql
process where event.type == "start" and
  process.name : ("net.exe","net1.exe") and
  process.command_line : ("*group \"domain admins\"*","*user /domain*","*group /domain*")
```

## Registry Run key persistence (T1547.001)

```eql
registry where event.code == "13" and
  registry.path : (
    "*\\CurrentVersion\\Run\\*",
    "*\\CurrentVersion\\RunOnce\\*"
  ) and
  not process.name : ("OneDriveSetup.exe","msiexec.exe")
```

## Event log cleared (T1070.001)

```eql
any where event.code == "1102" or
  (process.command_line : ("*wevtutil cl*","*Clear-EventLog*"))
```

## Recon then lateral movement sequence (correlation example)

This is the one that is hard to do well in a flat query language. It fires only
when domain recon is followed by a PsExec style service install from the same
host inside ten minutes, which is a much higher confidence signal than either
event alone.

```eql
sequence by host.name with maxspan=10m
  [ process where process.name : ("net.exe","net1.exe") and
      process.command_line : ("*group \"domain admins\"*","*user /domain*") ]
  [ any where event.code == "7045" and
      winlog.event_data.ServiceName : ("PSEXESVC*","PAExec*") ]
```
