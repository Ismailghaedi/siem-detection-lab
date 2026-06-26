# Kibana KQL quick filters

These are Kibana Query Language one liners for hunting in Discover or for the
filter bar on a dashboard. KQL here means Kibana Query Language, the Elastic
filter syntax, not Azure Sentinel KQL. They are deliberately simple, made for
quickly pivoting through data while investigating rather than for standing
alerts. For alerting, use the EQL versions in ../eql.

Field names assume ECS with Sysmon via Winlogbeat or Elastic Agent.

---

Failed logons, useful for spotting brute force or password spray:

```
event.code:4625
```

Successful logon straight after a run of failures from one source (pair with a
time filter on the same source.ip):

```
event.code:4624 and winlog.event_data.LogonType:3
```

New service installed:

```
event.code:7045
```

PowerShell with an encoded command:

```
process.name:("powershell.exe" or "pwsh.exe") and process.command_line:*-enc*
```

LSASS access:

```
event.code:10 and winlog.event_data.TargetImage:*lsass.exe
```

Domain group enumeration:

```
process.name:("net.exe" or "net1.exe") and process.command_line:*domain*
```

Security log cleared:

```
event.code:1102
```

A new local admin being added (Event ID 4732 into the Administrators group):

```
event.code:4732 and winlog.event_data.TargetUserName:*Administrators*
```
