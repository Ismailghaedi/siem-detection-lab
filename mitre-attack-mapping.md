# MITRE ATT&CK coverage

What this repo detects, mapped to ATT&CK. It is a focused set aimed at the attack
chain I practise most in the lab, from landing on a host through to covering
tracks, rather than trying to cover everything thinly.

| Tactic | Technique | ID | Detection |
|--------|-----------|----|-----------|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | sigma/credential_access/lsass_memory_access.yml |
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | sigma/credential_access/kerberoasting.yml |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | sigma/execution/powershell_encoded_command.yml |
| Defense Evasion | Obfuscated Files or Information | T1027 | sigma/execution/powershell_encoded_command.yml |
| Lateral Movement | Remote Services: SMB / Admin Shares | T1021.002 | sigma/lateral_movement/psexec_service_install.yml |
| Execution | System Services: Service Execution | T1569.002 | sigma/lateral_movement/psexec_service_install.yml |
| Discovery | Account Discovery: Domain Account | T1087.002 | sigma/discovery/ad_recon_net_commands.yml |
| Discovery | Permission Groups Discovery: Domain Groups | T1069.002 | sigma/discovery/ad_recon_net_commands.yml |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 | sigma/persistence/registry_run_key.yml |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | sigma/defense_evasion/clear_event_logs.yml |

## Where the gaps are

I am being upfront about coverage because pretending a lab covers everything is a
red flag to anyone who knows what they are looking at. There is no detection here
for initial access, exfiltration or command and control, because those need
network and proxy telemetry the lab does not have yet. The natural next additions
are an EDR feed and some network detections, and that is on the roadmap as the lab
grows.
