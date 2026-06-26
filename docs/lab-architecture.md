# Lab architecture

The detections in this repo come out of a home lab I built to practise both sides
of the fence, attacking a small Active Directory environment and then catching
myself doing it in the SIEM.

## The setup

```
                 Attacker box (Kali)
                        |
                        |  attacks: recon, Kerberoasting, PsExec,
                        |  Mimikatz, persistence
                        v
   +--------------------------------------------+
   |        Windows AD environment              |
   |                                            |
   |   Domain Controller (Windows Server)       |
   |   Domain joined workstations               |
   |                                            |
   |   each host runs Sysmon                    |
   +--------------------------------------------+
                        |
                        |  Winlogbeat / Elastic Agent
                        v
   +--------------------------------------------+
   |        Elastic SIEM                         |
   |   Elasticsearch  ->  Kibana                 |
   |   detection rules + dashboards              |
   +--------------------------------------------+
```

## How I use it

The loop is simple and it is the whole point. I run an attack from the Kali box
against the AD environment, then go into Kibana and work out what it looked like
in the logs. If I can see it clearly, I write a detection for it. If I cannot see
it, I fix the logging, usually by tuning Sysmon, and try again.

Every rule in `../sigma` and `../elastic` came from that cycle. The
`filter_known_good` blocks exist because I generated real false positives in this
lab and tuned them out, not because I copied them from somewhere.

## Why it is built this way

I want to move into offensive security, but the fastest way in is through a blue
team or SOC seat. Building the detection side myself means I understand what my own
attacks look like to a defender, which makes me better at both. This lab is the
evidence that I learn by doing rather than just collecting certificates.
