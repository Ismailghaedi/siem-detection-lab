# Elastic detections

Two flavours of the same detections, tuned for my Elastic SIEM lab.

`eql/` holds the EQL queries that go into the Elastic Security detection engine as
real, standing rules. Use these for alerting. The sequence example shows the kind
of multi step detection that EQL does well and a flat filter cannot.

`kql/` holds Kibana Query Language filters for live hunting in Discover. These are
for poking around the data during an investigation, not for alerts.

## How the data gets here

```
Windows endpoints  ->  Sysmon (rich process, network, registry telemetry)
                   ->  Winlogbeat / Elastic Agent  ->  Elasticsearch  ->  Kibana
```

Sysmon does the heavy lifting on visibility. The config that drives what it logs
lives in ../sysmon. Without a good Sysmon config most of these detections have
nothing to match on, so that file matters as much as the rules themselves.

## A note on field names

Everything here assumes Elastic Common Schema. If your Sysmon data is mapped
slightly differently, the event codes stay the same but you may need to adjust a
field path, for example `winlog.event_data.TargetImage` versus a custom mapping.
That tuning is part of the point of running the lab.
