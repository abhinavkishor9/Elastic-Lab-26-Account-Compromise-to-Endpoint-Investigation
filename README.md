# Lab 26 — Account Compromise → Endpoint Investigation

## Overview

This lab investigates Windows endpoint activity to determine whether available telemetry contains indicators that warrant further investigation into a suspected account compromise.

The investigation uses Elastic Security, Sysmon process-creation events, and network connection events. Windows authentication events are also considered, but their availability must be verified before drawing conclusions about successful or failed logons.

The focus is on analyzing process execution, user context, network activity, and relationships between events while distinguishing observed behavior from unverified assumptions.

## Investigation Objectives

- Examine process-creation events and identify the accounts associated with recorded activity.
- Investigate PowerShell execution and review available command-line and parent-process details.
- Analyze network connections and identify the associated processes and destination addresses.
- Validate whether authentication telemetry is available in the current Elastic data view.
- Correlate endpoint events using timestamps, hostnames, user context, and process identifiers where possible.
- Document missing evidence and determine whether the available information supports further investigation.

## Lab Environment

- **Platform:** Elastic Security
- **Query language:** ES|QL
- **Data view:** `logs-*`
- **Endpoint:** `desktop-9mmm37v`
- **Operating system:** Windows 11
- **Telemetry:** Windows Sysmon Operational events
- **Agent policy:** `Windows-SOC-Lab`
- **Agent status:** Healthy at the time of the latest check

## Investigation Workflow

1. Verify Elastic Agent health and confirm that endpoint events are arriving.
2. Search process-creation events and examine execution details.
3. Investigate network connection events and identify the associated processes.
4. Search for Windows authentication events, including event IDs `4624`, `4625`, and `4648`.
5. Troubleshoot missing authentication records and validate the available data sources.
6. Correlate relevant events where the evidence supports a relationship.
7. Document findings, limitations, and additional evidence required for a defensible assessment.

## Observed Findings

The investigation produced the following results:

- The process-creation query processed 203 documents and displayed 200 results.
- The displayed process records included `powershell.exe` running as `SYSTEM` and `PickerHost.exe` running as `Dell`.
- The network connection query processed 89 documents and returned 89 results.
- Network records included connections associated with `Zoho Mail - Desktop.exe` to `169.148.149.13` and `1.1.1.1`.
- The authentication-event query for event IDs `4624`, `4625`, and `4648` returned zero documents.
- The Elastic Agent was observed in a Healthy state after troubleshooting.

These findings establish that process and network telemetry was available. They do not establish that an account was compromised or that the observed activity was malicious.

## Evidence Limitations

The absence of authentication records prevents confirmation of successful logons, failed logons, or explicit-credential logon attempts from the queried data.

Similarly, PowerShell execution under `SYSTEM` is not inherently malicious, and network connections to the observed destination addresses are not proof of command-and-control activity or data exfiltration.

Further investigation requires validation of event availability, complete process details, and any relevant relationships between authentication and endpoint activity.

## Expected Outcome

Produce an evidence-based investigation record that identifies relevant endpoint activity, explains the limitations of the available telemetry, and determines what additional evidence is needed to assess a suspected account compromise.

The final assessment must distinguish confirmed observations from hypotheses and unknowns.

## Conclusion

Endpoint process and network telemetry can help investigate activity associated with a potentially compromised account. However, a defensible conclusion requires reliable correlation and sufficient context. When authentication evidence is unavailable, the limitation must be documented rather than replaced with an unsupported assumption.
