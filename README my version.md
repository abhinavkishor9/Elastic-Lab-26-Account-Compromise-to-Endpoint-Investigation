# Elastic-Lab-26-Account-Compromise-to-Endpoint-Investigation
## Overview
An account compromise occurs when an unauthorized person gains access to a legitimate user account. Attackers may use stolen credentials, password spraying, phishing, or session theft to access systems. Once access is obtained, they may attempt to execute commands, create processes, access sensitive files, or establish network connections from the compromised endpoint.
The investigation follows this sequence:
Suspected account compromise → User context → Endpoint process activity → Related network activity → Evidence-based assessment
Endpoint logs alone may not confirm how an account was compromised. Authentication evidence, such as Windows logon events or identity-provider sign-in records, may be required to establish unauthorized access and connect it to subsequent endpoint activity.

This lab investigates Windows endpoint activity to determine whether available telemetry contains indicators that warrant further investigation into a suspected account compromise.

The investigation uses Elastic Security, Sysmon process-creation events, and network connection events. Windows authentication events are also considered, but their availability must be verified before drawing conclusions about successful or failed logons.

The focus is on analyzing process execution, user context, network activity, and relationships between events while distinguishing observed behavior from unverified assumptions.

## Lab Objectives

- Investigate Windows endpoint activity for behaviors that may indicate unauthorized account use or post-compromise execution.
- Examine process-creation events to identify the associated user accounts, executable paths, command lines, and process identifiers.
- Analyze PowerShell activity and determine whether the available execution context warrants further investigation.
- Investigate network connection events to identify destination addresses, associated processes, and potentially relevant communication patterns.
- Validate the availability of Windows authentication events and investigate why event IDs `4624`, `4625`, and `4648` are not returned.
- Correlate process and network events using timestamps, hostnames, user context, and process identifiers where supported by the evidence.
- Identify missing telemetry and incomplete process details that limit the reconstruction of suspicious activity.
- Distinguish confirmed endpoint observations from suspected account compromise and other unverified explanations.
- Document investigation findings, troubleshooting steps, and outstanding evidence requirements in a chronological record.
- Develop an evidence-based assessment that identifies what can be established and what additional authentication or endpoint evidence is needed.

## Lab Scenario 

A Windows endpoint is being examined for activity that could indicate account compromise or suspicious execution. The objective is to investigate the available endpoint telemetry, identify potentially relevant process and network activity, and determine whether the collected evidence supports a connection between authentication activity and subsequent execution.

The investigation uses Elastic Security, ES|QL, and Sysmon telemetry from the Windows endpoint `desktop-9mmm37v`. Process-creation events are available for analysis, and network connection events provide additional context about processes communicating with external destinations. However, the expected Windows authentication events are not returned by the initial queries.

### Investigation Context

The analyst must assess the available evidence without assuming that an account has been compromised. The investigation focuses on:

- **Process activity:** Review Sysmon Event ID `1` for executable names, user context, command lines, process identifiers, and execution timestamps.
- **Network activity:** Review Sysmon Event ID `3` to identify communicating processes, source and destination addresses, and relevant timestamps.
- **Authentication visibility:** Check for Windows events `4624` (successful logon), `4625` (failed logon), and `4648` (logon using explicit credentials).
- **Event correlation:** Compare timestamps, host information, users, and process identifiers to determine whether the available records support a common activity sequence.
- **Telemetry troubleshooting:** Investigate why authentication events are unavailable and distinguish missing evidence from evidence that an event did not occur.

### Investigation Challenge

The process-creation query returns 203 processed documents, with 200 results displayed, while the network query returns 89 documents. The authentication query returns zero documents for the selected event IDs. The available process telemetry includes PowerShell activity under the `SYSTEM` account and activity associated with the interactive user `Dell`. Network records include connections attributed to `Zoho Mail - Desktop.exe`.

These observations provide investigation leads, but they do not independently establish malicious execution, unauthorized access, or a relationship between the observed processes and network connections. The analyst must determine which details can be correlated reliably and which conclusions remain unsupported because authentication telemetry and complete event details are unavailable.

### Expected Outcome

Produce an evidence-based investigation report that documents the available process and network activity, authentication-log visibility issues, troubleshooting performed, and limitations affecting correlation. The final assessment should clearly separate **observed facts, plausible explanations, and unresolved questions**.

The investigation is successful when it establishes what the available telemetry can demonstrate, identifies the evidence needed to validate or reject the account-compromise hypothesis, and avoids declaring a compromise without sufficient supporting evidence.


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

