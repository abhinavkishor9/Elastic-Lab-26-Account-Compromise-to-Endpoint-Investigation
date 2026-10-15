# Investigation Notes — Lab 26

## 1. Investigation Objective

Investigate available Windows endpoint telemetry to determine whether process execution and network activity provide evidence relevant to a suspected account compromise.

The investigation examines process-creation events, PowerShell activity, network connections, and the availability of Windows authentication events.

## 2. Environment and Scope

- **Platform:** Elastic Security
- **Query language:** ES|QL
- **Data view:** `logs-*`
- **Endpoint:** `desktop-9mmm37v`
- **Telemetry:** Windows Sysmon Operational events
- **Investigation time range:** Last 15 minutes, as displayed during the session
- **Agent status:** Healthy after troubleshooting

The findings below reflect the records captured during the investigation. They should not be generalized beyond the selected time range.

## 3. Process-Creation Investigation

### Query

```esql
FROM logs-*
| WHERE event.code == "1"
| KEEP @timestamp, host.name, user.name,
       process.name, process.executable,
       process.command_line, process.pid,
       process.parent.name
| SORT @timestamp DESC
| LIMIT 200
```

### Observed Results

The query processed 203 documents, with 200 results displayed.

The extracted results included:

- **Timestamp:** October 15, 2026, 05:47:10.464
- **Host:** `desktop-9mmm37v`
- **User:** `SYSTEM`
- **Process:** `powershell.exe`
- **Executable path:** Under `C:\Windows\System32\WindowsPowerShell\...`
- **Command line:** Not populated in the displayed record
- **Process ID:** Partially captured in the extracted image

A nearby record at 05:47:10.371 showed `powershell.exe` with a partially visible command line beginning with `powershell.exe -NoProfile -...`.

A later record showed `PickerHost.exe` running under the `Dell` account at 05:49:45.687.

### Assessment

Process-creation telemetry was available, including PowerShell execution under `SYSTEM` and a process associated with the `Dell` account.

The available extracted output does not contain enough information to determine the purpose of the PowerShell execution or establish whether it was associated with unauthorized access.

The command lines and process identifiers must be retrieved in full before attempting detailed process correlation.

## 4. Authentication Investigation

### Query

```esql
FROM logs-*
| WHERE event.code IN ("4624", "4625", "4648")
| KEEP @timestamp, host.name, user.name,
       event.code, event.action,
       source.ip, winlog.event_data.LogonType,
       winlog.event_data.TargetUserName,
       winlog.event_data.IpAddress
| SORT @timestamp DESC
| LIMIT 200
```

### Observed Result

The query returned zero documents processed.

The selected event IDs represent:

- `4624` — Successful logon.
- `4625` — Failed logon.
- `4648` — Logon attempted using explicit credentials.

### Assessment

No matching authentication records were available through this query in the observed run.

This does not establish that no logons occurred. Possible explanations include missing Windows Security log collection, the selected data view or time range, field mapping differences, or a lack of matching events during the selected period.

The actual cause has not yet been established.

Without suitable authentication evidence, the investigation cannot confirm a successful or failed logon sequence associated with a suspected account compromise.

## 5. Network Connection Investigation

### Query

```esql
FROM logs-*
| WHERE event.code == "3"
| KEEP @timestamp, host.name, user.name,
       process.name, process.pid,
       source.ip, destination.ip,
       destination.port, destination.domain
| SORT @timestamp DESC
| LIMIT 100
```

### Observed Results

The query processed 89 documents and returned 89 results.

The first displayed records included:

- **Timestamp:** October 15, 2026, 05:49:33.975
- **Host:** `desktop-9mmm37v`
- **User:** `Dell`
- **Process:** `Zoho Mail - Desktop.exe`
- **Process ID:** `10596`
- **Source IP:** `192.168.1.6`
- **Destination IP:** `169.148.149.13`

Two additional records at approximately 05:49:33.956 and 05:49:33.952 showed the same process and source IP connecting to `1.1.1.1`.

### Assessment

The observed records establish that `Zoho Mail - Desktop.exe` was associated with network connection events to the displayed destination addresses.

The extracted results do not establish the purpose or security significance of these connections. The destinations have not been verified as malicious, and the connections have not been linked to the PowerShell activity or to a confirmed authentication event.

## 6. Correlation Assessment

The current evidence establishes the following:

1. Process-creation telemetry was available and included PowerShell and `PickerHost.exe` records.
2. Network telemetry included connections associated with `Zoho Mail - Desktop.exe`.
3. The authentication-event query returned zero documents.
4. The Elastic Agent was observed as Healthy after troubleshooting.

The available evidence does not establish that these observations belong to a single incident. No confirmed account compromise, unauthorized logon, or causal relationship between the observed processes and network connections has been demonstrated.

## 7. Evidence Gaps and Next Steps

- Verify whether Windows Security events are being collected into the relevant Elastic data streams.
- Inspect the complete event documents and validate the actual event-code and field mappings.
- Retrieve full PowerShell command lines and process identifiers.
- Examine parent-process details where available.
- Review network records in context and verify destination information if required.
- Correlate events only when timestamps, hostnames, user context, or process identifiers provide sufficient support.
- Document any additional findings before changing the investigation assessment.

## 8. Final Assessment

The investigation confirms the presence of endpoint process and network telemetry but does not confirm an account compromise.

Authentication evidence is currently unavailable through the queried event IDs. Further investigation is needed to establish whether the missing records reflect collection limitations or an absence of matching events.

The incident assessment must remain inconclusive until additional evidence supports a stronger conclusion.
