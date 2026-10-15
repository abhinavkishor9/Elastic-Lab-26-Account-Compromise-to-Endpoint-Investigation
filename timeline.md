# Investigation Timeline — Lab 26

## Investigation Scope

- **Date:** October 15, 2026
- **Endpoint:** `desktop-9mmm37v`
- **Platform:** Elastic Security
- **Telemetry:** Windows Sysmon Operational events
- **Selected time range:** Last 15 minutes, as displayed during the session

This timeline records observed process events, network events, and query results. The timestamps do not establish that all observations belong to the same incident.

## Observed Events

| Timestamp | Evidence Source | Observation | Assessment |
|---|---|---|---|
| 05:47:10.371 | Process creation | A `powershell.exe` record running as `SYSTEM` contained a partially visible command line beginning with `powershell.exe -NoProfile -...`. | The complete command and execution context require validation. |
| 05:47:10.464 | Process creation | A `powershell.exe` record running as `SYSTEM` had no visible command line in the extracted result. | The purpose of this process cannot be established from the displayed fields alone. |
| 05:49:33.952 | Network connection | `Zoho Mail - Desktop.exe`, PID `10596`, was associated with a connection from `192.168.1.6` to `1.1.1.1`. | Connection observed; security significance not established. |
| 05:49:33.956 | Network connection | `Zoho Mail - Desktop.exe`, PID `10596`, was associated with another connection to `1.1.1.1`. | Connection observed; relationship to other events unconfirmed. |
| 05:49:33.975 | Network connection | `Zoho Mail - Desktop.exe`, PID `10596`, was associated with a connection to `169.148.149.13`. | Connection observed; destination purpose not established. |
| 05:49:45.687 | Process creation | `PickerHost.exe` was recorded under the `Dell` account. | Process observed; no malicious behavior established by this record alone. |

## Query Results

| Investigation Step | Result | Interpretation |
|---|---|---|
| Process-creation search | 203 documents processed; 200 results displayed | Process telemetry was available for review. |
| Authentication search | 0 documents processed | No matching authentication records were returned by the query. |
| Network connection search | 89 documents processed and returned | Network connection telemetry was available for review. |
| Agent health check | Healthy after troubleshooting | The agent's reported health recovered; individual data sources still require validation. |

## Timeline Assessment

The observed events establish the presence of process-creation and network connection telemetry. The authentication search did not return matching records, so a successful or failed logon sequence could not be reconstructed from the queried data.

The current evidence does not establish that the PowerShell processes, `PickerHost.exe`, and `Zoho Mail - Desktop.exe` connections were related. It also does not confirm an account compromise.

## Outstanding Actions

- Validate the collection and availability of Windows Security authentication events.
- Retrieve complete process details where available.
- Correlate events using reliable identifiers and timestamps.
- Document additional verified findings as they become available.
- Update the assessment only when the evidence supports a stronger conclusion.
