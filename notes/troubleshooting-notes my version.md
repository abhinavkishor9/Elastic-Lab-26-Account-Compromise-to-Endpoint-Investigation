# Troubleshooting Notes

## 1. Elastic Agent Initially Reported Unhealthy

### Symptom

The Elastic Agent was reported as Unhealthy in Fleet during the investigation.

### Resolution

The agent subsequently returned to a Healthy state.

### Validation

- Confirm the current agent status in Fleet.
- Verify that recent process and network events are arriving.
- Confirm that the assigned agent policy is correct.
- Check integration status if a particular event type remains unavailable.

### Important Limitation

A Healthy agent status does not guarantee that every configured integration is collecting all expected event types. Validate the actual events in Elastic.

## 2. Authentication Queries Return Zero Documents

### Symptom

The search for Windows Security event IDs `4624`, `4625`, and `4648` returned zero documents processed.

### Troubleshooting Steps

1. Confirm the selected time range.
2. Inspect the available data streams and verify whether Windows Security events are being collected.
3. Check the assigned Elastic Agent policy and the configured Windows integrations.
4. Inspect the actual event-code values and relevant field mappings.
5. Search the appropriate data source for recent authentication events without assuming that they are stored in the same dataset as Sysmon.
6. Review integration status and collection configuration before changing the policy.

### Important Limitation

Zero results do not prove that no logons occurred. The underlying cause must be established through data-source and collection checks.

## 3. Process Records Have Missing Command Lines or Parent Details

### Symptom

Some PowerShell records did not display a complete command line or parent-process information.

### Troubleshooting Steps

1. Open the full event in Discover.
2. Inspect the raw event for available process and parent-process fields.
3. Verify the field names and whether the values are populated.
4. Record the complete process identifier and timestamp where available.
5. Examine related process-creation events only when a reliable relationship can be established.

### Important Limitation

Do not infer a parent process or the purpose of a command from an incomplete record.

## 4. Network Connections Need Additional Context

### Observation

The network query returned 89 records, including connections associated with `Zoho Mail - Desktop.exe` to `169.148.149.13` and `1.1.1.1`.

### Troubleshooting Steps

1. Inspect the complete network event.
2. Record the source IP, destination IP, destination port, timestamp, process ID, and available domain.
3. Verify the destination's purpose using an appropriate source if necessary.
4. Review related process events using the available identifiers and timestamps.
5. Document whether a relationship to suspected account compromise is supported by evidence.

### Important Limitation

A network connection does not by itself establish malicious activity, command-and-control communication, or data exfiltration.

## 5. Process Query Returned More Documents Than the Display Limit

### Observation

The process-creation query processed 203 documents and displayed 200 results.

### Interpretation

The query used a limit of 200, so the displayed results do not represent every processed record.

### Troubleshooting Steps

- Keep the query limit in mind when interpreting the displayed results.
- Narrow the search using a validated time range, host, process name, or other relevant field.
- Increase the limit only when appropriate.
- Record the actual result count and query conditions.

