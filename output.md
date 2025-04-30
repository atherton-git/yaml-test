## Id
fbd72eb8-087e-466b-bd54-1ca6ea08c6d3
## Name
Office Policy Tampering
## Description
'Detects tampering or disabling of security-related Office 365 policies (Audit Logging, ATP SafeLinks, SafeAttachments, AntiPhish, DLP) via administrative actions. This behaviour may indicate an adversary attempting to evade detection or reduce policy-based protections.'<br/>
## Technicalcontext
This detection uses the `OfficeActivity` table from the `Office365` connector, specifically focusing on `ExchangeAdmin` record types. Administrative operations such as `Remove-DlpCompliancePolicy` or `Disable-AntiPhishRule` are flagged. This logic assumes all administrative activity related to these security policies should be minimal and deliberate. Unexpected or frequent changes may indicate compromise or misconfiguration.
## Detection
* Identifies operations matching policy disable/removal actions.
* Parses `ClientIP` and `Port` for correlation and triage.
* Aggregates results by user, IP, port, and operation status.
## Blindspots
* Non-standard logs or activity via APIs not recorded in OfficeActivity will not be captured.
## Assumptions
* All policy removal or disablement actions are performed via ExchangeAdmin and logged.
* Only Admin or DcAdmin roles can perform impactful changes (may not hold true in some misconfigured environments).
## Faslepositives
### Knownscenarios
* Scheduled or legitimate policy changes.
* Actions by security engineers during threat testing or policy updates.
* Migrations or testing in dev environments improperly mirrored in production logs.
### Minimisationrecommendations
* Add allowlisting logic for known maintenance users or service accounts.
* Filter on `ResultStatus` to exclude failed attempts.
* Use scheduled time filters to suppress known change windows.

## Validation
### Samplealert
* Create a test policy with no meaningful impact, and name appropriately; “Test Anti-Phish Policy 001”.
* Assign a test account with the appropriate permissions.
* Execute a PowerShell command that will trigger the KQL logic
* E.g. Remove-AntiPhishPolicy -Identity "Test Anti-Phish Policy 001"
* Confirm event logs appear in the OfficeActivity table with the appropriate operation.
* Ensure the alert fires and captures the correct user, IP, and operation.

## Severity
Medium
## Response
* Contact user/team associated with the UserId.
* Check for approved change request or CAB record.
* Investigate past activity of the user/IP.
* Check for other security-related changes around the same time.
* If unauthorised, immediately re-enable affected policies.
* Review user account for compromise (password reset, suspicious authentications, etc.)
* Record findings and actions in ticketing system.
* Escalate to IR team if tampering is malicious.
## References
* https://learn.microsoft.com/en-gb/powershell/module/exchange/remove-antiphishrule?view=exchange-ps
* https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
* https://attack.mitre.org/techniques/T1562/
* https://attack.mitre.org/techniques/T1098/
## Status
Available
## Requireddataconnectors
| Connectorid | Datatypes |
| --- | --- |
| Office365 | <ul><li>OfficeActivity (Exchange)</li></ul> |
## Queryfrequency
1d
## Queryperiod
1d
## Triggeroperator
gt
## Triggerthreshold
0
## Tactics
* Persistence
* DefenseEvasion
## Relevanttechniques
* T1098
* T1562
## Query
let opList = OfficeActivity <br/>| summarize by Operation<br/>//| where Operation startswith "Remove-" or Operation startswith "Disable-"<br/>| where Operation has_any ("Remove", "Disable")<br/>| where Operation contains "AntiPhish" or Operation contains "SafeAttachment" or Operation contains "SafeLinks" or Operation contains "Dlp" or Operation contains "Audit"<br/>| summarize make_set(Operation, 500);<br/>OfficeActivity<br/>// Only admin or global-admin can disable/remove policy<br/>| where RecordType =~ "ExchangeAdmin"<br/>| where UserType in~ ("Admin","DcAdmin")<br/>// Pass in interesting Operation list<br/>| where Operation in~ (opList)<br/>| extend ClientIPOnly = case( <br/>ClientIP has ".", tostring(split(ClientIP,":")[0]), <br/>ClientIP has "[", tostring(trim_start(@'[[]',tostring(split(ClientIP,"]")[0]))),<br/>ClientIP<br/>)  <br/>| extend Port = case(<br/>ClientIP has ".", (split(ClientIP,":")[1]),<br/>ClientIP has "[", tostring(split(ClientIP,"]:")[1]),<br/>ClientIP<br/>)<br/>| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), OperationCount = count() by Operation, UserType, UserId, ClientIP = ClientIPOnly, Port, ResultStatus, Parameters<br/>| extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix = tostring(split(UserId, "@")[1])<br/>
## Entitymappings
| Entitytype | Fieldmappings |
| --- | --- |
| Account | <ul><li>{'identifier': 'FullName', 'columnName': 'UserId'}</li><li>{'identifier': 'Name', 'columnName': 'AccountName'}</li><li>{'identifier': 'UPNSuffix', 'columnName': 'AccountUPNSuffix'}</li></ul> |
| IP | <ul><li>{'identifier': 'Address', 'columnName': 'ClientIP'}</li></ul> |
## Version
2.0.3
## Kind
Scheduled
