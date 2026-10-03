# Detection Engineering: Detecting Credential Attacks in Microsoft Sentinel

**Role:** Tier 1 SOC Analyst / detection engineering (project)
**Tools:** Microsoft Sentinel, KQL, Windows Security logs, MITRE ATT&CK
**Scope:** Custom detection rules, attack simulation, alert triage, incident investigation, reporting

## Overview

This project covers detection and response: writing detection rules in Sentinel, simulating the attacks they target, and investigating the resulting alerts the way a SOC analyst would.

Lab Diagram.
<img width="2720" height="2560" alt="corrected_original_layout_diagram" src="https://github.com/user-attachments/assets/8b31b6f6-be04-48d7-a68d-e61edc4ad942" />

Log collection is covered separately in the [Azure Arc Onboarding project](../azure-arc-onboarding) (update this link to your repo). This project assumes Windows Security events from the lab machines are already available in the `SecurityEvent` table.

## Threat model

| Attack | Why it matters | ATT&CK |
|---|---|---|
| Password spraying | Low-and-slow attempts across many accounts avoid lockout | T1110.003 Password Spraying |
| Brute force | Repeated guesses against a single account | T1110.001 Password Guessing |

**Design decision.** The lab's AD account lockout threshold is set to 3, which already limits single-account brute force. Spraying works around that control by trying few passwords against many accounts, so the flagship detection correlates failed logons across accounts by source IP. A single-account brute-force rule is kept as a complementary detection.

## Detection workflow

```mermaid
flowchart LR
    A[Windows Security events<br/>4624 / 4625] --> B[SecurityEvent table]
    B --> C[Sentinel analytics rule]
    C --> D[Alert]
    D --> E[Incident]
    E --> F[Triage and investigation]
    F --> G{Verdict}
    G -->|True positive| H[Respond / escalate]
    G -->|False positive| I[Tune rule]
```

## Detection rules

| # | Detection | Severity | ATT&CK | Events |
|---|---|---|---|---|
| 1 | Password spray: failed logons across multiple accounts from one source | High | T1110.003 | 4625 |
| 2 | Brute force: repeated failed logons against one account | Medium | T1110.001 | 4625 |

Rules are created in Sentinel (Microsoft Defender portal) under **Microsoft Sentinel > Configuration > Analytics > Scheduled query rule**.

<img width="951" height="326" alt="Screenshot 2026-10-03 012118" src="https://github.com/user-attachments/assets/77c93f9f-d5a4-43c4-babf-2a2d86537f3b" />


### Detection 2: Brute force

**Logic.** Repeated failures against one account from one source. The threshold is aligned to the account lockout policy.

```kql
SecurityEvent
| where EventID == 4625
| where IpAddress !in ("-", "", "::1", "127.0.0.1")
| summarize FailedAttempts = count(),
            FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated)
    by IpAddress, TargetUserName, Computer
| where FailedAttempts >= 5
```

Use the threshold you configured. Confirmed firing during testing.

| Setting | Value |
|---|---|
| Run every / lookback | [for example 5 min / 10 min] |
| Entity mapping | Account: `TargetUserName`, IP: `IpAddress`, Host: `Computer` |

## Attack simulations

All tests were run in an isolated lab against dedicated test accounts.

| Test | Simulated behavior | Expected rule | Result |
|---|---|---|---|
| 1 | successful login after multiple failed attempt accounts | Detection 1 | [Fired] |
| 2 | Repeated bad passwords against one account | Detection 2 | [Fired] |

Simulation method and tooling: I intentionally typed in wrong passwords multiple times followed by a correct password from the Active Directory computer keyboard to trigger the alert. i discovered the account lockout policy does not apply to the Active Directory default account. 

## Incident report

### Incident 1: [title from Sentinel]

| Field | Value |
|---|---|
| Detected | [timestamp] |
| Severity | [severity] |
| Triggering rule | [rule name] |
| Source IP | [ip] |
| Target accounts | [accounts] |
| Target host | [host] |
| ATT&CK | [technique] |
| Verdict | [False positive]|


**Triage.** [the alert reported bruteforce account . The activity was expected].

**Investigation.** Pivoted on the source IP to see every account and host involved, and checked whether any attempt succeeded:

```kql
SecurityEvent
| where TimeGenerated between (datetime([start]) .. datetime([end]))
| where IpAddress == "[ip]"
| where EventID in (4624, 4625)
| project TimeGenerated, Computer, EventID, TargetUserName, LogonType, Status, SubStatus
| order by TimeGenerated asc
```

| Time | Event | Significance |
|---|---|---|
| [time] | [event] | [meaning] |
| [time] | [event] | [meaning] |


**Response and recommendations.** [Containment steps (block the source, reset targeted accounts), this doesnt need to be escalated because it is expected. 

**Closure notes.** [The note you would leave in the ticket.]

Evidence: `screenshots/02-alert.png`, `screenshots/03-incident.png`, `screenshots/04-investigation.png`

## Triage and escalation

For each alert:

1. Is the source internal or external, and is it normal for that host?
2. How many accounts are affected, and are any privileged?
3. Did any attempt succeed after the failures?
4. What happened after a successful logon?
5. Is this expected activity (admin task, service account, authorized test)?

**Escalate to Tier 2 when:** a privileged account is targeted, a successful logon follows the failures, multiple hosts are involved, or later activity suggests persistence or lateral movement.



## Next steps

Full incident response walkthrough, threat intelligence enrichment of source IPs, and a SOAR playbook for automated response.

## Skills demonstrated

Detection engineering · KQL · Microsoft Sentinel · MITRE ATT&CK · Alert triage · Incident investigation · Windows Security event analysis · Incident documentation
