# IR-001: Persistent Authentication Attempts Against Synology NAS

## Executive Summary

A review of 9,179 Synology DSM System log records identified **2,052 automatic source blocks** between July 24, 2025 and October 16, 2026. Of these events, 2,047 involved SSH and five involved DSM.

The activity is most consistent with persistent, automated authentication scanning against Internet-reachable services. Synology Auto Block contained the observed sources. No successful authentication event, privilege change, or security-configuration change was identified in this export, so this investigation found **no evidence of compromise in the available dataset**.

That conclusion is deliberately narrow. The export records blocks, not the complete authentication trail, and therefore cannot rule out successful access without additional logs.

## Classification

- **Type:** Suspected brute-force / password-spraying activity
- **Severity:** Medium
- **Status:** Observed attempts contained; compromise not confirmed
- **Affected services:** SSH and DSM authentication surfaces
- **Confidence:** High for repeated hostile or unauthorized authentication activity; low for actor identity; insufficient evidence for compromise

## Scope and Evidence

- Evidence source: private Synology DSM System log export
- Evidence window: 2025-07-24 02:55:11 through 2026-10-16 11:48:39
- Parsed records: 9,179
- Evidence integrity: SHA-256 recorded in the evidence-handling document
- Analysis method: read-only parsing, aggregation, passive enrichment, and manual review

## Timeline and Observations

- **2025-07-24:** first event in the supplied export
- **2025-07 through 2026-10:** recurring SSH Auto Block events throughout the available months
- **2025-12:** highest monthly total, with 320 blocks
- **2026-03-01:** highest daily total, with 57 blocks
- **2026-10-16:** last event in the supplied export

The 2,052 block events came from 2,052 distinct source addresses across 1,648 /24 networks. The one-event-per-address pattern, combined with recurrence inside several network ranges, suggests rotating or distributed infrastructure rather than one source repeatedly retrying from a fixed address.

## Threat-Intelligence Context

Representatives from the five highest-volume network clusters were enriched using passive sources. They resolved to hosting/network-provider space in Germany and the Netherlands. Four appeared in multiple AlienVault OTX pulses.

This strengthens the hypothesis of automated scanning infrastructure, but it does not identify the human operator or prove that every address in those networks is malicious. Public reporting uses synthetic network labels rather than raw indicators.

## MITRE ATT&CK Mapping

### T1110 — Brute Force

Auto Block behavior indicates repeated authentication failures crossed a configured threshold. The exact sub-technique cannot be determined from the block records alone because attempted credential sets and failure counts are absent.

### T1133 — External Remote Services

The events target SSH and DSM authentication surfaces reachable by external source addresses. This technique is relevant as exposure context; there is no evidence in the supplied export that an attacker established access.

## Impact Assessment

### Confirmed

- Repeated unauthorized authentication activity reached exposed services.
- Synology Auto Block blocked the observed source addresses.
- The activity persisted across an extended period.

### Not confirmed

- Successful authentication
- Account takeover
- Privilege escalation
- Malware execution
- Data access or exfiltration
- Persistence
- Actor identity or geographic origin

## Evidence Gaps

The following sources are needed for a higher-confidence conclusion:

- detailed SSH authentication logs, including success and failure records
- DSM login and connection history
- account, group, privilege, and MFA audit events
- firewall/router NAT and connection logs
- configuration-change history
- endpoint/process telemetry from the NAS where available
- time synchronization and timezone confirmation across sources

The most important correlation is a successful login following failures from the same address, network, account, or time window.

## Containment and Hardening

1. Confirm whether direct Internet access to SSH or DSM is required.
2. Remove direct exposure where possible and use a private VPN for administration.
3. Restrict management access with firewall allowlists.
4. Require SSH keys and disable password and root authentication.
5. Enforce MFA for DSM and disable default or unused administrator accounts.
6. Review successful logins, account changes, and configuration changes across the evidence window.
7. Patch DSM and installed packages.
8. Verify offline or immutable backups and test restoration.

## Detection Improvements

Forward Synology, firewall, and authentication telemetry to a central collector. Prioritize alerts for:

- a successful login after repeated failures
- blocks involving privileged or valid account names
- new administrators or privilege changes
- MFA disablement or authentication-policy changes
- SSH/DSM access from a new country or ASN
- firewall or port-forward changes
- high-volume blocks from one network cluster

## Lessons Learned

- Auto Block provides useful containment but limited investigative context.
- A blocked event should trigger correlation, not an assumption that the incident is resolved.
- Threat intelligence is most useful when combined with local evidence.
- Public case studies should preserve methodology while withholding operationally sensitive raw data.

## Final Assessment

**Persistent automated authentication attempts were observed and blocked. No compromise was identified in the supplied export, but the absence of detailed authentication telemetry prevents a definitive no-compromise conclusion.**
