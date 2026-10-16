# Runbook: NAS Authentication Attack

## Trigger

Use this runbook when monitoring identifies repeated SSH or DSM authentication failures, an Auto Block event, or an unusual successful login.

## 1. Validate and Preserve

- Record the detection time, source, service, affected account, and timezone.
- Preserve the relevant logs before retention or rotation removes them.
- Hash exported evidence and store the original read-only.
- Confirm whether the event came from authorized testing or a trusted client with stale credentials.

## 2. Scope

- Review failures and successes before and after the trigger.
- Search for the same source address, /24 network, account, and user agent where available.
- Review new users, group membership, privilege changes, MFA changes, and SSH-key changes.
- Check firewall, router, VPN, and reverse-proxy logs.
- Look for unusual processes, scheduled tasks, packages, shares, or outbound traffic.

## 3. Determine Severity

- **Low:** isolated failure, known user error, no suspicious follow-on activity
- **Medium:** repeated unauthorized failures or automatic block, no successful access found
- **High:** success after failures, privileged account targeted, or suspicious configuration changes
- **Critical:** confirmed persistence, data access, encryption, exfiltration, or destructive activity

## 4. Contain

- Block confirmed hostile indicators at the appropriate control point.
- Disable or restrict the affected account when compromise is plausible.
- Revoke active sessions and rotate credentials.
- Remove direct Internet exposure and require VPN access where possible.
- Isolate the NAS if active compromise is suspected.

## 5. Eradicate and Recover

- Remove unauthorized accounts, keys, tasks, packages, and configuration changes.
- Patch DSM and packages.
- Restore known-good configuration or data if integrity is uncertain.
- Validate backups before relying on them.
- Re-enable services gradually while monitoring authentication and outbound traffic.

## 6. Document

- Record the timeline, evidence, affected assets, actions, and decision points.
- Separate confirmed facts from hypotheses.
- Note telemetry gaps and confidence levels.
- Add detection or hardening improvements to the follow-up plan.
