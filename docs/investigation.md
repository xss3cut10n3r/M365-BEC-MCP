# M365 investigation guide

Use the five MCP prompts as needed. Collection, investigation, containment and customer communications can proceed in parallel. Give each workstream an owner and record action times in UTC.

| Prompt | What to establish |
| --- | --- |
| `investigation_intake` | Who reported the incident, who was affected, what happened, when and where it happened, and how it was detected. Record possible motives as hypotheses. Ask about licensing, retention, MFA, OWA, API access, approved apps and hybrid identity. |
| `plan_collection` | Agree on sources, tenant, collection windows, filters and permissions. Record gaps and who can supply the missing evidence. |
| `investigate_compromise` | Trace initial access, determine the observed window, and examine outbound mail, rules, grants, devices and mailbox access. Seek independent evidence for message content, downloads, fraud and financial loss. |
| `verify_containment` | Compare activity before and after each confirmed action. Track session revocation, credential and MFA resets, devices, rules and app grants separately. Assign follow-up collection and escalation. |
| `incident_handoff` | Deliver the evidence timeline, findings, confidence, business impact, recovery checks, unresolved questions and artifact references. Agree on lessons learned and inventory updates. |

## Collection coverage

Use Entra sign-ins and authentication details for access, directory audits for identity changes, Purview for audited operations, and Exchange traces for message delivery. Ask the SOC for relevant Sentinel or LogRhythm exports. Defender, endpoint, mail security and on-premises evidence can help distinguish initial access hypotheses. The local tools operate on supplied files and cases.

Record the collector, tenant, export method, requested UTC window, filters, record types, and returned counts. Case inventory shows observed event times. A header-only export, an absent source, and records outside the requested window have different implications. A combined timeline can include several providers.

Confirm Exchange Online permissions independently of on-premises Domain Admin membership. Verify audit-search access for the collector and preview access if the task involves message contents. Check the approved Exchange Online PowerShell connection and tenant access policies with the operator. [Exchange Online permissions](https://learn.microsoft.com/en-us/exchange/permissions-exo/permissions-exo) and [Purview audit search](https://learn.microsoft.com/en-us/purview/audit-search)

For `Search-UnifiedAuditLog`, a `ReturnLargeSet` session can retrieve up to 50,000 records across pages of up to 5,000. Record each session and interval, retrieve all pages, and use smaller UTC windows when a session reaches the limit. Retain the collection log and reconcile gaps or overlap. A CSV assembled from several sessions cannot establish whether a particular session reached the cap. [Microsoft audit-search reference](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/search-unifiedauditlog)

## Recovery checks

Supply the mailbox and three UTC timestamps to `compare_containment`. The first window includes the start and ends immediately before containment. The second includes containment and ends immediately before the review cutoff. Undated records need separate review. Result categories can overlap.

Follow each BQL filter into the timeline. Compare sign-in outcomes, device and session IDs, MFA changes, rules, sent mail, message traces and accessed items. Review tenant-wide consent and service-principal activity separately because it may omit the user's mailbox. A rule or application change needs inspection before attributing it to an attacker. A quiet interval needs collection coverage before supporting a recovery decision.

For each material claim, cite the UTC time, event key, original filename, source row or JSON path, and file hash. Record reported facts separately from observed events. Ask the customer to confirm financial loss, business disruption and data sensitivity. Use a named owner and UTC deadline for each open question.
