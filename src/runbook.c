#include "server.h"
#include <string.h>

typedef struct { const char *name, *description, *task; } Runbook;

static const Runbook workflows[] = {
    {"plan_collection", "Scope the collection and check audit-search limits.",
     "Identify the tenant, license, retention, collection owner, source, UTC start and end, record types and "
     "filters. Request Entra sign-ins and directory audit, Purview unified audit and Exchange traces. "
     "Ask SOC for Sentinel or LogRhythm coverage. Confirm the actual tenant roles for each collection step: "
     "Exchange Online permissions are separate from on-premises Domain Admin. Verify audit-search rights, "
     "and any preview or remediation rights separately with the customer. For Exchange Online PowerShell "
     "confirm the approved module, connection method, source network and access policy with the operator. "
     "For Search-UnifiedAuditLog ReturnLargeSet, record the session, requested interval, returned pages "
     "and counts. A 5,000-record page can be followed by more pages; a session reaching 50,000 needs "
     "smaller UTC windows. Check every interval, including empty and failed windows, and reconcile overlaps. "
     "Use the record types appropriate to the question, including AzureActiveDirectoryStsLogon for logons. "
     "Preserve the original export and collector log. A combined CSV count cannot prove a session hit its cap."},
    {"investigation_intake", "Establish the facts and assess collection coverage.",
     "Start with case_overview and page through every log. Record the reporting party, affected identities, "
     "tenant, first report, suspected start, timezone, and collection owner. Ask what happened, when, where, "
     "who was affected, how it was detected, and what motive the evidence supports. Ask the customer about "
     "licensing, retention, MFA coverage, OWA, API access, approved apps, and hybrid identity. "
     "Inventory Entra sign-ins, authentication details and audit, Purview audit, and Exchange traces. "
     "Record filenames, hashes, errors, warnings, and first/last observed events. Obtain the collector's "
     "requested UTC windows, record types, filters and per-window counts separately. A first or last event "
     "is not a collection boundary. Ask the SOC for Sentinel or LogRhythm coverage, Defender mail/device "
     "evidence, and endpoint or on-premises logs as relevant. Track questions, owners and missing sources. "
     "Separate customer statements, observations and hypotheses."},
    {"investigate_compromise", "Reconstruct initial access, mailbox actions and impact.",
     "Establish affected accounts and an explicit UTC window. Search earlier than detection. Use "
     "case_statistics for outcomes, methods, devices, sessions, applications and endpoints. Check successes "
     "and failures, compare with the user's expected devices and travel, and pivot by request or session ID. "
     "Look for inbound phishing, outbound mail, invoice changes, inbox rules, delegation, forwarding, "
     "message traces, app consent and mailbox item access. Use search_events and inspect_event to cite each "
     "finding with file, source location, UTC time and stable event key. A trace records delivery activity; "
     "it cannot establish email content or payment. Describe what was accessible, what access was logged "
     "and what transfer was independently confirmed. Have the customer quantify exposure, actual loss, "
     "data sensitivity and affected business processes. List alternative initial access explanations "
     "and the additional endpoint, mail or identity evidence needed to distinguish them."},
    {"verify_containment", "Compare activity across containment, eradication and recovery.",
     "Ask for exact UTC times, affected entities, the person responsible and evidence for each response action. "
     "Coordinate investigation, customer communications and authorized responders in parallel. Track session "
     "revocation, credential and MFA resets, device removal, forwarding and inbox rules, application grants, "
     "mail remediation and any hybrid identity work separately. Run compare_containment on the mailbox. "
     "Inspect the evidence behind continuing sign-ins, sends, delivery, rule changes and mailbox access. "
     "Pivot on known device, session or app IDs across the tenant: some consent and service-principal changes "
     "do not name the mailbox. Separate failed attempts from successful activity and allow for audit delay. "
     "Record the next collection window, monitoring owner and escalation contact. Verify each action with "
     "the responsible operator. Zero matches alone cannot establish containment."},
    {"incident_handoff", "Prepare the evidence and post-incident handoff.",
     "Produce a concise handoff with detection source, verified UTC timeline, initial access confidence, "
     "impacted users and data, containment actions and owners, and post-containment observations. "
     "Attach source locations, file hashes and BQL filters to material claims. Separate reported fraud "
     "from confirmed financial loss. Identify unresolved questions, retention gaps, recovery checks, "
     "communication owners and the next review time. Ask stakeholders to confirm business impact, artifact "
     "retention, CMDB updates and lessons learned. Send the draft to the operator for review."}
};

Json *list_prompts(JsonDoc *doc) {
    Json *prompts = yyjson_mut_arr(doc);
    for (guint i = 0; i < G_N_ELEMENTS(workflows); i++) {
        Json *entry = yyjson_mut_arr_add_obj(doc, prompts);
        put_text(doc, entry, "name", workflows[i].name);
        put_text(doc, entry, "description", workflows[i].description);
    }
    return prompts;
}

Json *get_prompt(JsonDoc *doc, const char *name) {
    for (guint i = 0; i < G_N_ELEMENTS(workflows); i++) {
        if (g_strcmp0(name, workflows[i].name)) continue;
        Json *result = yyjson_mut_obj(doc);
        put_text(doc, result, "description", workflows[i].description);
        Json *messages = yyjson_mut_obj_add_arr(doc, result, "messages");
        Json *message = yyjson_mut_arr_add_obj(doc, messages);
        put_text(doc, message, "role", "user");
        Json *content = yyjson_mut_obj_add_obj(doc, message, "content");
        put_text(doc, content, "type", "text");
        put_text(doc, content, "text", workflows[i].task);
        return result;
    }
    return NULL;
}

static char *timestamp(Input *args, const char *key) {
    const char *value = yyjson_get_str(yyjson_obj_get(args, key));
    return value && strchr(value, 'T') && g_str_has_suffix(value, "Z") ? utc_normalize(value) : NULL;
}

static const struct { const char *name, *filter; } activity[] = {
    {"all_timed_events", ""},
    {"successful_sign_ins", "source contains \"sign-ins\" AND (result = \"Success\" OR result = \"0\")"},
    {"failed_sign_ins", "source contains \"sign-ins\" AND (result = \"Failure\" OR result = \"Failed\" OR "
                        "(exists \"/status/errorCode\" AND field \"/status/errorCode\" != \"0\"))"},
    {"outbound_send_operations", "operation = \"Send\" OR operation = \"SendAs\" OR operation = \"SendOnBehalf\""},
    {"exchange_traces", "source = \"Exchange trace\""},
    {"rule_or_forwarding_changes", "operation contains \"InboxRule\" OR operation = \"Set-Mailbox\" OR operation contains \"TransportRule\""},
    {"mail_access", "operation = \"MailItemsAccessed\" OR operation = \"AttachmentAccess\""},
    {"device_changes", "operation contains \"device\""},
    {"consent_or_app_changes", "operation contains \"consent\" OR operation contains \"service principal\" OR operation contains \"app role\" OR operation contains \"permission grant\" OR operation contains \"application\""}
};

static void review_period(JsonDoc *doc, Json *result, Session *session, const char *name,
                          const char *identity, const char *start, const char *end, GError **error) {
    Json *window = yyjson_mut_obj_add_obj(doc, result, name);
    put_text(doc, window, "start_inclusive_utc", start);
    put_text(doc, window, "end_exclusive_utc", end);
    char *scope = g_strdup_printf("mailbox = %s AND time >= \"%s\" AND time < \"%s\"", identity, start, end);
    Json *observations = yyjson_mut_obj_add_obj(doc, window, "observations");
    for (guint i = 0; i < G_N_ELEMENTS(activity) && !*error; i++) {
        char *bql = combine_filters(scope, activity[i].filter);
        Json *entry = yyjson_mut_obj_add_obj(doc, observations, activity[i].name);
        put_text(doc, entry, "bql", bql);
        yyjson_mut_obj_add_int(doc, entry, "count", count_rows(session->db, 0, bql, error));
        g_free(bql);
    }
    g_free(scope);
}

Json *compare_containment(JsonDoc *doc, Session *session, Input *args, GError **error) {
    const char *mailbox = yyjson_get_str(yyjson_obj_get(args, "mailbox"));
    char *start = timestamp(args, "start_utc"), *cut = timestamp(args, "containment_utc");
    char *end = timestamp(args, "end_utc");
    Json *result = yyjson_mut_obj(doc);
    if (!mailbox || !*mailbox || strlen(mailbox) > 320 || !start || !*start || !cut || !*cut || !end || !*end ||
        strcmp(start, cut) >= 0 || strcmp(cut, end) >= 0) {
        bec_fail(error, "Supply a mailbox and three increasing UTC timestamps ending in Z");
    } else {
        char *identity = j_quoted(mailbox);
        put_text(doc, result, "mailbox", mailbox);
        put_text(doc, result, "scope", "Matched mailbox identities and dated events only. Categories overlap. "
                 "Review other sign-in results and tenant-wide grants separately. Counts measure recorded activity.");
        review_period(doc, result, session, "before", identity, start, cut, error);
        if (!*error) review_period(doc, result, session, "after", identity, cut, end, error);
        g_free(identity);
    }
    g_free(start);
    g_free(cut);
    g_free(end);
    return result;
}
