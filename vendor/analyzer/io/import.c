#include "io.h"

#include <string.h>
#include <zlib.h>

#define CHUNK (1024 * 1024)

struct Importer {
    sqlite3 *db;
    gint64 file_id;
    const char *name;
    gboolean json;
    ProgressFn progress;
    gpointer progress_user;
    sqlite3_stmt *event, *ip, *identity;
    // Per-sheet state follows.
    gboolean active;
    gint64 log;
    char *kind;
    guint width;
    GHashTable *positions;
    GArray *targets;
    gint64 count, problems;
    gboolean flat_audit;
    gboolean own_export;
    GString *warnings;
    GPtrArray *verdicts;
};

static const char *get(Importer *im, GPtrArray *values, const char *const *keys) {
    for (; *keys; keys++) {
        gpointer slot;
        if (!g_hash_table_lookup_extended(im->positions, *keys, NULL, &slot))
            continue;
        guint index = GPOINTER_TO_UINT(slot);
        if (index < values->len && *(const char *)values->pdata[index])
            return values->pdata[index];
    }
    return "";
}

#define GET(im, values, ...) get(im, values, (const char *const[]){__VA_ARGS__, NULL})

static gboolean has_header(Importer *im, const char *clean) {
    return g_hash_table_contains(im->positions, clean);
}

static char *detect(Importer *im, const char *label) {
    char *name = casefold(label);
    const char *kind = "Tabular log";
    char *owned = NULL;
    if (has_header(im, "auditdata")) {
        kind = "Purview audit";
    } else if (has_header(im, "actortype") && has_header(im, "activity")) {
        kind = "Entra directory audit";
    } else if (has_header(im, "request id")) {
        const char *family = "User";
        if (strstr(name, "noninteractive") || strstr(name, "non-interactive"))
            family = "Non-interactive";
        else if (strstr(name, "interactive"))
            family = "Interactive";
        else if (has_header(im, "service principal id") && !has_header(im, "username"))
            family = strstr(name, "msisignins") ? "Managed identity"
                                                 : strstr(name, "applicationsignins") ? "Application" : "Workload";
        gboolean steps = has_header(im, "authentication method") && has_header(im, "succeeded");
        kind = owned = g_strconcat(family, steps ? " auth details" : " sign-ins", NULL);
    } else if ((has_header(im, "message_id") && has_header(im, "sender_address")) ||
               (has_header(im, "recipientaddress") && has_header(im, "senderaddress")) ||
               (has_header(im, "recipient address") && has_header(im, "sender address"))) {
        kind = "Exchange trace";
    } else if (has_header(im, "source") && has_header(im, "source row") && has_header(im, "operation") &&
               has_header(im, "time (utc)")) {
        kind = "Timeline";
    } else if (im->json) {
        // Recognize common JSON shapes.
        if (has_header(im, "creationtime") && has_header(im, "operation"))
            kind = "Purview audit";
        else if (has_header(im, "createddatetime") && has_header(im, "userprincipalname"))
            kind = "Graph sign-ins";
        else if (has_header(im, "activitydatetime") && has_header(im, "activitydisplayname"))
            kind = "Graph directory audit";
        else
            kind = "JSON events";
    }
    char *out = g_strdup(kind);
    g_free(owned);
    g_free(name);
    return out;
}

static gboolean target_principal(const char *clean) {
    if (!g_str_has_prefix(clean, "target") || !g_ascii_isdigit(clean[6]))
        return FALSE;
    const char *p = clean + 6;
    while (g_ascii_isdigit(*p))
        p++;
    return !strcmp(p, "userprincipalname");
}

static char *nested_text(const JV *record, const char *first, const char *second, const char *third) {
    const JV *value = j_get(record, first);
    if (second)
        value = j_get(value, second);
    if (third)
        value = j_get(value, third);
    return value && !j_is_container(value) ? j_text(value, TRUE) : g_strdup("");
}

static void prefer(char **slot, char *candidate) {
    if (**slot) {
        g_free(candidate);
        return;
    }
    g_free(*slot);
    *slot = candidate;
}

gboolean importer_begin(Importer *im, const char *sheet, GError **error) {
    (void)error;
    im->active = FALSE;
    im->log = 0;
    im->count = im->problems = 0;
    g_free(im->kind);
    im->kind = g_strdup(sheet);
    g_string_truncate(im->warnings, 0);
    g_ptr_array_set_size(im->verdicts, 0);
    return TRUE;
}

static gboolean start_log(Importer *im, GPtrArray *headers, GError **error) {
    char *sheet = im->kind;
    im->kind = NULL;
    g_hash_table_remove_all(im->positions);
    g_array_set_size(im->targets, 0);
    GString *packed = g_string_new("[");
    for (guint i = 0; i < headers->len; i++) {
        char *clean = clean_header(headers->pdata[i]);
        if (target_principal(clean))
            g_array_append_val(im->targets, i);
        if (g_hash_table_contains(im->positions, clean))
            g_free(clean);
        else
            g_hash_table_insert(im->positions, clean, GUINT_TO_POINTER(i));
        if (i)
            g_string_append_c(packed, ',');
        j_quote(packed, headers->pdata[i], -1);
    }
    g_string_append_c(packed, ']');
    im->width = headers->len;
    char *label = g_strconcat(im->name, " ", sheet, NULL);
    im->kind = detect(im, label);
    g_free(label);
    im->flat_audit = im->json && !has_header(im, "auditdata") && !strcmp(im->kind, "Purview audit");
    im->own_export = im->json && !strcmp(im->kind, "Timeline") && has_header(im, "record") && has_header(im, "verdict");
    sqlite3_stmt *insert = sql_prepare(im->db, "INSERT INTO logs(file,name,sheet,kind,headers) VALUES(?,?,?,?,?)", error);
    gboolean ok = FALSE;
    if (insert) {
        sqlite3_bind_int64(insert, 1, im->file_id);
        sqlite3_bind_text(insert, 2, im->name, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert, 3, sheet, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert, 4, im->kind, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert, 5, packed->str, -1, SQLITE_STATIC);
        ok = sqlite3_step(insert) == SQLITE_DONE;
        if (!ok)
            bec_fail(error, "%s", sqlite3_errmsg(im->db));
        sqlite3_finalize(insert);
        im->log = sqlite3_last_insert_rowid(im->db);
    }
    g_string_free(packed, TRUE);
    g_free(sheet);
    im->active = ok;
    return ok;
}

static void add_note(GString *notes, const char *note) {
    if (notes->len)
        g_string_append(notes, ", ");
    g_string_append(notes, note);
}

static void add_unique(GPtrArray *list, char *value) {
    for (guint i = 0; i < list->len; i++) {
        if (!strcmp(list->pdata[i], value)) {
            g_free(value);
            return;
        }
    }
    g_ptr_array_add(list, value);
}

static void add_address(GPtrArray *ips, const char *value) {
    if (!value || !*value)
        return;
    char *ip = ip_normalize(value);
    if (*ip)
        add_unique(ips, ip);
    else
        g_free(ip);
}

gboolean importer_row(Importer *im, GPtrArray *values, const char *raw, const JV *record, GError **error) {
    if (!im->log && !im->active) {
        // The first row names columns.
        if (im->count < 0)
            return TRUE;
        if (!values->len && !im->json) {
            im->count = -1;
            return TRUE;
        }
        return start_log(im, values, error);
    }
    if (!im->active)
        return TRUE;
    gint64 count = ++im->count;
    GString *notes = g_string_new(NULL);
    if (!im->json && values->len != im->width) {
        char *note = g_strdup_printf("Expected %u fields, found %u", im->width, values->len);
        add_note(notes, note);
        g_free(note);
    }
    JDoc *audit_doc = NULL;
    const JV *audit = NULL;
    if (im->flat_audit) {
        audit = record;
    } else if (!strcmp(im->kind, "Purview audit")) {
        const char *cell = GET(im, values, "auditdata");
        audit_doc = j_parse(cell, -1, 0, NULL);
        if (audit_doc && audit_doc->root->t == J_OBJ)
            audit = audit_doc->root;
        else
            add_note(notes, "Malformed AuditData");
    }
    char *actor = j_text(j_get(audit, "UserId"), FALSE);
    prefer(&actor, g_strdup(GET(im, values, "username", "userid", "actoruserprincipalname", "actorserviceprincipalname",
                                "actordisplayname", "service principal name", "sender_address", "senderaddress",
                                "sender address", "mailbox", "actor")));
    char *stamp = j_text(j_get(audit, "CreationTime"), FALSE);
    prefer(&stamp, g_strdup(GET(im, values, "date (utc)", "creationdate", "date", "date_time", "origin_timestamp",
                                "received", "time (utc)", "timestamp")));
    char *op = j_text(j_get(audit, "Operation"), FALSE);
    prefer(&op, g_strdup(GET(im, values, "operation", "activity", "authentication method", "event_id", "event")));
    char *result = j_text(j_get(audit, "ResultStatus"), FALSE);
    const JV *status = im->json ? j_get(record, "status") : NULL;
    if (status && status->t == J_OBJ) {
        // Graph nests the outcome.
        char *code = nested_text(record, "status", "errorCode", NULL);
        char *reason = nested_text(record, "status", "failureReason", NULL);
        if (*code)
            prefer(&result, g_strdup(!strcmp(code, "0") ? "Success" : *reason ? reason : "Failure"));
        g_free(code);
        g_free(reason);
    }
    prefer(&result, g_strdup(GET(im, values, "status", "result", "succeeded", "recipient_status")));
    char *request = NULL;
    {
        char *stripped = py_strip(GET(im, values, "request id"));
        request = g_utf8_strdown(stripped, -1);
        g_free(stripped);
    }
    GPtrArray *ips = g_ptr_array_new_with_free_func(g_free);
    static const char *const audit_ips[] = {"ClientIP", "ClientIPAddress", "ActorIpAddress"};
    for (guint i = 0; i < G_N_ELEMENTS(audit_ips); i++) {
        char *text = j_text(j_get(audit, audit_ips[i]), FALSE);
        add_address(ips, text);
        g_free(text);
    }
    static const char *const ip_columns[] = {"ip address", "ipaddress", "ip address (seen by resource)",
                                             "global secure access ip address", "original_client_ip", "client_ip", "ip"};
    for (guint i = 0; i < G_N_ELEMENTS(ip_columns); i++) {
        const char *cell = GET(im, values, ip_columns[i]);
        if (im->json && strstr(cell, ", ")) {
            char **parts = g_strsplit(cell, ", ", -1);
            for (char **part = parts; *part; part++)
                add_address(ips, *part);
            g_strfreev(parts);
        } else {
            add_address(ips, cell);
        }
    }
    if (im->json) {
        // JSON exports use other names.
        prefer(&actor, g_strdup(GET(im, values, "userprincipalname", "userdisplayname")));
        prefer(&actor, nested_text(record, "initiatedBy", "user", "userPrincipalName"));
        prefer(&actor, nested_text(record, "initiatedBy", "app", "displayName"));
        prefer(&stamp, g_strdup(GET(im, values, "createddatetime", "activitydatetime", "creationtime", "timegenerated",
                                    "eventdatetime")));
        prefer(&op, g_strdup(GET(im, values, "activitydisplayname", "operationname")));
        prefer(&result, g_strdup(GET(im, values, "resultstatus")));
        add_address(ips, GET(im, values, "clientip", "clientipaddress", "calleripaddress"));
        if (!*request && g_str_has_suffix(im->kind, " sign-ins")) {
            g_free(request);
            request = g_utf8_strdown(GET(im, values, "id"), -1);
        }
    }
    if (!*op)
        prefer(&op, g_strdup(im->kind));
    char *time = utc_normalize(stamp);
    if (*stamp && !*time)
        add_note(notes, "Unrecognized timestamp");
    GString *joined = g_string_new(NULL);
    for (guint i = 0; i < ips->len; i++)
        g_string_append_printf(joined, "%s%s", i ? ", " : "", (char *)ips->pdata[i]);
    char *packed = NULL;
    if (!raw) {
        GString *text = g_string_new("[");
        for (guint i = 0; i < values->len; i++) {
            if (i)
                g_string_append_c(text, ',');
            j_quote(text, values->pdata[i], -1);
        }
        g_string_append_c(text, ']');
        packed = g_string_free(text, FALSE);
    }
    sqlite3_stmt *event = im->event;
    sqlite3_bind_int64(event, 1, im->log);
    sqlite3_bind_int64(event, 2, im->json ? count : count + 1);
    sqlite3_bind_text(event, 3, time, -1, SQLITE_STATIC);
    sqlite3_bind_text(event, 4, actor, -1, SQLITE_STATIC);
    sqlite3_bind_text(event, 5, op, -1, SQLITE_STATIC);
    sqlite3_bind_text(event, 6, result, -1, SQLITE_STATIC);
    sqlite3_bind_text(event, 7, request, -1, SQLITE_STATIC);
    sqlite3_bind_text(event, 8, joined->str, -1, SQLITE_STATIC);
    sqlite3_bind_text(event, 9, raw ? raw : packed, -1, SQLITE_STATIC);
    sqlite3_bind_text(event, 10, notes->str, -1, SQLITE_STATIC);
    gboolean ok = sqlite3_step(event) == SQLITE_DONE;
    sqlite3_reset(event);
    gint64 id = sqlite3_last_insert_rowid(im->db);
    for (guint i = 0; ok && i < ips->len; i++) {
        sqlite3_bind_int64(im->ip, 1, id);
        sqlite3_bind_text(im->ip, 2, ips->pdata[i], -1, SQLITE_STATIC);
        ok = sqlite3_step(im->ip) == SQLITE_DONE;
        sqlite3_reset(im->ip);
    }
    // Collect identities for mailbox filters.
    GPtrArray *users = g_ptr_array_new_with_free_func(g_free);
    g_ptr_array_add(users, g_strdup(actor));
    g_ptr_array_add(users, j_text(j_get(audit, "MailboxOwnerUPN"), FALSE));
    g_ptr_array_add(users, g_strdup(GET(im, values, "actoruserprincipalname")));
    g_ptr_array_add(users, g_strdup(GET(im, values, "username")));
    for (guint i = 0; i < im->targets->len; i++) {
        guint index = g_array_index(im->targets, guint, i);
        if (index < values->len)
            g_ptr_array_add(users, g_strdup(values->pdata[index]));
    }
    char **recipients =
        g_strsplit(GET(im, values, "recipient_address", "recipientaddress", "recipient address", "recipient_status"), ";", -1);
    for (char **entry = recipients; *entry; entry++) {
        char *mark = strstr(*entry, "##");
        g_ptr_array_add(users, mark ? g_strndup(*entry, mark - *entry) : g_strdup(*entry));
    }
    g_strfreev(recipients);
    for (guint i = 0; ok && i < users->len; i++) {
        char *user = py_strip(users->pdata[i]);
        if (*user) {
            sqlite3_bind_int64(im->identity, 1, id);
            sqlite3_bind_text(im->identity, 2, user, -1, SQLITE_STATIC);
            ok = sqlite3_step(im->identity) == SQLITE_DONE;
            sqlite3_reset(im->identity);
        }
        g_free(user);
    }
    if (!ok)
        bec_fail(error, "%s", sqlite3_errmsg(im->db));
    if (ok && im->own_export) {
        const char *verdict = GET(im, values, "verdict");
        if (!strcmp(verdict, "Good") || !strcmp(verdict, "Bad") || !strcmp(verdict, "Unsure")) {
            g_ptr_array_add(im->verdicts, g_strdup_printf("%" G_GINT64_FORMAT, id));
            g_ptr_array_add(im->verdicts, g_strdup(verdict));
        }
    }
    im->problems += notes->len > 0;
    if (ok && count % 5000 == 0 && im->progress) {
        char *grouped = group_digits(count);
        char *message = g_strdup_printf("%s \xc2\xb7 %s rows", im->name, grouped);
        im->progress(message, im->progress_user);
        g_free(message);
        g_free(grouped);
    }
    g_ptr_array_free(users, TRUE);
    g_ptr_array_free(ips, TRUE);
    g_string_free(joined, TRUE);
    g_string_free(notes, TRUE);
    g_free(packed);
    g_free(actor);
    g_free(stamp);
    g_free(op);
    g_free(result);
    g_free(request);
    g_free(time);
    j_free(audit_doc);
    return ok;
}

void importer_warn(Importer *im, const char *warning) {
    if (im->warnings->len)
        g_string_append_c(im->warnings, ' ');
    g_string_append(im->warnings, warning);
}

gboolean importer_end(Importer *im, GError **error) {
    if (!im->active)
        return TRUE;
    gint64 cap = g_str_has_suffix(im->kind, " sign-ins") || g_str_has_suffix(im->kind, " auth details")
                     ? 100000
                     : !strcmp(im->kind, "Entra directory audit") ? 250000 : 0;
    if (cap && im->count >= cap) {
        char *records = group_digits(im->count), *limit = group_digits(cap);
        char *warning = g_strdup_printf("Possible truncation: %s records (portal limit %s).", records, limit);
        GString *all = g_string_new(warning);
        if (im->warnings->len)
            g_string_append_printf(all, " %s", im->warnings->str);
        g_string_assign(im->warnings, all->str);
        g_string_free(all, TRUE);
        g_free(warning);
        g_free(records);
        g_free(limit);
    }
    sqlite3_stmt *update = sql_prepare(im->db, "UPDATE logs SET total=?,issues=?,warning=? WHERE id=?", error);
    if (!update)
        return FALSE;
    sqlite3_bind_int64(update, 1, im->count);
    sqlite3_bind_int64(update, 2, im->problems);
    sqlite3_bind_text(update, 3, im->warnings->str, -1, SQLITE_STATIC);
    sqlite3_bind_int64(update, 4, im->log);
    gboolean ok = sqlite3_step(update) == SQLITE_DONE;
    if (!ok)
        bec_fail(error, "%s", sqlite3_errmsg(im->db));
    sqlite3_finalize(update);
    // Restore exported analyst verdicts.
    if (ok && im->verdicts->len) {
        gint64 batch = sql_int(im->db, "SELECT coalesce(max(batch),0)+1 FROM verdict_rules", NULL);
        sqlite3_stmt *rule = sql_prepare(im->db, "INSERT INTO verdict_rules(batch,kind,lo,hi,verdict) VALUES(?,'event',?,'',?)", error);
        for (guint i = 0; rule && ok && i + 1 < im->verdicts->len; i += 2) {
            sqlite3_bind_int64(rule, 1, batch);
            sqlite3_bind_text(rule, 2, im->verdicts->pdata[i], -1, SQLITE_STATIC);
            sqlite3_bind_text(rule, 3, im->verdicts->pdata[i + 1], -1, SQLITE_STATIC);
            ok = sqlite3_step(rule) == SQLITE_DONE;
            sqlite3_reset(rule);
        }
        ok = ok && rule;
        sqlite3_finalize(rule);
    }
    im->active = FALSE;
    return ok;
}

static gboolean sink_begin(const char *sheet, gpointer user, GError **error) {
    return importer_begin(user, sheet, error);
}

static gboolean sink_row(GPtrArray *values, gpointer user, GError **error) {
    return importer_row(user, values, NULL, NULL, error);
}

static gboolean sink_end(gpointer user, GError **error) {
    return importer_end(user, error);
}

static const char *extension(const char *path) {
    const char *dot = strrchr(path, '.');
    return dot ? dot : "";
}

gboolean import_supported(const char *path) {
    const char *suffix = extension(path);
    return !g_ascii_strcasecmp(suffix, ".csv") || !g_ascii_strcasecmp(suffix, ".xlsx") ||
           !g_ascii_strcasecmp(suffix, ".json");
}

static gboolean archive(sqlite3 *db, gint64 file_id, const char *data, gsize length, GError **error) {
    sqlite3_stmt *insert = sql_prepare(db, "INSERT INTO chunks VALUES(?,?,?)", error);
    if (!insert)
        return FALSE;
    uLongf room = compressBound(CHUNK);
    Bytef *buffer = g_malloc(room);
    gboolean ok = TRUE;
    for (gsize offset = 0, part = 0; ok && offset < length; offset += CHUNK, part++) {
        uLongf size = room;
        gsize take = MIN((gsize)CHUNK, length - offset);
        compress2(buffer, &size, (const Bytef *)data + offset, (uLong)take, 1);
        sqlite3_bind_int64(insert, 1, file_id);
        sqlite3_bind_int64(insert, 2, (gint64)part);
        sqlite3_bind_blob(insert, 3, buffer, (int)size, SQLITE_STATIC);
        ok = sqlite3_step(insert) == SQLITE_DONE;
        sqlite3_reset(insert);
    }
    if (!ok)
        bec_fail(error, "%s", sqlite3_errmsg(db));
    g_free(buffer);
    sqlite3_finalize(insert);
    return ok;
}

// Import each evidence file atomically.
ImportState import_file(sqlite3 *db, const char *path, ProgressFn progress, gpointer user, GError **error) {
    if (!import_supported(path)) {
        bec_fail(error, "Unsupported format");
        return IMPORT_FAILED;
    }
    char *data = NULL;
    gsize length = 0;
    if (!g_file_get_contents(path, &data, &length, error))
        return IMPORT_FAILED;
    char *digest = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (const guchar *)data, length);
    char *absolute = absolute_path(path);
    char *name = g_path_get_basename(path);
    ImportState state = IMPORT_FAILED;
    if (!sql_run(db, "BEGIN IMMEDIATE", error))
        goto done;
    sqlite3_stmt *known = sql_prepare(db, "SELECT 1 FROM files WHERE path=? AND digest=?", error);
    gboolean duplicate = FALSE, ok = known != NULL;
    if (known) {
        sqlite3_bind_text(known, 1, absolute, -1, SQLITE_STATIC);
        sqlite3_bind_text(known, 2, digest, -1, SQLITE_STATIC);
        duplicate = sqlite3_step(known) == SQLITE_ROW;
        sqlite3_finalize(known);
    }
    if (duplicate) {
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
        state = IMPORT_DUPLICATE;
        goto done;
    }
    Importer im = {0};
    im.db = db;
    im.name = name;
    im.progress = progress;
    im.progress_user = user;
    im.json = !g_ascii_strcasecmp(extension(path), ".json");
    im.positions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    im.targets = g_array_new(FALSE, FALSE, sizeof(guint));
    im.warnings = g_string_new(NULL);
    im.verdicts = g_ptr_array_new_with_free_func(g_free);
    sqlite3_stmt *file = ok ? sql_prepare(db, "INSERT INTO files(path,digest,size) VALUES(?,?,?)", error) : NULL;
    ok = file != NULL;
    if (file) {
        sqlite3_bind_text(file, 1, absolute, -1, SQLITE_STATIC);
        sqlite3_bind_text(file, 2, digest, -1, SQLITE_STATIC);
        sqlite3_bind_int64(file, 3, (gint64)length);
        ok = sqlite3_step(file) == SQLITE_DONE;
        if (!ok)
            bec_fail(error, "%s", sqlite3_errmsg(db));
        sqlite3_finalize(file);
        im.file_id = sqlite3_last_insert_rowid(db);
    }
    ok = ok && archive(db, im.file_id, data, length, error);
    if (ok) {
        im.event = sql_prepare(db, "INSERT INTO events(log,rownum,time,actor,op,result,request,ip,raw,issue) VALUES(?,?,?,?,?,?,?,?,?,?)", error);
        im.ip = sql_prepare(db, "INSERT INTO ips VALUES(?,?)", error);
        im.identity = sql_prepare(db, "INSERT OR IGNORE INTO identities VALUES(?,?)", error);
        ok = im.event && im.ip && im.identity;
    }
    if (ok) {
        RowSink sink = {sink_begin, sink_row, sink_end, &im};
        const char *suffix = extension(path);
        if (im.json)
            ok = json_import(&im, data, length, error);
        else if (!g_ascii_strcasecmp(suffix, ".xlsx"))
            ok = xlsx_read(data, length, &sink, error);
        else
            ok = csv_read(data, length, &sink, error);
    }
    if (ok) {
        sqlite3_stmt *logs = sql_prepare(db, "SELECT 1 FROM logs WHERE file=?", error);
        ok = logs != NULL;
        if (logs) {
            sqlite3_bind_int64(logs, 1, im.file_id);
            if (sqlite3_step(logs) != SQLITE_ROW) {
                bec_fail(error, "File contains no header row");
                ok = FALSE;
            }
            sqlite3_finalize(logs);
        }
    }
    sqlite3_finalize(im.event);
    sqlite3_finalize(im.ip);
    sqlite3_finalize(im.identity);
    g_hash_table_destroy(im.positions);
    g_array_free(im.targets, TRUE);
    g_string_free(im.warnings, TRUE);
    g_ptr_array_free(im.verdicts, TRUE);
    g_free(im.kind);
    if (ok && sql_run(db, "COMMIT", error)) {
        state = IMPORT_DONE;
    } else {
        // Leave the case unchanged.
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        if (error && !*error)
            bec_fail(error, "File could not be imported");
    }
done:
    g_free(data);
    g_free(digest);
    g_free(absolute);
    g_free(name);
    return state;
}

/* JSON events keep typed values. */

static gboolean json_fail(GError **error, const char *message, const char *path) {
    bec_fail(error, "%s%s%s", message, path ? " at " : "", path ? path : "");
    return FALSE;
}

gboolean json_import(Importer *im, const char *data, gsize length, GError **error) {
    gsize size = 0;
    char *text = decode_text(data, length, &size, error);
    if (!text)
        return FALSE;
    JDoc *doc = j_parse(text, (gssize)size, J_STRICT_KEYS, error);
    g_free(text);
    if (!doc)
        return FALSE;
    const JV *root = doc->root, *list = NULL;
    const char *sheet = "";
    const JV *single[1];
    guint count = 0;
    JV *const *events = NULL;
    gboolean ok = TRUE, more_pages = FALSE;
    if (root->t == J_ARR) {
        list = root;
    } else if (root->t == J_OBJ) {
        const JV *value = j_get(root, "value");
        gboolean wrapper = value && value->t == J_ARR;
        for (guint i = 0; wrapper && i < root->n; i++) {
            const char *key = root->u.m[i].key;
            if (strcmp(key, "value") && key[0] != '@') {
                // Events never wrap value arrays.
                gboolean objects = value->n > 0;
                for (guint k = 0; objects && k < value->n; k++)
                    objects = value->u.a[k]->t == J_OBJ;
                if (objects)
                    ok = json_fail(error, "Ambiguous JSON: a \"value\" array of records sits beside other fields. "
                                          "Export one event, an array of events, or a Microsoft Graph response",
                                   NULL);
                wrapper = FALSE;
            }
        }
        if (wrapper) {
            list = value;
            sheet = "/value";
            more_pages = j_get(root, "@odata.nextLink") != NULL;
        } else if (ok) {
            if (!root->n)
                ok = json_fail(error, "JSON object contains no fields", NULL);
            single[0] = root;
            events = (JV *const *)single;
            count = 1;
            sheet = "#";
        }
    } else {
        ok = json_fail(error, "Expected a JSON event object, an array of events, or a Graph \"value\" array", NULL);
    }
    if (ok && list) {
        events = list->u.a;
        count = list->n;
        for (guint i = 0; ok && i < count; i++) {
            if (events[i]->t != J_OBJ) {
                char *path = g_strdup_printf("%s/%u", sheet, i);
                ok = json_fail(error, "Expected an event object", path);
                g_free(path);
            }
        }
    }
    // Columns are first-seen keys.
    GPtrArray *headers = g_ptr_array_new();
    GHashTable *index = g_hash_table_new(g_str_hash, g_str_equal);
    for (guint i = 0; ok && i < count; i++) {
        for (guint k = 0; k < events[i]->n; k++) {
            const char *key = events[i]->u.m[k].key;
            if (!g_hash_table_contains(index, key)) {
                g_hash_table_insert(index, (gpointer)key, GUINT_TO_POINTER(headers->len));
                g_ptr_array_add(headers, (gpointer)key);
            }
        }
    }
    ok = ok && importer_begin(im, sheet, error) && importer_row(im, headers, NULL, NULL, error);
    GPtrArray *values = g_ptr_array_new_with_free_func(g_free);
    GString *raw = g_string_new(NULL);
    for (guint i = 0; ok && i < count; i++) {
        const JV *event = events[i];
        gboolean prefix = event->n <= headers->len;
        for (guint k = 0; prefix && k < event->n; k++)
            prefix = !strcmp(event->u.m[k].key, headers->pdata[k]);
        guint width = prefix ? event->n : headers->len;
        g_ptr_array_set_size(values, 0);
        for (guint k = 0; k < width; k++)
            g_ptr_array_add(values, NULL);
        g_string_assign(raw, "[");
        GString *present = prefix ? NULL : g_string_new("[");
        const JV **cells = g_new0(const JV *, MAX(width, 1));
        for (guint k = 0; k < event->n; k++) {
            guint position = GPOINTER_TO_UINT(g_hash_table_lookup(index, event->u.m[k].key));
            cells[position] = event->u.m[k].v;
            if (present)
                g_string_append_printf(present, "%s%u", k ? "," : "", position);
        }
        for (guint k = 0; k < width; k++) {
            if (k)
                g_string_append_c(raw, ',');
            if (cells[k])
                j_dump(raw, cells[k], J_RAW_NUMBERS);
            else
                g_string_append(raw, "null");
            values->pdata[k] = cells[k] ? j_text(cells[k], TRUE) : g_strdup("");
        }
        if (present) {
            g_string_append_printf(raw, "%s%s]", width ? "," : "", present->str);
            g_string_free(present, TRUE);
        }
        g_string_append_c(raw, ']');
        g_free(cells);
        ok = importer_row(im, values, raw->str, event, error);
    }
    if (ok && more_pages)
        importer_warn(im, "Possible truncation: this Graph response names a next page (@odata.nextLink).");
    ok = ok && importer_end(im, error);
    g_string_free(raw, TRUE);
    g_ptr_array_free(values, TRUE);
    g_ptr_array_free(headers, TRUE);
    g_hash_table_destroy(index);
    j_free(doc);
    return ok;
}
