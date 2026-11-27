#include "core.h"

#include <string.h>

#define CONSENT                                                                                               \
    "source = \"Entra directory audit\" AND (operation contains \"consent\" OR operation contains "          \
    "\"application\" OR operation contains \"service principal\" OR operation contains \"app role\" OR "     \
    "operation contains \"permission grant\")"

const Report REPORTS[] = {
    {"activity", "Activity over time", {"time"}, {"Interval start (UTC)"}, ""},
    {"indicators", "Investigation indicators", {"indicator"}, {"Recorded activity"}, ""},
    {"sources", "Log sources", {"source"}, {"Source"}, ""},
    {"files", "Evidence files", {"file"}, {"Filename"}, ""},
    {"operations", "Operations", {"operation"}, {"Operation"}, ""},
    {"endpoints", "IP endpoints", {"ip"}, {"IP address"}, ""},
    {"mailboxes", "Accounts and mailboxes", {"mailbox"}, {"Identity"}, ""},
    {"conversations", "Mail conversations", {"actor", "recipient"}, {"Sender", "Recipient"},
     "operation = \"Send\" OR operation = \"SendAs\" OR operation = \"SendOnBehalf\" OR source = \"Exchange trace\""},
    {"ip_accounts", "Account and IP pairs", {"actor", "ip"}, {"Account or actor", "IP address"}, ""},
    {"delivery", "Message trace results", {"delivery"}, {"Recorded delivery status"}, "source = \"Exchange trace\""},
    {"outcomes", "Sign-in outcomes", {"source", "result"}, {"Sign-in log", "Outcome"}, "source contains \"sign-ins\""},
    {"devices", "Devices", {"device"}, {"Device ID"}, ""},
    {"sessions", "Sessions", {"session"}, {"Session ID"}, ""},
    {"locations", "Sign-in locations", {"location"}, {"Location"}, ""},
    {"applications", "Applications", {"application"}, {"Application"}, ""},
    {"clients", "Client operating systems", {"os"}, {"Operating system"}, ""},
    {"methods", "Authentication steps", {"authmethod", "result"}, {"Method", "Recorded outcome"}, ""},
    {"policies", "Conditional Access", {"conditionalaccess"}, {"Recorded result"}, ""},
    {"rules", "Inbox rule changes", {"operation", "rule"}, {"Operation", "Rule name or identity"}, ""},
    {"access", "Mailbox access types", {"access"}, {"Access type"}, ""},
    {"folders", "Accessed folders", {"folder"}, {"Folder"}, ""},
    {"items", "Accessed mail items", {"mailitem"}, {"Message or item identifier"}, ""},
    {"consent", "Application and consent changes", {"operation", "result"}, {"Directory operation", "Result"}, CONSENT},
    {"marks", "Analyst-marked events", {"verdict", "source", "operation"}, {"Verdict", "Source", "Operation"},
     "marked = true"},
};
const int REPORT_COUNT = G_N_ELEMENTS(REPORTS);

const Report *report_find(const char *key) {
    for (int i = 0; i < REPORT_COUNT; i++)
        if (!strcmp(REPORTS[i].key, key))
            return &REPORTS[i];
    return NULL;
}

int report_width(const Report *report) {
    int width = 0;
    while (width < 3 && report->fields[width])
        width++;
    return width;
}

// Indicator categories can overlap.
static const struct {
    const char *label;
    gboolean result;
    gboolean contains;
    const char *values[6];
} INDICATORS[] = {
    {"Inbox rules created, modified or removed", FALSE, TRUE, {"InboxRule"}},
    {"Mailbox and transport configuration", FALSE, FALSE,
     {"Set-Mailbox", "Set-MailboxAutoReplyConfiguration", "New-TransportRule", "Set-TransportRule"}},
    {"Delegation and send permissions", FALSE, TRUE, {"MailboxPermission", "RecipientPermission", "FolderPermission"}},
    {"Messages sent", FALSE, FALSE, {"Send", "SendAs", "SendOnBehalf"}},
    {"Mailbox items accessed", FALSE, FALSE, {"MailItemsAccessed"}},
    {"Attachments accessed", FALSE, FALSE, {"AttachmentAccess"}},
    {"Messages deleted or moved to Deleted Items", FALSE, FALSE, {"HardDelete", "SoftDelete", "MoveToDeletedItems"}},
    {"Device registration or configuration", FALSE, TRUE, {"device"}},
    {"Password, credential or authentication changes", FALSE, TRUE,
     {"password", "security info", "authentication method", "credential", "refreshTokenValidFrom"}},
    {"Account enabled or disabled", FALSE, FALSE, {"Enable account", "Disable account"}},
    {"Application consent or permission grants", FALSE, TRUE,
     {"consent", "service principal", "app role", "permission grant"}},
    {"Failures and interrupted operations", TRUE, FALSE, {"Failure", "Failed", "ClientError", "Interrupted"}},
};

void stat_row_free(StatRow *row) {
    if (!row)
        return;
    for (int i = 0; i < 3; i++)
        g_free(row->values[i]);
    g_free(row->first);
    g_free(row->last);
    g_free(row);
}

void quality_row_free(QualityRow *row) {
    if (!row)
        return;
    g_free(row->name);
    g_free(row->sheet);
    g_free(row->kind);
    g_free(row->warning);
    g_free(row);
}

char *combine_filters(const char *first, const char *second) {
    if (first && *first && second && *second)
        return g_strdup_printf("(%s) AND (%s)", first, second);
    return g_strdup(first && *first ? first : second ? second : "");
}

static char *indicator_expression(const char *label) {
    GString *out = g_string_new(NULL);
    for (guint i = 0; i < G_N_ELEMENTS(INDICATORS); i++) {
        if (strcmp(INDICATORS[i].label, label))
            continue;
        for (int k = 0; k < 6 && INDICATORS[i].values[k]; k++) {
            char *quoted = j_quoted(INDICATORS[i].values[k]);
            g_string_append_printf(out, "%s%s %s %s", k ? " OR " : "", INDICATORS[i].result ? "result" : "operation",
                                   INDICATORS[i].contains ? "contains" : "=", quoted);
            g_free(quoted);
        }
    }
    return g_string_free(out, FALSE);
}

static gint compare_rows(gconstpointer left, gconstpointer right) {
    const StatRow *a = *(StatRow *const *)left, *b = *(StatRow *const *)right;
    if (a->count != b->count)
        return a->count > b->count ? -1 : 1;
    return strcmp(a->values[0], b->values[0]);
}

static GPtrArray *indicators(sqlite3 *db, gint64 log, const char *filter, GError **error) {
    GPtrArray *args = args_new();
    char *clause = where_sql(log, filter, args, error);
    if (!clause) {
        g_ptr_array_free(args, TRUE);
        return NULL;
    }
    char *sql = g_strconcat("SELECT e.op,e.result,count(*),min(nullif(e.time,'')),max(nullif(e.time,''))"
                            " FROM events e JOIN logs l ON l.id=e.log",
                            clause, " GROUP BY e.op COLLATE NOCASE,e.result COLLATE NOCASE", NULL);
    GPtrArray *rows = g_ptr_array_new_with_free_func((GDestroyNotify)stat_row_free);
    for (guint i = 0; i < G_N_ELEMENTS(INDICATORS); i++) {
        StatRow *row = g_new0(StatRow, 1);
        row->values[0] = g_strdup(INDICATORS[i].label);
        g_ptr_array_add(rows, row);
    }
    sqlite3_stmt *statement = sql_prepare(db, sql, error);
    gboolean ok = statement != NULL;
    if (statement) {
        args_bind(statement, args, 1);
        int state;
        while ((state = sqlite3_step(statement)) == SQLITE_ROW) {
            char *op = g_utf8_strdown(column_text(statement, 0), -1);
            char *result = g_utf8_strdown(column_text(statement, 1), -1);
            const char *first = (const char *)sqlite3_column_text(statement, 3);
            const char *last = (const char *)sqlite3_column_text(statement, 4);
            for (guint i = 0; i < G_N_ELEMENTS(INDICATORS); i++) {
                const char *value = INDICATORS[i].result ? result : op;
                gboolean hit = FALSE;
                for (int k = 0; k < 6 && INDICATORS[i].values[k] && !hit; k++) {
                    char *wanted = g_utf8_strdown(INDICATORS[i].values[k], -1);
                    hit = INDICATORS[i].contains ? strstr(value, wanted) != NULL : !strcmp(value, wanted);
                    g_free(wanted);
                }
                if (!hit)
                    continue;
                StatRow *row = rows->pdata[i];
                row->count += sqlite3_column_int64(statement, 2);
                if (first && *first && (!row->first || strcmp(first, row->first) < 0)) {
                    g_free(row->first);
                    row->first = g_strdup(first);
                }
                if (last && *last && (!row->last || strcmp(last, row->last) > 0)) {
                    g_free(row->last);
                    row->last = g_strdup(last);
                }
            }
            g_free(op);
            g_free(result);
        }
        if (state != SQLITE_DONE) {
            bec_fail(error, "%s", sqlite3_errmsg(db));
            ok = FALSE;
        }
        sqlite3_finalize(statement);
    }
    g_free(sql);
    g_free(clause);
    g_ptr_array_free(args, TRUE);
    if (!ok) {
        g_ptr_array_free(rows, TRUE);
        return NULL;
    }
    g_ptr_array_sort(rows, compare_rows);
    return rows;
}

static GPtrArray *collect(sqlite3 *db, const char *sql, GPtrArray *args, int width, gboolean activity, GError **error) {
    sqlite3_stmt *statement = sql_prepare(db, sql, error);
    if (!statement)
        return NULL;
    args_bind(statement, args, 1);
    GPtrArray *rows = g_ptr_array_new_with_free_func((GDestroyNotify)stat_row_free);
    int state;
    while ((state = sqlite3_step(statement)) == SQLITE_ROW) {
        StatRow *row = g_new0(StatRow, 1);
        for (int i = 0; i < width; i++) {
            if (activity)
                row->epoch = sqlite3_column_int64(statement, i);
            else
                row->values[i] = g_strdup(column_text(statement, i));
        }
        row->count = sqlite3_column_int64(statement, width);
        row->first = g_strdup((const char *)sqlite3_column_text(statement, width + 1));
        row->last = g_strdup((const char *)sqlite3_column_text(statement, width + 2));
        g_ptr_array_add(rows, row);
    }
    sqlite3_finalize(statement);
    if (state != SQLITE_DONE) {
        bec_fail(error, "%s", sqlite3_errmsg(db));
        g_ptr_array_free(rows, TRUE);
        return NULL;
    }
    return rows;
}

GPtrArray *stats_calculate(sqlite3 *db, const char *key, gint64 log, const char *filter, int interval,
                           GError **error) {
    const Report *report = report_find(key);
    if (!report) {
        bec_fail(error, "Unknown report");
        return NULL;
    }
    if (!filter)
        filter = "";
    if (!strcmp(key, "indicators"))
        return indicators(db, log, filter, error);
    gboolean files = !strcmp(key, "files");
    if ((files || !strcmp(key, "sources")) && !*filter &&
        sql_int(db, "SELECT count(*) FROM (SELECT 1 FROM logs WHERE kind='Timeline' LIMIT 1)", NULL) == 0) {
        // Labels can span exports.
        const char *label = files ? "l.name" : "source_label(l.kind)";
        char *sql = g_strdup_printf(
            "SELECT %s,sum(l.total),min((SELECT min(time) FROM events WHERE log=l.id AND time>'')),"
            "max((SELECT max(time) FROM events WHERE log=l.id AND time>'')) FROM logs l "
            "WHERE l.total>0 AND (?=0 OR l.id=?) GROUP BY %s COLLATE NOCASE ORDER BY sum(l.total) DESC,1",
            label, label);
        GPtrArray *args = args_new();
        args_int(args, log);
        args_int(args, log);
        GPtrArray *rows = collect(db, sql, args, 1, FALSE, error);
        g_ptr_array_free(args, TRUE);
        g_free(sql);
        return rows;
    }
    char *combined = combine_filters(filter, report->subset);
    GPtrArray *args = args_new(), *extra = args_new();
    char *where = where_sql(log, combined, args, error);
    g_free(combined);
    if (!where) {
        g_ptr_array_free(args, TRUE);
        g_ptr_array_free(extra, TRUE);
        return NULL;
    }
    GString *clause = g_string_new(where);
    g_free(where);
    GString *joins = g_string_new(" FROM events e JOIN logs l ON l.id=e.log");
    GString *select = g_string_new("SELECT ");
    GString *group = g_string_new(NULL);
    char *verdict = sql_verdict();
    GPtrArray *rows = NULL;
    gboolean empty = FALSE;
    int width = report_width(report);
    for (int index = 0; index < width && !empty; index++) {
        const char *field = report->fields[index];
        char *expr = NULL;
        gboolean simple = TRUE;
        if (!strcmp(field, "time")) {
            if (interval != 60 && interval != 900 && interval != 3600 && interval != 86400) {
                bec_fail(error, "Invalid interval");
                goto done;
            }
            // Avoid midnight rounding errors.
            const char *epoch = "unixepoch(substr(e.time,1,19))";
            expr = g_strdup_printf("%s-((%s%%%d+%d)%%%d)", epoch, epoch, interval, interval, interval);
        } else if (!strcmp(field, "source")) {
            expr = g_strdup(SQL_SOURCE);
        } else if (!strcmp(field, "operation")) {
            expr = g_strdup("trim(e.op)");
        } else if (!strcmp(field, "actor")) {
            expr = g_strdup("trim(e.actor)");
        } else if (!strcmp(field, "result")) {
            expr = g_strdup("trim(e.result)");
        } else if (!strcmp(field, "file")) {
            expr = g_strdup("l.name");
        } else if (!strcmp(field, "verdict")) {
            expr = g_strdup(verdict);
        } else if (!strcmp(field, "ip") || !strcmp(field, "mailbox")) {
            simple = FALSE;
            gboolean ip = !strcmp(field, "ip");
            g_string_append_printf(joins, " JOIN %s d%d ON d%d.event=e.id", ip ? "ips" : "identities", index, index);
            expr = g_strdup_printf("d%d.%s", index, ip ? "ip" : "value");
        } else {
            simple = FALSE;
            // Find logs containing this field.
            GString *branches = g_string_new(NULL);
            GString *marks = g_string_new(NULL);
            sqlite3_stmt *logs = sql_prepare(db, "SELECT id,headers,name FROM logs", error);
            if (!logs) {
                g_string_free(branches, TRUE);
                g_string_free(marks, TRUE);
                goto done;
            }
            const Slot *slot = slot_find(field);
            while (sqlite3_step(logs) == SQLITE_ROW) {
                gint64 id = sqlite3_column_int64(logs, 0);
                if (log && id != log)
                    continue;
                Columns *columns = columns_new(column_text(logs, 1));
                if (columns_support(columns, field)) {
                    g_string_append(marks, marks->len ? ",?" : "?");
                    args_int(args, id);
                    // Read unambiguous scalar columns directly.
                    int hits = 0, position = 0;
                    for (int i = 0; i < 5 && slot->outer[i]; i++) {
                        GArray *found = columns_get(columns, slot->outer[i]);
                        for (guint k = 0; found && k < found->len; k++, hits++)
                            position = g_array_index(found, int, k);
                    }
                    // JSON cells may hold objects.
                    gboolean nested = columns_support(columns, "rule") || log_is_json(column_text(logs, 2));
                    if (!nested && hits == 1 && strcmp(field, "recipient") && strcmp(field, "target") &&
                        strcmp(field, "delivery"))
                        g_string_append_printf(branches,
                                               "WHEN %" G_GINT64_FORMAT
                                               " THEN CASE WHEN json_type(e.raw,'$[%d]')='text' THEN "
                                               "json_array(trim(json_extract(e.raw,'$[%d]'))) ELSE json_array() END ",
                                               id, position, position);
                }
                columns_free(columns);
            }
            sqlite3_finalize(logs);
            if (!marks->len) {
                empty = TRUE;
            } else {
                g_string_append_printf(clause, " AND e.log IN (%s)", marks->str);
                if (branches->len)
                    g_string_append_printf(joins, " JOIN json_each(CASE e.log %sELSE event_values(l.headers,e.raw,?) END) d%d",
                                           branches->str, index);
                else
                    g_string_append_printf(joins, " JOIN json_each(event_values(l.headers,e.raw,?)) d%d", index);
                args_text(extra, field);
                g_string_append_printf(clause, " AND d%d.value IS NOT NULL AND d%d.value!=''", index, index);
                expr = g_strdup_printf("d%d.value", index);
            }
            g_string_free(branches, TRUE);
            g_string_free(marks, TRUE);
        }
        if (expr) {
            g_string_append_printf(select, "%s,", expr);
            if (simple)
                g_string_append_printf(clause, " AND %s IS NOT NULL AND %s!=''", expr, expr);
            g_string_append_printf(group, "%s%s COLLATE %s", index ? "," : "", expr,
                                   strcmp(field, "time") && strcmp(field, "ip") ? "BQL_TEXT" : "NOCASE");
        }
        g_free(expr);
    }
    if (empty) {
        rows = g_ptr_array_new_with_free_func((GDestroyNotify)stat_row_free);
        goto done;
    }
    gboolean activity = !strcmp(key, "activity");
    char *sql = g_strconcat(select->str, "count(*) AS frequency,min(nullif(e.time,'')),max(nullif(e.time,''))",
                            joins->str, clause->str, " GROUP BY ", group->str, " ORDER BY ",
                            activity ? "1" : "frequency DESC,1", NULL);
    // Join parameters precede filters.
    for (guint i = 0; i < args->len; i++) {
        Arg *arg = args->pdata[i];
        if (arg->integer)
            args_int(extra, arg->number);
        else
            args_text(extra, arg->text);
    }
    rows = collect(db, sql, extra, width, activity, error);
    g_free(sql);
done:
    g_free(verdict);
    g_string_free(clause, TRUE);
    g_string_free(joins, TRUE);
    g_string_free(select, TRUE);
    g_string_free(group, TRUE);
    g_ptr_array_free(args, TRUE);
    g_ptr_array_free(extra, TRUE);
    return rows;
}

char *stats_drilldown(const char *key, const StatRow *row, int interval) {
    if (!strcmp(key, "indicators"))
        return indicator_expression(row->values[0]);
    const Report *report = report_find(key);
    if (!strcmp(key, "activity")) {
        char *start = utc_from_epoch(row->epoch), *end = utc_from_epoch(row->epoch + interval);
        char *out = g_strdup_printf("time >= \"%s\" AND time < \"%s\"", start, end);
        g_free(start);
        g_free(end);
        return out;
    }
    GString *filters = g_string_new(NULL);
    for (int i = 0; i < report_width(report); i++) {
        char *quoted = j_quoted(row->values[i]);
        g_string_append_printf(filters, "%s%s = %s", i ? " AND " : "", report->fields[i], quoted);
        g_free(quoted);
    }
    char *out = combine_filters(report->subset, filters->str);
    g_string_free(filters, TRUE);
    return out;
}

GPtrArray *stats_quality(sqlite3 *db, GError **error) {
    sqlite3_stmt *logs = sql_prepare(db, "SELECT id,name,sheet,kind,total,issues,warning FROM logs ORDER BY id", error);
    if (!logs)
        return NULL;
    GPtrArray *rows = g_ptr_array_new_with_free_func((GDestroyNotify)quality_row_free);
    while (sqlite3_step(logs) == SQLITE_ROW) {
        QualityRow *row = g_new0(QualityRow, 1);
        row->id = sqlite3_column_int64(logs, 0);
        row->name = g_strdup(column_text(logs, 1));
        row->sheet = g_strdup(column_text(logs, 2));
        row->kind = g_strdup(column_text(logs, 3));
        row->total = sqlite3_column_int64(logs, 4);
        row->issues = sqlite3_column_int64(logs, 5);
        row->warning = g_strdup(column_text(logs, 6));
        row->linked = row->missing = -1;
        if (g_str_has_suffix(row->kind, "auth details")) {
            GString *parent = g_string_new(row->kind);
            g_string_replace(parent, "auth details", "sign-ins", 0);
            sqlite3_stmt *linked = sql_prepare(
                db,
                "SELECT count(*) FROM events e WHERE e.log=? AND e.request!='' AND EXISTS (SELECT 1 FROM events p "
                "JOIN logs l ON p.log=l.id WHERE p.request!='' AND p.request=e.request AND l.kind=?)",
                NULL);
            if (linked) {
                sqlite3_bind_int64(linked, 1, row->id);
                sqlite3_bind_text(linked, 2, parent->str, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(linked) == SQLITE_ROW) {
                    row->linked = sqlite3_column_int64(linked, 0);
                    row->missing = row->total - row->linked;
                }
                sqlite3_finalize(linked);
            }
            g_string_free(parent, TRUE);
        }
        g_ptr_array_add(rows, row);
    }
    sqlite3_finalize(logs);
    return rows;
}
