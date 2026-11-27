#include "server.h"
#include <glib/gstdio.h>
#include <string.h>

typedef enum { BQL, LOG, OFFSET, LIMIT, EVENT, REPORT, FORMAT, MAILBOX, START, CONTAINMENT, END, PARAM_COUNT } Param;
typedef struct { const char *key, *description; int minimum, maximum; } Parameter;
static const Parameter parameters[] = {
    {"bql", "Analyzer display filter. Empty includes all events.", 0, 0},
    {"log_id", "Log ID from case_overview. Zero searches every log.", 0, G_MAXINT},
    {"offset", "Number of entries to skip. For inspect_event, Unicode characters to skip.", 0, G_MAXINT},
    {"limit", "Page size from 1 to 100. Default 25.", 1, 100},
    {"event_key", "Stable event key returned by search_events.", 1, G_MAXINT},
    {"report", "Investigation report to calculate.", 0, 0},
    {"format", "Output file format.", 0, 0},
    {"mailbox", "Mailbox identity to review.", 0, 0},
    {"start_utc", "Inclusive UTC start, e.g. 2026-01-01T00:00:00Z.", 0, 0},
    {"containment_utc", "Time the responder applied containment, in UTC.", 0, 0},
    {"end_utc", "Exclusive UTC end of review.", 0, 0}
};
#define BIT(p) (1u << (p))
#define SCOPE (BIT(BQL) | BIT(LOG))
#define PAGE (BIT(OFFSET) | BIT(LIMIT))
#define WINDOW (BIT(MAILBOX) | BIT(START) | BIT(CONTAINMENT) | BIT(END))

typedef Json *(*Handler)(JsonDoc *, Session *, Input *, GError **);
static Json *overview(JsonDoc *, Session *, Input *, GError **);
static Json *search(JsonDoc *, Session *, Input *, GError **);
static Json *inspect(JsonDoc *, Session *, Input *, GError **);
static Json *statistics(JsonDoc *, Session *, Input *, GError **);
static Json *export_matches(JsonDoc *, Session *, Input *, GError **);

static const struct Tool {
    const char *name, *description;
    unsigned allowed, required;
    Handler run;
} tools[] = {
    {"case_overview", "List source logs, SHA-256 hashes, row counts, import issues and truncation warnings. Page with offset and limit.", PAGE, 0, overview},
    {"search_events", "Search the UTC timeline with BQL. Returns source references, verdicts and stable event keys.", SCOPE | PAGE, 0, search},
    {"inspect_event", "Read source headers and stored row values by stable event key. Large records return paged JSON text.", BIT(EVENT) | BIT(OFFSET), BIT(EVENT), inspect},
    {"case_statistics", "Group evidence by sign-in outcomes, IPs, devices, inbox rules, mailbox access, consent, or other named reports. Each group includes its BQL drilldown.", SCOPE | PAGE | BIT(REPORT), BIT(REPORT), statistics},
    {"compare_containment", "Compare mailbox activity before and after a known containment time. Returns bounded UTC windows, observed counts, and reproducible evidence filters.", WINDOW, WINDOW, compare_containment},
    {"export_events", "Write matching events to a new file in the operator's export directory.", SCOPE | BIT(FORMAT), BIT(FORMAT), export_matches}
};

static gboolean enabled(const struct Tool *tool, const Session *session) {
    return tool->run != export_matches || session->export_dir;
}

Json *list_tools(JsonDoc *doc, const Session *session) {
    Json *list = yyjson_mut_arr(doc);
    for (guint i = 0; i < G_N_ELEMENTS(tools); i++) {
        const struct Tool *tool = &tools[i];
        if (!enabled(tool, session)) continue;
        Json *entry = yyjson_mut_arr_add_obj(doc, list);
        put_text(doc, entry, "name", tool->name);
        put_text(doc, entry, "description", tool->description);
        Json *schema = yyjson_mut_obj_add_obj(doc, entry, "inputSchema");
        put_text(doc, schema, "type", "object");
        yyjson_mut_obj_add_bool(doc, schema, "additionalProperties", false);
        Json *properties = yyjson_mut_obj_add_obj(doc, schema, "properties");
        Json *required = yyjson_mut_obj_add_arr(doc, schema, "required");
        for (int p = 0; p < PARAM_COUNT; p++) {
            if (!(tool->allowed & BIT(p))) continue;
            const Parameter *spec = &parameters[p];
            Json *prop = yyjson_mut_obj_add_obj(doc, properties, spec->key);
            put_text(doc, prop, "type", spec->maximum ? "integer" : "string");
            put_text(doc, prop, "description", spec->description);
            if (spec->maximum) {
                yyjson_mut_obj_add_int(doc, prop, "minimum", spec->minimum);
                yyjson_mut_obj_add_int(doc, prop, "maximum", spec->maximum);
            } else if (p == REPORT || p == FORMAT) {
                Json *choices = yyjson_mut_obj_add_arr(doc, prop, "enum");
                if (p == REPORT)
                    for (int r = 0; r < REPORT_COUNT; r++) yyjson_mut_arr_add_str(doc, choices, REPORTS[r].key);
                else {
                    yyjson_mut_arr_add_str(doc, choices, "csv");
                    yyjson_mut_arr_add_str(doc, choices, "xlsx");
                    yyjson_mut_arr_add_str(doc, choices, "json");
                }
            } else yyjson_mut_obj_add_int(doc, prop, "maxLength", 2048);
            if (tool->required & BIT(p)) yyjson_mut_arr_add_str(doc, required, spec->key);
        }
        Json *annotations = yyjson_mut_obj_add_obj(doc, entry, "annotations");
        yyjson_mut_obj_add_bool(doc, annotations, "readOnlyHint", tool->run != export_matches);
        yyjson_mut_obj_add_bool(doc, annotations, "destructiveHint", false);
        yyjson_mut_obj_add_bool(doc, annotations, "openWorldHint", false);
    }
    return list;
}

static const char *string_arg(Input *args, Param p) {
    const char *value = yyjson_get_str(yyjson_obj_get(args, parameters[p].key));
    return value ? value : "";
}

static gint64 integer_arg(Input *args, Param p) {
    Input *value = yyjson_obj_get(args, parameters[p].key);
    return value ? yyjson_get_sint(value) : (p == LIMIT ? 25 : 0);
}

static gboolean valid_args(const struct Tool *tool, Input *args, GError **error) {
    size_t index, count;
    Input *key, *value;
    unsigned supplied = 0;
    yyjson_obj_foreach(args, index, count, key, value) {
        int p = 0;
        while (p < PARAM_COUNT && !yyjson_equals_str(key, parameters[p].key)) p++;
        if (p == PARAM_COUNT || !(tool->allowed & BIT(p)) || (supplied & BIT(p))) {
            bec_fail(error, "Unexpected or duplicate argument");
            return FALSE;
        }
        const Parameter *spec = &parameters[p];
        gboolean valid = spec->maximum
            ? yyjson_is_uint(value) && yyjson_get_uint(value) >= (unsigned)spec->minimum &&
              yyjson_get_uint(value) <= (unsigned)spec->maximum
            : yyjson_is_str(value) && yyjson_get_len(value) == strlen(yyjson_get_str(value)) &&
              g_utf8_strlen(yyjson_get_str(value), -1) <= 2048;
        if (!valid) {
            bec_fail(error, "Invalid %s", spec->key);
            return FALSE;
        }
        supplied |= BIT(p);
    }
    if ((supplied & tool->required) != tool->required) {
        bec_fail(error, "Missing required tool argument");
        return FALSE;
    }
    return TRUE;
}

Json *call_tool(JsonDoc *doc, Session *session, const char *name, Input *args, GError **error) {
    for (guint i = 0; i < G_N_ELEMENTS(tools); i++) {
        const struct Tool *tool = &tools[i];
        if (strcmp(tool->name, name) || !enabled(tool, session)) continue;
        if (!valid_args(tool, args, error) || !sql_run(session->db, "BEGIN", error)) return NULL;
        Json *result = tool->run(doc, session, args, error);
        sql_run(session->db, "ROLLBACK", NULL);
        return result;
    }
    bec_fail(error, "Unknown or disabled tool");
    return NULL;
}

static void page_end(JsonDoc *doc, Json *result, gint64 next, gboolean more) {
    if (more) yyjson_mut_obj_add_int(doc, result, "next_offset", next);
    else yyjson_mut_obj_add_null(doc, result, "next_offset");
}

static Json *source_coverage(JsonDoc *doc, sqlite3 *db, GError **error) {
    const char *families[] = {"sign_ins", "authentication_details", "directory_audit", "purview_audit",
                              "exchange_trace", "combined_timeline", "other"};
    gint64 logs[G_N_ELEMENTS(families)] = {0}, records[G_N_ELEMENTS(families)] = {0};
    sqlite3_stmt *st = sql_prepare(db, "SELECT kind,count(*),sum(total) FROM logs GROUP BY kind", error);
    if (!st) return NULL;
    int state;
    while ((state = sqlite3_step(st)) == SQLITE_ROW) {
        const char *kind = column_text(st, 0);
        size_t index = 6;
        if (g_str_has_suffix(kind, "sign-ins")) index = 0;
        else if (g_str_has_suffix(kind, "auth details")) index = 1;
        else if (g_str_has_suffix(kind, "directory audit")) index = 2;
        else if (!strcmp(kind, "Purview audit")) index = 3;
        else if (!strcmp(kind, "Exchange trace")) index = 4;
        else if (!strcmp(kind, "Timeline")) index = 5;
        logs[index] += sqlite3_column_int64(st, 1);
        records[index] += sqlite3_column_int64(st, 2);
    }
    if (state != SQLITE_DONE) bec_fail(error, "%s", sqlite3_errmsg(db));
    sqlite3_finalize(st);
    Json *coverage = yyjson_mut_obj(doc);
    for (size_t i = 0; i < G_N_ELEMENTS(families); i++) {
        Json *entry = yyjson_mut_obj_add_obj(doc, coverage, families[i]);
        put_text(doc, entry, "status", !logs[i] ? "not identified" : records[i] ? "records present" : "header only");
        yyjson_mut_obj_add_int(doc, entry, "logs", logs[i]);
        yyjson_mut_obj_add_int(doc, entry, "records", records[i]);
    }
    return coverage;
}

static Json *overview(JsonDoc *doc, Session *session, Input *args, GError **error) {
    sqlite3_stmt *st = sql_prepare(session->db,
        "SELECT l.id,l.name,l.sheet,l.kind,l.total,l.issues,l.warning,f.digest,"
        "(SELECT min(time) FROM events WHERE log=l.id AND time>''),"
        "(SELECT max(time) FROM events WHERE log=l.id AND time>''),"
        "(SELECT count(*) FROM events WHERE log=l.id AND time='') FROM logs l "
        "JOIN files f ON f.id=l.file ORDER BY l.id LIMIT ? OFFSET ?", error);
    if (!st) return NULL;
    gint64 offset = integer_arg(args, OFFSET), limit = integer_arg(args, LIMIT);
    sqlite3_bind_int64(st, 1, limit + 1);
    sqlite3_bind_int64(st, 2, offset);
    Json *result = yyjson_mut_obj(doc), *logs = yyjson_mut_obj_add_arr(doc, result, "logs");
    int state;
    while ((state = sqlite3_step(st)) == SQLITE_ROW && yyjson_mut_arr_size(logs) < (size_t)limit) {
        Json *log = yyjson_mut_arr_add_obj(doc, logs);
        yyjson_mut_obj_add_int(doc, log, "log_id", sqlite3_column_int64(st, 0));
        put_text(doc, log, "file", column_text(st, 1));
        put_text(doc, log, "sheet", column_text(st, 2));
        char *label = source_label(column_text(st, 3));
        put_text(doc, log, "source", label);
        g_free(label);
        yyjson_mut_obj_add_int(doc, log, "records", sqlite3_column_int64(st, 4));
        yyjson_mut_obj_add_int(doc, log, "issues", sqlite3_column_int64(st, 5));
        put_text(doc, log, "warning", column_text(st, 6));
        put_text(doc, log, "sha256", column_text(st, 7));
        put_text(doc, log, "first_observed_utc", (const char *)sqlite3_column_text(st, 8));
        put_text(doc, log, "last_observed_utc", (const char *)sqlite3_column_text(st, 9));
        yyjson_mut_obj_add_int(doc, log, "undated", sqlite3_column_int64(st, 10));
    }
    if (state != SQLITE_DONE && state != SQLITE_ROW) bec_fail(error, "%s", sqlite3_errmsg(session->db));
    page_end(doc, result, offset + limit, state == SQLITE_ROW);
    sqlite3_finalize(st);
    if (!*error) {
        Json *coverage = source_coverage(doc, session->db, error);
        if (coverage) yyjson_mut_obj_add_val(doc, result, "case_source_coverage", coverage);
    }
    return result;
}

static Json *search(JsonDoc *doc, Session *session, Input *args, GError **error) {
    GPtrArray *bindings = args_new();
    char *select = select_sql(NULL, bindings);
    char *where = where_sql(integer_arg(args, LOG), string_arg(args, BQL), bindings, error);
    sqlite3_stmt *st = NULL;
    gint64 limit = integer_arg(args, LIMIT), offset = integer_arg(args, OFFSET);
    if (where) {
        char *sql = g_strconcat(select, where, " ORDER BY (e.time=''),e.time,e.id LIMIT ? OFFSET ?", NULL);
        args_int(bindings, limit + 1);
        args_int(bindings, offset);
        st = sql_prepare(session->db, sql, error);
        if (st) args_bind(st, bindings, 1);
        g_free(sql);
    }
    g_free(select);
    g_free(where);
    g_ptr_array_free(bindings, TRUE);
    if (!st) return NULL;

    Json *result = yyjson_mut_obj(doc), *events = yyjson_mut_obj_add_arr(doc, result, "events");
    const char *columns[] = {"event_key","source_row","utc","actor","operation","result","ip","issue",
                            "log_kind","file","sheet","source","timeline_id","verdict","verdict_reason"};
    int state;
    while ((state = sqlite3_step(st)) == SQLITE_ROW && yyjson_mut_arr_size(events) < (size_t)limit) {
        Json *event = yyjson_mut_arr_add_obj(doc, events);
        for (guint i = 0; i < G_N_ELEMENTS(columns); i++) {
            if (sqlite3_column_type(st, i) == SQLITE_INTEGER)
                yyjson_mut_obj_add_int(doc, event, columns[i], sqlite3_column_int64(st, i));
            else put_text(doc, event, columns[i], column_text(st, i));
        }
        char *location = source_location(column_text(st, 9), column_text(st, 10), sqlite3_column_int64(st, 1));
        put_text(doc, event, "location", location);
        g_free(location);
    }
    if (state != SQLITE_DONE && state != SQLITE_ROW) bec_fail(error, "%s", sqlite3_errmsg(session->db));
    page_end(doc, result, offset + limit, state == SQLITE_ROW);
    sqlite3_finalize(st);
    return result;
}

static Json *json_record(JsonDoc *doc, Input *headers, Input *cells) {
    Json *record = yyjson_mut_obj(doc);
    size_t width = yyjson_arr_size(headers);
    Input *present = yyjson_arr_size(cells) == width + 1 ? yyjson_arr_get(cells, width) : NULL;
    gboolean sparse = yyjson_is_arr(present);
    size_t count = sparse ? yyjson_arr_size(present) : MIN(width, yyjson_arr_size(cells));
    for (size_t i = 0; i < count; i++) {
        size_t column = sparse ? yyjson_get_uint(yyjson_arr_get(present, i)) : i;
        Input *key = yyjson_arr_get(headers, column), *value = yyjson_arr_get(cells, column);
        if (yyjson_is_str(key) && value)
            yyjson_mut_obj_add(record, yyjson_val_mut_copy(doc, key), yyjson_val_mut_copy(doc, value));
    }
    return record;
}

static Json *inspect(JsonDoc *doc, Session *session, Input *args, GError **error) {
    const int chunk = 8192;
    sqlite3_stmt *st = sql_prepare(session->db,
        "SELECT l.name,l.sheet,e.rownum,f.digest,length(l.headers),length(e.raw),"
        "substr(l.headers,?1,?2),substr(e.raw,?1,?2) FROM events e JOIN logs l ON l.id=e.log "
        "JOIN files f ON f.id=l.file WHERE e.id=?3", error);
    if (!st) return NULL;
    gint64 offset = integer_arg(args, OFFSET);
    sqlite3_bind_int64(st, 1, offset + 1);
    sqlite3_bind_int(st, 2, chunk);
    sqlite3_bind_int64(st, 3, integer_arg(args, EVENT));
    int state = sqlite3_step(st);
    Json *result = yyjson_mut_obj(doc);
    if (state == SQLITE_ROW) {
        char *location = source_location(column_text(st, 0), column_text(st, 1), sqlite3_column_int64(st, 2));
        put_text(doc, result, "location", location);
        g_free(location);
        put_text(doc, result, "sha256", column_text(st, 3));
        yyjson_mut_obj_add_int(doc, result, "event_key", integer_arg(args, EVENT));
        gint64 length = MAX(sqlite3_column_int64(st, 4), sqlite3_column_int64(st, 5));
        gboolean fragments = offset || length > chunk;
        const char *names = column_text(st, 6), *values = column_text(st, 7);
        yyjson_doc *headers = fragments ? NULL : yyjson_read(names, strlen(names), 0);
        yyjson_doc *cells = fragments ? NULL : yyjson_read(values, strlen(values), 0);
        if (!headers || !cells) {
            put_text(doc, result, "headers_json_fragment", names);
            put_text(doc, result, "values_json_fragment", values);
        } else if (log_is_json(column_text(st, 0))) {
            Json *record = json_record(doc, yyjson_doc_get_root(headers), yyjson_doc_get_root(cells));
            yyjson_mut_obj_add_val(doc, result, "record", record);
        } else {
            yyjson_mut_obj_add_val(doc, result, "headers", yyjson_val_mut_copy(doc, yyjson_doc_get_root(headers)));
            yyjson_mut_obj_add_val(doc, result, "values", yyjson_val_mut_copy(doc, yyjson_doc_get_root(cells)));
        }
        yyjson_doc_free(headers);
        yyjson_doc_free(cells);
        page_end(doc, result, offset + chunk, offset + chunk < length);
    } else if (state == SQLITE_DONE) bec_fail(error, "Unknown event key");
    else bec_fail(error, "%s", sqlite3_errmsg(session->db));
    sqlite3_finalize(st);
    return result;
}

static Json *statistics(JsonDoc *doc, Session *session, Input *args, GError **error) {
    const char *key = string_arg(args, REPORT), *filter = string_arg(args, BQL);
    const Report *report = report_find(key);
    if (!report) { bec_fail(error, "Unknown report"); return NULL; }
    gint64 log = integer_arg(args, LOG);
    GPtrArray *rows = stats_calculate(session->db, key, log, filter, 3600, error);
    if (!rows) return NULL;
    Json *result = yyjson_mut_obj(doc), *groups = yyjson_mut_obj_add_arr(doc, result, "groups");
    yyjson_mut_obj_add_int(doc, result, "log_id", log);
    gint64 offset = integer_arg(args, OFFSET), end = MIN(offset + integer_arg(args, LIMIT), rows->len);
    for (gint64 i = offset; i < end; i++) {
        StatRow *row = rows->pdata[i];
        Json *group = yyjson_mut_arr_add_obj(doc, groups);
        Json *values = yyjson_mut_obj_add_obj(doc, group, "dimensions");
        for (int j = 0; j < report_width(report); j++) {
            if (!strcmp(report->fields[j], "time")) {
                char *start = utc_from_epoch(row->epoch);
                put_text(doc, values, "time", start);
                g_free(start);
            } else put_text(doc, values, report->fields[j], row->values[j]);
        }
        yyjson_mut_obj_add_int(doc, group, "count", row->count);
        put_text(doc, group, "first_utc", row->first);
        put_text(doc, group, "last_utc", row->last);
        char *group_filter = stats_drilldown(key, row, 3600);
        char *drill = combine_filters(filter, group_filter);
        put_text(doc, group, "bql", drill);
        g_free(group_filter);
        g_free(drill);
    }
    page_end(doc, result, end, end < rows->len);
    g_ptr_array_free(rows, TRUE);
    return result;
}

static Json *export_matches(JsonDoc *doc, Session *session, Input *args, GError **error) {
    const char *format = string_arg(args, FORMAT);
    if (strcmp(format, "csv") && strcmp(format, "xlsx") && strcmp(format, "json")) {
        bec_fail(error, "Choose csv, xlsx, or json");
        return NULL;
    }
    char *folder = g_build_filename(session->export_dir, "export-XXXXXX", NULL);
    if (!g_mkdtemp(folder)) {
        bec_fail(error, "Could not create export directory");
        g_free(folder);
        return NULL;
    }
    char *filename = g_strdup_printf("timeline.%s", format);
    char *path = g_build_filename(folder, filename, NULL);
    Json *result = yyjson_mut_obj(doc);
    if (export_events(session->db, path, integer_arg(args, LOG), string_arg(args, BQL), FALSE, "time", NULL, error))
        put_text(doc, result, "path", path);
    else g_rmdir(folder);
    g_free(path);
    g_free(filename);
    g_free(folder);
    return result;
}
