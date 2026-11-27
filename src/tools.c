#include "server.h"
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { TEXT, NUMBER, TEXTS, NUMBERS, FLAG } Kind;
typedef enum { BQL, LOG, OFFSET, LIMIT, FIELDS, ORDER, EVENT, FIELD, REPORT, FORMAT, MAILBOX, START, CONTAINMENT, END,
               VERDICT, IPS, KEYS, UNDO, PARAM_COUNT } Param;
typedef struct { const char *key, *description; Kind kind; int minimum, maximum; const char *choices; } Parameter;
static const Parameter parameters[] = {
    {"bql", "Display filter", TEXT, 0, 0, NULL}, {"log_id", NULL, NUMBER, 0, G_MAXINT, NULL},
    {"offset", "Use next_offset", NUMBER, 0, G_MAXINT, NULL}, {"limit", NULL, NUMBER, 1, 200, NULL},
    {"fields", "Extra columns: field names or /Header/nested paths", TEXTS, 1, 8, NULL},
    {"order", NULL, TEXT, 0, 0, "asc,desc"}, {"event_key", NULL, NUMBER, 1, G_MAXINT, NULL},
    {"field", "Path such as /AuditData/Item", TEXT, 0, 0, NULL}, {"reports", NULL, TEXTS, 1, 8, ""},
    {"format", NULL, TEXT, 0, 0, "csv,xlsx,json"}, {"mailbox", NULL, TEXT, 0, 0, NULL},
    {"start_utc", "Inclusive ISO time ending in Z", TEXT, 0, 0, NULL}, {"containment_utc", NULL, TEXT, 0, 0, NULL},
    {"end_utc", "Exclusive", TEXT, 0, 0, NULL}, {"verdict", NULL, TEXT, 0, 0, "Good,Bad,Unsure,Unmarked"},
    {"ips", NULL, TEXTS, 1, 100, NULL}, {"event_keys", NULL, NUMBERS, 1, 500, NULL},
    {"undo", "Revert the last mark", FLAG, 0, 0, NULL}
};
#define BIT(p) (1u << (p))
#define SCOPE (BIT(BQL) | BIT(LOG))
#define PAGE (BIT(OFFSET) | BIT(LIMIT))
#define WINDOW (BIT(MAILBOX) | BIT(START) | BIT(CONTAINMENT) | BIT(END))
#define BUDGET 12000
#define CELL 192

typedef Json *(*Handler)(JsonDoc *, Session *, Input *, GError **);
static Json *overview(JsonDoc *, Session *, Input *, GError **);
static Json *search(JsonDoc *, Session *, Input *, GError **);
static Json *inspect(JsonDoc *, Session *, Input *, GError **);
static Json *statistics(JsonDoc *, Session *, Input *, GError **);
static Json *mark(JsonDoc *, Session *, Input *, GError **);
static Json *export_matches(JsonDoc *, Session *, Input *, GError **);

static const struct Tool {
    const char *name, *description;
    unsigned allowed, required;
    Handler run;
} tools[] = {
    {"case_overview", "Start here. Logs with hashes, date coverage, warnings, missing sources and mark counts.",
     PAGE, 0, overview},
    {"search_events", NULL, SCOPE | PAGE | BIT(FIELDS) | BIT(ORDER), 0, search},
    {"inspect_event", "One source record as nested JSON without empty values. Pass field for one subtree or value.",
     BIT(EVENT) | BIT(OFFSET) | BIT(FIELD), BIT(EVENT), inspect},
    {"case_statistics", "Grouped counts for several reports in one call. Drill down in search_events with "
     "dimension = \"value\", plus scope when given.", SCOPE | PAGE | BIT(REPORT), BIT(REPORT), statistics},
    {"compare_containment", "Compare mailbox activity across a containment timestamp.", WINDOW, WINDOW,
     compare_containment},
    {"mark_events", "Set a verdict on events matching bql, on ips, on event_keys, or on start_utc to end_utc. "
     "undo reverts the last mark.", SCOPE | BIT(VERDICT) | BIT(IPS) | BIT(KEYS) | BIT(START) | BIT(END) | BIT(UNDO),
     0, mark},
    {"export_events", "Save filtered events to the export directory. XLSX rows carry verdict colours.",
     SCOPE | BIT(FORMAT) | BIT(FIELDS), BIT(FORMAT), export_matches}
};

static gboolean enabled(const struct Tool *tool, const Session *session) {
    if (tool->run == export_matches) return session->export_dir != NULL;
    return tool->run != mark || session->allow_marks;
}

// Search teaches the filter language.
static char *search_help(void) {
    char *fields = bql_field_list();
    char *text = g_strdup_printf(
        "Search the UTC timeline. Rows: key, utc, actor, operation, result, ip, log, row, verdict, then fields. "
        "BQL: field op value with = != contains < <= > >=, joined by AND OR NOT and parentheses; text in double "
        "quotes. Nested: field \"/AuditData/ClientIP\" = \"x\", exists \"/path\", * for any array item. "
        "raw contains \"x\" searches whole records. Fields: %s.", fields);
    g_free(fields);
    return text;
}

static void add_choices(JsonDoc *doc, Json *holder, Param p) {
    Json *choices = yyjson_mut_obj_add_arr(doc, holder, "enum");
    if (p == REPORT) {
        for (int r = 0; r < REPORT_COUNT; r++) yyjson_mut_arr_add_str(doc, choices, REPORTS[r].key);
        return;
    }
    char **words = g_strsplit(parameters[p].choices, ",", -1);
    for (int i = 0; words[i]; i++) yyjson_mut_arr_add_strcpy(doc, choices, words[i]);
    g_strfreev(words);
}

Json *list_tools(JsonDoc *doc, const Session *session) {
    Json *list = yyjson_mut_arr(doc);
    for (guint i = 0; i < G_N_ELEMENTS(tools); i++) {
        const struct Tool *tool = &tools[i];
        if (!enabled(tool, session)) continue;
        Json *entry = yyjson_mut_arr_add_obj(doc, list);
        put_text(doc, entry, "name", tool->name);
        char *help = tool->description ? NULL : search_help();
        put_text(doc, entry, "description", help ? help : tool->description);
        g_free(help);
        Json *schema = yyjson_mut_obj_add_obj(doc, entry, "inputSchema");
        put_text(doc, schema, "type", "object");
        yyjson_mut_obj_add_bool(doc, schema, "additionalProperties", false);
        Json *properties = yyjson_mut_obj_add_obj(doc, schema, "properties");
        Json *required = tool->required ? yyjson_mut_obj_add_arr(doc, schema, "required") : NULL;
        for (int p = 0; p < PARAM_COUNT; p++) {
            if (!(tool->allowed & BIT(p))) continue;
            const Parameter *spec = &parameters[p];
            Json *prop = yyjson_mut_obj_add_obj(doc, properties, spec->key);
            gboolean list_kind = spec->kind == TEXTS || spec->kind == NUMBERS;
            put_text(doc, prop, "type", list_kind ? "array" : spec->kind == NUMBER ? "integer"
                                        : spec->kind == FLAG ? "boolean" : "string");
            if (spec->description) put_text(doc, prop, "description", spec->description);
            if (spec->kind == NUMBER) {
                yyjson_mut_obj_add_int(doc, prop, "minimum", spec->minimum);
                yyjson_mut_obj_add_int(doc, prop, "maximum", spec->maximum);
            } else if (list_kind) {
                Json *items = yyjson_mut_obj_add_obj(doc, prop, "items");
                put_text(doc, items, "type", spec->kind == TEXTS ? "string" : "integer");
                if (spec->choices) add_choices(doc, items, p);
                yyjson_mut_obj_add_int(doc, prop, "maxItems", spec->maximum);
            } else if (spec->choices) add_choices(doc, prop, p);
            if (tool->required & BIT(p)) yyjson_mut_arr_add_str(doc, required, spec->key);
        }
        Json *annotations = yyjson_mut_obj_add_obj(doc, entry, "annotations");
        yyjson_mut_obj_add_bool(doc, annotations, "readOnlyHint", tool->run != export_matches && tool->run != mark);
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
    return value ? yyjson_get_sint(value) : 0;
}

static Input *list_arg(Input *args, Param p) {
    return yyjson_obj_get(args, parameters[p].key);
}

static gboolean valid_text(Input *value) {
    return yyjson_is_str(value) && yyjson_get_len(value) == strlen(yyjson_get_str(value)) &&
           g_utf8_validate(yyjson_get_str(value), -1, NULL) && g_utf8_strlen(yyjson_get_str(value), -1) <= 2048;
}

static gboolean valid_choice(Param p, const char *word) {
    if (p == REPORT) return report_find(word) != NULL;
    char **words = g_strsplit(parameters[p].choices, ",", -1);
    gboolean found = g_strv_contains((const char *const *)words, word);
    g_strfreev(words);
    return found;
}

static gboolean valid_value(Param p, Input *value) {
    const Parameter *spec = &parameters[p];
    if (spec->kind == FLAG) return yyjson_is_bool(value);
    if (spec->kind == NUMBER)
        return yyjson_is_uint(value) && yyjson_get_uint(value) >= (unsigned)spec->minimum &&
               yyjson_get_uint(value) <= (unsigned)spec->maximum;
    if (spec->kind == TEXT) return valid_text(value) && (!spec->choices || valid_choice(p, yyjson_get_str(value)));
    size_t index, count;
    Input *item;
    if (!yyjson_is_arr(value) || !yyjson_arr_size(value) || yyjson_arr_size(value) > (size_t)spec->maximum)
        return FALSE;
    yyjson_arr_foreach(value, index, count, item) {
        if (spec->kind == NUMBERS && !(yyjson_is_uint(item) && yyjson_get_uint(item) && yyjson_get_uint(item) <= G_MAXINT))
            return FALSE;
        if (spec->kind == TEXTS && !(valid_text(item) && (!spec->choices || valid_choice(p, yyjson_get_str(item)))))
            return FALSE;
    }
    return TRUE;
}

static gboolean valid_args(const struct Tool *tool, Input *args, GError **error) {
    size_t index, count;
    Input *key, *value;
    unsigned supplied = 0;
    yyjson_obj_foreach(args, index, count, key, value) {
        int p = 0;
        while (p < PARAM_COUNT && !yyjson_equals_str(key, parameters[p].key)) p++;
        if (p == PARAM_COUNT || !(tool->allowed & BIT(p)) || (supplied & BIT(p))) {
            GString *known = g_string_new(NULL);
            for (int k = 0; k < PARAM_COUNT; k++)
                if (tool->allowed & BIT(k)) g_string_append_printf(known, "%s%s", known->len ? ", " : "", parameters[k].key);
            bec_fail(error, "Unexpected or duplicate argument. %s takes: %s", tool->name, known->str);
            g_string_free(known, TRUE);
            return FALSE;
        }
        if (!valid_value(p, value)) {
            const Parameter *spec = &parameters[p];
            if (p == REPORT) {
                GString *known = g_string_new(NULL);
                for (int r = 0; r < REPORT_COUNT; r++) g_string_append_printf(known, "%s%s", r ? ", " : "", REPORTS[r].key);
                bec_fail(error, "Invalid reports. Pass an array of: %s", known->str);
                g_string_free(known, TRUE);
            } else if (spec->choices) bec_fail(error, "Invalid %s. Choose: %s", spec->key, spec->choices);
            else if (spec->kind == NUMBER) bec_fail(error, "Invalid %s. Use an integer from %d to %d", spec->key, spec->minimum, spec->maximum);
            else if (spec->kind == TEXT) bec_fail(error, "Invalid %s. Use text up to 2048 characters", spec->key);
            else if (spec->kind == FLAG) bec_fail(error, "Invalid %s. Use true or false", spec->key);
            else bec_fail(error, "Invalid %s. Use an array of 1 to %d %s", spec->key, spec->maximum,
                          spec->kind == TEXTS ? "strings" : "positive integers");
            return FALSE;
        }
        supplied |= BIT(p);
    }
    if ((supplied & tool->required) != tool->required) {
        for (int p = 0; p < PARAM_COUNT; p++)
            if ((tool->required & BIT(p)) && !(supplied & BIT(p))) {
                bec_fail(error, "Missing %s", parameters[p].key);
                break;
            }
        return FALSE;
    }
    return TRUE;
}

Json *call_tool(JsonDoc *doc, Session *session, const char *name, Input *args, GError **error) {
    for (guint i = 0; i < G_N_ELEMENTS(tools); i++) {
        const struct Tool *tool = &tools[i];
        if (strcmp(tool->name, name) || !enabled(tool, session)) continue;
        if (!valid_args(tool, args, error)) return NULL;
        // Marks commit their own transaction.
        if (tool->run == mark) return mark(doc, session, args, error);
        if (!sql_run(session->db, "BEGIN", error)) return NULL;
        Json *result = tool->run(doc, session, args, error);
        sql_run(session->db, "ROLLBACK", NULL);
        return result;
    }
    GString *known = g_string_new(NULL);
    for (guint i = 0; i < G_N_ELEMENTS(tools); i++)
        if (enabled(&tools[i], session)) g_string_append_printf(known, "%s%s", known->len ? ", " : "", tools[i].name);
    bec_fail(error, "Unknown or disabled tool. Available: %s", known->str);
    g_string_free(known, TRUE);
    return NULL;
}

static void page_end(JsonDoc *doc, Json *result, gint64 next, gboolean more) {
    if (more) yyjson_mut_obj_add_int(doc, result, "next_offset", next);
}

static gboolean fits(Json *rows, Json *row, const Session *session, size_t *used) {
    if (!session->full_output) {
        size_t length = 0;
        char *encoded = yyjson_mut_val_write(row, 0, &length);
        free(encoded);
        if (*used && *used + length > BUDGET) return FALSE;
        *used += length;
    }
    return yyjson_mut_arr_append(rows, row);
}

static Json *columns(JsonDoc *doc, Json *result, const char *const *names, guint count) {
    Json *list = yyjson_mut_obj_add_arr(doc, result, "columns");
    for (guint i = 0; i < count; i++) yyjson_mut_arr_add_str(doc, list, names[i]);
    return list;
}

static void cell(JsonDoc *doc, Json *row, const char *text, const Session *session, gboolean *clipped) {
    if (session->full_output || g_utf8_strlen(text, CELL * 4 + 4) <= CELL) {
        yyjson_mut_arr_add_strcpy(doc, row, text);
        return;
    }
    yyjson_mut_arr_add_strncpy(doc, row, text, g_utf8_offset_to_pointer(text, CELL) - text);
    *clipped = TRUE;
}

// Whole seconds lose zero fractions.
static void time_cell(JsonDoc *doc, Json *row, const char *stamp) {
    size_t length = stamp ? strlen(stamp) : 0;
    if (length == 27 && !strcmp(stamp + 19, ".000000Z")) {
        char whole[21];
        memcpy(whole, stamp, 19);
        memcpy(whole + 19, "Z", 2);
        yyjson_mut_arr_add_strcpy(doc, row, whole);
    } else yyjson_mut_arr_add_strcpy(doc, row, stamp ? stamp : "");
}

static Json *source_coverage(JsonDoc *doc, const Session *session, GError **error) {
    sqlite3 *db = session->db;
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
    Json *missing = yyjson_mut_arr(doc);
    for (size_t i = 0; i < G_N_ELEMENTS(families); i++) {
        if (!logs[i]) yyjson_mut_arr_add_str(doc, missing, families[i]);
        else if (!records[i]) put_text(doc, coverage, families[i], "header only");
        else yyjson_mut_obj_add_int(doc, coverage, families[i], records[i]);
    }
    if (yyjson_mut_arr_size(missing)) yyjson_mut_obj_add_val(doc, coverage, "missing", missing);
    return coverage;
}

static Json *overview(JsonDoc *doc, Session *session, Input *args, GError **error) {
    sqlite3_stmt *st = sql_prepare(session->db,
        "SELECT l.id,l.name,l.sheet,l.kind,l.total,"
        "(SELECT min(time) FROM events WHERE log=l.id AND time>''),"
        "(SELECT max(time) FROM events WHERE log=l.id AND time>''),"
        "(SELECT count(*) FROM events WHERE log=l.id AND time=''),l.issues,l.warning,f.digest FROM logs l "
        "JOIN files f ON f.id=l.file ORDER BY l.id LIMIT ? OFFSET ?", error);
    if (!st) return NULL;
    gint64 offset = integer_arg(args, OFFSET), limit = integer_arg(args, LIMIT);
    if (!limit) limit = 50;
    sqlite3_bind_int64(st, 1, limit + 1);
    sqlite3_bind_int64(st, 2, offset);
    Json *result = yyjson_mut_obj(doc);
    static const char *const names[] = {"log", "file", "sheet", "source", "records", "first_utc", "last_utc",
                                        "undated", "issues", "warning", "sha256"};
    columns(doc, result, names, G_N_ELEMENTS(names));
    Json *rows = yyjson_mut_obj_add_arr(doc, result, "logs");
    size_t used = 0;
    int state;
    while ((state = sqlite3_step(st)) == SQLITE_ROW && yyjson_mut_arr_size(rows) < (size_t)limit) {
        Json *row = yyjson_mut_arr(doc);
        for (int i = 0; i < 11; i++) {
            if (i == 0 || i == 4 || i == 7 || i == 8) yyjson_mut_arr_add_int(doc, row, sqlite3_column_int64(st, i));
            else if (i == 5 || i == 6) time_cell(doc, row, (const char *)sqlite3_column_text(st, i));
            else if (i == 3) {
                char *label = source_label(column_text(st, i));
                yyjson_mut_arr_add_strcpy(doc, row, label);
                g_free(label);
            } else yyjson_mut_arr_add_strcpy(doc, row, column_text(st, i));
        }
        if (!fits(rows, row, session, &used)) break;
    }
    if (state != SQLITE_DONE && state != SQLITE_ROW) bec_fail(error, "%s", sqlite3_errmsg(session->db));
    page_end(doc, result, offset + yyjson_mut_arr_size(rows), state == SQLITE_ROW);
    sqlite3_finalize(st);
    if (*error || offset) return result;
    Json *coverage = source_coverage(doc, session, error);
    if (coverage) yyjson_mut_obj_add_val(doc, result, "coverage", coverage);
    // Verdict totals live in statistics.
    gint64 rules = sql_int(session->db, "SELECT (SELECT count(*) FROM verdict_rules)+(SELECT count(*) FROM marks)", NULL);
    if (rules > 0) yyjson_mut_obj_add_int(doc, result, "mark_rules", rules);
    return result;
}

// Extra columns use engine fields.
static GPtrArray *custom_columns(Input *args, GError **error) {
    GPtrArray *custom = g_ptr_array_new_with_free_func(g_free);
    size_t index, count;
    Input *item;
    Input *fields = list_arg(args, FIELDS);
    yyjson_arr_foreach(fields, index, count, item) {
        const char *name = yyjson_get_str(item);
        if (*name != '/' && !slot_find(name)) {
            GString *known = g_string_new(NULL);
            for (int i = 0; i < SLOT_COUNT; i++) g_string_append_printf(known, "%s%s", i ? ", " : "", SLOTS[i].name);
            bec_fail(error, "Unknown extra field: %s. Use a /Header/nested path or: %s", name, known->str);
            g_string_free(known, TRUE);
            g_ptr_array_free(custom, TRUE);
            return NULL;
        }
        CustomColumn *column = g_new0(CustomColumn, 1);
        column->label = column->path = (char *)name;
        g_ptr_array_add(custom, column);
    }
    return custom;
}

static Json *search(JsonDoc *doc, Session *session, Input *args, GError **error) {
    GPtrArray *custom = custom_columns(args, error);
    if (!custom) return NULL;
    GPtrArray *bindings = args_new();
    char *select = select_sql(custom, bindings);
    gint64 log = integer_arg(args, LOG);
    const char *bql = string_arg(args, BQL);
    char *where = where_sql(log, bql, bindings, error);
    sqlite3_stmt *st = NULL;
    gint64 limit = integer_arg(args, LIMIT), offset = integer_arg(args, OFFSET);
    if (!limit) limit = 20;
    if (where) {
        gboolean latest = !strcmp(string_arg(args, ORDER), "desc");
        char *sql = g_strconcat(select, where, latest ? " ORDER BY (e.time=''),e.time DESC,e.id DESC LIMIT ? OFFSET ?"
                                                      : " ORDER BY (e.time=''),e.time,e.id LIMIT ? OFFSET ?", NULL);
        args_int(bindings, limit + 1);
        args_int(bindings, offset);
        st = sql_prepare(session->db, sql, error);
        if (st) args_bind(st, bindings, 1);
        g_free(sql);
    }
    g_free(select);
    g_free(where);
    g_ptr_array_free(bindings, TRUE);
    if (!st) {
        g_ptr_array_free(custom, TRUE);
        return NULL;
    }
    Json *result = yyjson_mut_obj(doc);
    static const char *const names[] = {"key", "utc", "actor", "operation", "result", "ip", "log", "row", "verdict"};
    Json *heads = columns(doc, result, names, G_N_ELEMENTS(names));
    for (guint i = 0; i < custom->len; i++)
        yyjson_mut_arr_add_strcpy(doc, heads, ((CustomColumn *)custom->pdata[i])->path);
    Json *rows = yyjson_mut_obj_add_arr(doc, result, "rows");
    int state, log_column = 15 + (int)custom->len;
    size_t used = 0;
    gboolean clipped = FALSE;
    while ((state = sqlite3_step(st)) == SQLITE_ROW && yyjson_mut_arr_size(rows) < (size_t)limit) {
        Json *row = yyjson_mut_arr(doc);
        gboolean row_clipped = FALSE;
        yyjson_mut_arr_add_int(doc, row, sqlite3_column_int64(st, 0));
        time_cell(doc, row, column_text(st, 2));
        for (int i = 3; i <= 6; i++) cell(doc, row, column_text(st, i), session, &row_clipped);
        yyjson_mut_arr_add_int(doc, row, sqlite3_column_int64(st, log_column));
        yyjson_mut_arr_add_int(doc, row, sqlite3_column_int64(st, 1));
        const char *verdict = column_text(st, 13);
        yyjson_mut_arr_add_strcpy(doc, row, strcmp(verdict, "Unmarked") ? verdict : "");
        for (guint i = 0; i < custom->len; i++) cell(doc, row, column_text(st, 15 + (int)i), session, &row_clipped);
        if (!fits(rows, row, session, &used)) break;
        clipped = clipped || row_clipped;
    }
    if (state != SQLITE_DONE && state != SQLITE_ROW) bec_fail(error, "%s", sqlite3_errmsg(session->db));
    gboolean more = state == SQLITE_ROW;
    sqlite3_finalize(st);
    g_ptr_array_free(custom, TRUE);
    gint64 shown = (gint64)yyjson_mut_arr_size(rows);
    if (!*error && !offset)
        yyjson_mut_obj_add_int(doc, result, "total", more ? count_rows(session->db, log, bql, error) : shown);
    page_end(doc, result, offset + shown, more);
    if (clipped) put_text(doc, result, "clipped", "Long cells cut at 192 characters. Use inspect_event for exact values.");
    return result;
}

static gboolean opens_json(const char *text) {
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') text++;
    return *text == '{' || *text == '[';
}

// Decodes JSON, drops empties.
static Json *tidy(JsonDoc *doc, Input *value, gboolean compact, gboolean *clipped) {
    if (yyjson_is_str(value)) {
        const char *text = yyjson_get_str(value);
        size_t length = yyjson_get_len(value);
        if (opens_json(text)) {
            yyjson_doc *inner = yyjson_read(text, length, 0);
            if (inner) {
                Json *decoded = tidy(doc, yyjson_doc_get_root(inner), compact, clipped);
                yyjson_doc_free(inner);
                return decoded;
            }
        }
        if (!compact) return yyjson_mut_strncpy(doc, text, length);
        if (!length) return NULL;
        glong characters = g_utf8_strlen(text, (gssize)length);
        if (characters <= 400) return yyjson_mut_strncpy(doc, text, length);
        *clipped = TRUE;
        char *head = g_utf8_substring(text, 0, 400);
        char *cut = g_strdup_printf("%s...[+%ld chars]", head, characters - 400);
        Json *out = yyjson_mut_strcpy(doc, cut);
        g_free(head);
        g_free(cut);
        return out;
    }
    size_t index, count;
    if (yyjson_is_obj(value)) {
        Json *out = yyjson_mut_obj(doc);
        Input *key, *child;
        yyjson_obj_foreach(value, index, count, key, child) {
            Json *tidied = tidy(doc, child, compact, clipped);
            if (tidied) yyjson_mut_obj_add(out, yyjson_val_mut_copy(doc, key), tidied);
        }
        return compact && !yyjson_mut_obj_size(out) ? NULL : out;
    }
    if (yyjson_is_arr(value)) {
        Json *out = yyjson_mut_arr(doc);
        Input *child;
        gboolean any = FALSE;
        yyjson_arr_foreach(value, index, count, child) {
            Json *tidied = tidy(doc, child, compact, clipped);
            any = any || tidied;
            // Positions keep their indexes.
            yyjson_mut_arr_append(out, tidied ? tidied : yyjson_mut_null(doc));
        }
        return compact && !any ? NULL : out;
    }
    if (compact && yyjson_is_null(value)) return NULL;
    return yyjson_val_mut_copy(doc, value);
}

static Json *whole_record(JsonDoc *doc, const char *headers_json, const char *raw, gboolean tabular,
                          gboolean compact, gboolean *clipped) {
    yyjson_doc *heads = yyjson_read(headers_json, strlen(headers_json), 0);
    yyjson_doc *cells_doc = yyjson_read(raw, strlen(raw), 0);
    Input *headers = yyjson_doc_get_root(heads), *cells = yyjson_doc_get_root(cells_doc);
    Json *record = yyjson_mut_obj(doc);
    size_t width = yyjson_arr_size(headers);
    Input *present = yyjson_arr_size(cells) == width + 1 ? yyjson_arr_get(cells, width) : NULL;
    gboolean sparse = yyjson_is_arr(present);
    size_t count = sparse ? yyjson_arr_size(present) : yyjson_arr_size(cells);
    GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    for (size_t i = 0; i < count; i++) {
        Input *slot = sparse ? yyjson_arr_get(present, i) : NULL;
        size_t column = !sparse ? i : yyjson_is_str(slot) ? (size_t)g_ascii_strtoull(yyjson_get_str(slot), NULL, 10)
                                                        : (size_t)yyjson_get_uint(slot);
        Input *value = yyjson_arr_get(cells, column);
        if (!value || (sparse && column >= width)) continue;
        const char *name = column < width ? yyjson_get_str(yyjson_arr_get(headers, column)) : NULL;
        char *label = name ? g_strdup(name) : g_strdup_printf("Extra column %zu", column + 1);
        // Repeated headers get ordinals.
        for (int copy = 2; g_hash_table_contains(seen, label); copy++) {
            g_free(label);
            label = g_strdup_printf("%s [%d]", name ? name : "Extra column", copy);
        }
        Json *tidied = tabular || compact ? tidy(doc, value, compact, clipped) : yyjson_val_mut_copy(doc, value);
        if (tidied) yyjson_mut_obj_add(record, yyjson_mut_strcpy(doc, label), tidied);
        g_hash_table_add(seen, label);
    }
    g_hash_table_destroy(seen);
    yyjson_doc_free(heads);
    yyjson_doc_free(cells_doc);
    return record;
}

// Large values list their keys.
static void outline(JsonDoc *doc, Json *result, Json *value, const char *prefix) {
    Json *paths = yyjson_mut_obj_add_arr(doc, result, "paths");
    size_t index, count;
    Json *key, *child;
    if (yyjson_mut_is_arr(value)) {
        yyjson_mut_obj_add_int(doc, result, "items", (gint64)yyjson_mut_arr_size(value));
        return;
    }
    yyjson_mut_obj_foreach(value, index, count, key, child) {
        char *part = escape_pointer(yyjson_mut_get_str(key));
        char *path = g_strdup_printf("%s/%s", prefix, part);
        size_t inner_index, inner_count;
        Json *inner_key, *inner_child;
        if (yyjson_mut_is_obj(child) && yyjson_mut_obj_size(child) <= 60) {
            yyjson_mut_obj_foreach(child, inner_index, inner_count, inner_key, inner_child) {
                char *leaf = escape_pointer(yyjson_mut_get_str(inner_key));
                char *deep = g_strdup_printf("%s/%s", path, leaf);
                yyjson_mut_arr_add_strcpy(doc, paths, deep);
                g_free(leaf);
                g_free(deep);
            }
        } else yyjson_mut_arr_add_strcpy(doc, paths, path);
        g_free(part);
        g_free(path);
    }
}

static gboolean oversized(Json *value) {
    size_t length = 0;
    char *encoded = yyjson_mut_val_write(value, 0, &length);
    free(encoded);
    return length > BUDGET;
}

static Json *inspect(JsonDoc *doc, Session *session, Input *args, GError **error) {
    const char *field = string_arg(args, FIELD);
    if (*field && *field != '/') {
        bec_fail(error, "Field paths start with /, for example /AuditData/Item");
        return NULL;
    }
    sqlite3_stmt *st = sql_prepare(session->db,
        "SELECT l.name,l.sheet,e.rownum,l.headers,e.raw,e.log,f.digest FROM events e JOIN logs l ON l.id=e.log "
        "JOIN files f ON f.id=l.file WHERE e.id=?", error);
    if (!st) return NULL;
    gint64 offset = integer_arg(args, OFFSET);
    gboolean compact = !session->full_output, clipped = FALSE;
    sqlite3_bind_int64(st, 1, integer_arg(args, EVENT));
    int state = sqlite3_step(st);
    Json *result = yyjson_mut_obj(doc);
    if (state != SQLITE_ROW) {
        if (state == SQLITE_DONE) bec_fail(error, "Unknown event key. Use the key column from search_events.");
        else bec_fail(error, "%s", sqlite3_errmsg(session->db));
        sqlite3_finalize(st);
        return result;
    }
    const char *name = column_text(st, 0), *headers = column_text(st, 3), *raw = column_text(st, 4);
    char *location = source_location(name, column_text(st, 1), sqlite3_column_int64(st, 2));
    yyjson_mut_obj_add_int(doc, result, "key", integer_arg(args, EVENT));
    yyjson_mut_obj_add_int(doc, result, "log", sqlite3_column_int64(st, 5));
    put_text(doc, result, "location", location);
    g_free(location);
    if (!compact) put_text(doc, result, "sha256", column_text(st, 6));
    if (!*field) {
        Json *record = whole_record(doc, headers, raw, !log_is_json(name), compact, &clipped);
        if (compact && oversized(record)) {
            put_text(doc, result, "too_large", "Pass field with one of these paths.");
            outline(doc, result, record, "");
        } else {
            yyjson_mut_obj_add_val(doc, result, "record", record);
            if (clipped) put_text(doc, result, "clipped", "Long strings cut at 400 characters. Pass field for the full value.");
        }
        sqlite3_finalize(st);
        return result;
    }
    put_text(doc, result, "field", field);
    Columns *layout = columns_new(headers);
    char *found = field_json(layout, raw, field);
    columns_free(layout);
    yyjson_doc *parsed = found ? yyjson_read(found, strlen(found), 0) : NULL;
    Input *root = yyjson_doc_get_root(parsed);
    yyjson_mut_obj_add_bool(doc, result, "present", found != NULL);
    if (yyjson_is_str(root)) {
        // Long text pages by characters.
        const char *text = yyjson_get_str(root);
        glong total = g_utf8_strlen(text, -1), chunk = compact ? 6000 : 60000;
        if (offset > total) offset = total;
        char *part = g_utf8_substring(text, offset, MIN(total, offset + chunk));
        put_text(doc, result, "value", part);
        g_free(part);
        page_end(doc, result, offset + chunk, offset + chunk < total);
    } else if (root) {
        Json *value = compact ? tidy(doc, root, TRUE, &clipped) : yyjson_val_mut_copy(doc, root);
        if (!value) value = yyjson_mut_null(doc);
        if (compact && oversized(value)) {
            put_text(doc, result, "too_large", "Pass a deeper field path.");
            outline(doc, result, value, field);
        } else {
            yyjson_mut_obj_add_val(doc, result, "value", value);
            if (clipped) put_text(doc, result, "clipped", "Long strings cut at 400 characters. Pass a deeper field path.");
        }
    }
    yyjson_doc_free(parsed);
    g_free(found);
    sqlite3_finalize(st);
    return result;
}

static Json *statistics(JsonDoc *doc, Session *session, Input *args, GError **error) {
    const char *filter = string_arg(args, BQL);
    gint64 log = integer_arg(args, LOG), offset = integer_arg(args, OFFSET), limit = integer_arg(args, LIMIT);
    Input *wanted = list_arg(args, REPORT), *item;
    size_t index, count, used = 0;
    if (!limit) limit = 15;
    Json *result = yyjson_mut_obj(doc);
    yyjson_arr_foreach(wanted, index, count, item) {
        const char *key = yyjson_get_str(item);
        const Report *report = report_find(key);
        if (yyjson_mut_obj_get(result, key)) continue;
        GPtrArray *groups = stats_calculate(session->db, key, log, filter, 3600, error);
        if (!groups) return NULL;
        Json *table = yyjson_mut_obj_add_obj(doc, result, key);
        Json *heads = yyjson_mut_obj_add_arr(doc, table, "columns");
        gboolean indicators = !strcmp(key, "indicators");
        for (int j = 0; j < report_width(report); j++) yyjson_mut_arr_add_str(doc, heads, report->fields[j]);
        yyjson_mut_arr_add_str(doc, heads, "count");
        yyjson_mut_arr_add_str(doc, heads, "first_utc");
        yyjson_mut_arr_add_str(doc, heads, "last_utc");
        if (indicators) yyjson_mut_arr_add_str(doc, heads, "bql");
        if (*report->subset) put_text(doc, table, "scope", report->subset);
        Json *rows = yyjson_mut_obj_add_arr(doc, table, "rows");
        gint64 end = MIN(offset + limit, (gint64)groups->len), i;
        gboolean clipped = FALSE;
        for (i = offset; i < end; i++) {
            StatRow *group = groups->pdata[i];
            if (indicators && !group->count) continue;
            Json *row = yyjson_mut_arr(doc);
            for (int j = 0; j < report_width(report); j++) {
                if (!strcmp(report->fields[j], "time")) {
                    char *start = utc_from_epoch(group->epoch);
                    time_cell(doc, row, start);
                    g_free(start);
                } else cell(doc, row, group->values[j], session, &clipped);
            }
            yyjson_mut_arr_add_int(doc, row, group->count);
            time_cell(doc, row, group->first);
            time_cell(doc, row, group->last);
            if (indicators) {
                char *drill = stats_drilldown(key, group, 3600);
                yyjson_mut_arr_add_strcpy(doc, row, drill);
                g_free(drill);
            }
            if (!fits(rows, row, session, &used)) break;
        }
        yyjson_mut_obj_add_int(doc, table, "groups", groups->len);
        page_end(doc, table, i, i < (gint64)groups->len);
        g_ptr_array_free(groups, TRUE);
    }
    return result;
}

static gboolean writable(Session *session, gboolean on, GError **error) {
    return sql_run(session->db, on ? "PRAGMA query_only=OFF" : "PRAGMA query_only=ON", error);
}

static Json *mark(JsonDoc *doc, Session *session, Input *args, GError **error) {
    sqlite3 *db = session->db;
    const char *verdict = string_arg(args, VERDICT), *bql = string_arg(args, BQL);
    const char *start = string_arg(args, START), *end = string_arg(args, END);
    Input *ips = list_arg(args, IPS), *keys = list_arg(args, KEYS), *item;
    gboolean undo = yyjson_get_bool(yyjson_obj_get(args, parameters[UNDO].key));
    int scopes = (ips != NULL) + (keys != NULL) + (*start || *end) + (*bql != 0);
    Json *result = yyjson_mut_obj(doc);
    if (undo ? scopes || *verdict : scopes != 1 || !*verdict || (integer_arg(args, LOG) && !*bql)) {
        bec_fail(error, "Pass verdict with exactly one of bql, ips, event_keys, or start_utc plus end_utc. "
                        "Or pass only undo: true.");
        return NULL;
    }
    if (!writable(session, TRUE, error)) return NULL;
    size_t index, count;
    GPtrArray *pairs = g_ptr_array_new_with_free_func(g_free);
    GString *scope = g_string_new(NULL);
    gint64 marked = -1;
    if (undo) {
        gint64 before = sql_int(db, "SELECT (SELECT count(*) FROM verdict_rules)+(SELECT count(*) FROM marks)", NULL);
        if (!before) bec_fail(error, "Nothing to undo");
        else if (undo_verdict(db, error)) yyjson_mut_obj_add_bool(doc, result, "undone", true);
    } else if (ips) {
        yyjson_arr_foreach(ips, index, count, item) {
            char *address = ip_normalize(yyjson_get_str(item));
            if (!*address && !*error) bec_fail(error, "Invalid IP address: %s", yyjson_get_str(item));
            g_string_append_printf(scope, "%sip = \"%s\"", scope->len ? " OR " : "", address);
            g_ptr_array_add(pairs, address);
            g_ptr_array_add(pairs, g_strdup(""));
        }
        if (!*error && assign_verdict(db, "ip", pairs, verdict, error)) marked = count_rows(db, 0, scope->str, error);
    } else if (keys) {
        GString *list = g_string_new("SELECT count(*) FROM events WHERE id IN (");
        yyjson_arr_foreach(keys, index, count, item) {
            g_string_append_printf(list, "%s%" G_GUINT64_FORMAT, index ? "," : "", (guint64)yyjson_get_uint(item));
            g_ptr_array_add(pairs, g_strdup_printf("%" G_GUINT64_FORMAT, (guint64)yyjson_get_uint(item)));
            g_ptr_array_add(pairs, g_strdup(""));
        }
        g_string_append_c(list, ')');
        gint64 known = sql_int(db, list->str, error);
        g_string_free(list, TRUE);
        if (!*error && known != (gint64)(pairs->len / 2)) bec_fail(error, "Some event_keys are not in this case. Nothing marked.");
        else if (!*error && assign_verdict(db, "event", pairs, verdict, error)) marked = known;
    } else if (*start || *end) {
        gboolean shaped = strchr(start, 'T') && g_str_has_suffix(start, "Z") && strchr(end, 'T') && g_str_has_suffix(end, "Z");
        char *lo = utc_normalize(start), *hi = utc_normalize(end);
        if (!shaped || !*lo || !*hi || strcmp(lo, hi) >= 0) {
            bec_fail(error, "Supply start_utc before end_utc, both ISO timestamps ending in Z");
            g_free(lo);
            g_free(hi);
        } else {
            g_string_printf(scope, "time >= \"%s\" AND time < \"%s\"", lo, hi);
            g_ptr_array_add(pairs, lo);
            g_ptr_array_add(pairs, hi);
            if (assign_verdict(db, "time", pairs, verdict, error)) marked = count_rows(db, 0, scope->str, error);
        }
    } else {
        marked = mark_matches(db, integer_arg(args, LOG), bql, verdict, 50000, error);
    }
    if (marked >= 0 && !*error) {
        yyjson_mut_obj_add_int(doc, result, "events", marked);
        put_text(doc, result, "verdict", verdict);
    }
    g_ptr_array_free(pairs, TRUE);
    g_string_free(scope, TRUE);
    writable(session, FALSE, *error ? NULL : error);
    return result;
}

static Json *export_matches(JsonDoc *doc, Session *session, Input *args, GError **error) {
    GPtrArray *custom = custom_columns(args, error);
    if (!custom) return NULL;
    const char *format = string_arg(args, FORMAT), *bql = string_arg(args, BQL);
    gint64 log = integer_arg(args, LOG);
    char *folder = g_build_filename(session->export_dir, "export-XXXXXX", NULL);
    Json *result = yyjson_mut_obj(doc);
    if (!g_mkdtemp(folder)) {
        bec_fail(error, "Could not create export directory");
    } else {
        char *filename = g_strdup_printf("timeline.%s", format);
        char *path = g_build_filename(folder, filename, NULL);
        if (export_events(session->db, path, log, bql, FALSE, "time", custom->len ? custom : NULL, error)) {
            put_text(doc, result, "path", path);
            yyjson_mut_obj_add_int(doc, result, "events", count_rows(session->db, log, bql, error));
        } else g_rmdir(folder);
        g_free(path);
        g_free(filename);
    }
    g_free(folder);
    g_ptr_array_free(custom, TRUE);
    return result;
}
