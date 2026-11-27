#include "core.h"

#include <string.h>

#define MARK_IP "EXISTS (SELECT 1 FROM ips i JOIN marks m ON m.kind='ip' AND m.lo=i.ip WHERE i.event=e.id)"
#define MARK_TIME "EXISTS (SELECT 1 FROM marks m WHERE m.kind='time' AND e.time>=m.lo AND e.time<m.hi)"
// Rules use permanent event keys.
#define LATEST_RULE                                                                                           \
    "CASE WHEN EXISTS(SELECT 1 FROM verdict_rules) THEN (SELECT max(rule) FROM ("                             \
    "SELECT max(id) AS rule FROM verdict_rules WHERE kind='event' AND lo=CAST(e.id AS TEXT) "                 \
    "UNION ALL SELECT max(r.id) FROM ips i JOIN verdict_rules r ON r.kind='ip' AND r.lo=i.ip WHERE i.event=e.id " \
    "UNION ALL SELECT max(id) FROM verdict_rules WHERE kind='time' AND lo<=e.time AND hi>e.time)) END"
#define LEGACY_REASON                                                                                         \
    "CASE WHEN " MARK_IP " THEN CASE WHEN " MARK_TIME " THEN 'IP + Time range' ELSE 'IP' END WHEN " MARK_TIME \
    " THEN 'Time range' ELSE '' END"
#define VERDICT                                                                                               \
    "coalesce((SELECT verdict FROM verdict_rules WHERE id=" LATEST_RULE "), CASE WHEN " MARK_IP " OR " MARK_TIME \
    " THEN 'Bad' ELSE 'Unmarked' END)"
#define REASON                                                                                                \
    "coalesce((SELECT CASE WHEN verdict='Unmarked' THEN '' WHEN kind='event' THEN 'Event' "                   \
    "WHEN kind='ip' THEN 'IP' ELSE 'Time range' END FROM verdict_rules WHERE id=" LATEST_RULE "),"            \
    LEGACY_REASON ")"

// Timelines may mix providers.
const char SQL_SOURCE[] =
    "source_label(CASE WHEN l.kind='Timeline' THEN COALESCE("
    "(SELECT NULLIF(trim(json_extract(e.raw,'$[' || h.key || ']')),'') "
    "FROM json_each(l.headers) h WHERE lower(trim(h.value))='source' LIMIT 1), l.kind) ELSE l.kind END)";
const char *SQL_CASE_ID = "(SELECT number FROM timeline_ids WHERE event=e.id)";

char *sql_verdict(void) {
    return g_strdup(VERDICT);
}

char *sql_reason(void) {
    return g_strdup(REASON);
}

const char *const BQL_FIELDS[] = {"source", "file",      "sheet",  "path",    "sha256", "issue", "markreason",
                                  "verdict", "time",     "operation", "result", "request", "actor", "raw", NULL};

static int name_order(gconstpointer a, gconstpointer b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static const char *field_sql(const char *field) {
    static const char *const sql[] = {
        SQL_SOURCE, "l.name", "l.sheet", "(SELECT path FROM files WHERE id=l.file)",
        "(SELECT digest FROM files WHERE id=l.file)", "e.issue", REASON, VERDICT, "e.time", "e.op", "e.result",
        "e.request", "e.actor", "e.raw"};
    for (int i = 0; BQL_FIELDS[i]; i++)
        if (!strcmp(BQL_FIELDS[i], field))
            return sql[i];
    return NULL;
}

// Lists every filter field.
char *bql_field_list(void) {
    GPtrArray *names = g_ptr_array_new();
    for (int i = 0; BQL_FIELDS[i]; i++)
        g_ptr_array_add(names, (gpointer)BQL_FIELDS[i]);
    for (int i = 0; i < SLOT_COUNT; i++)
        g_ptr_array_add(names, (gpointer)SLOTS[i].name);
    static const char *const extra[] = {"id", "row", "ip", "mailbox", "marked"};
    for (guint i = 0; i < G_N_ELEMENTS(extra); i++)
        g_ptr_array_add(names, (gpointer)extra[i]);
    g_ptr_array_sort(names, name_order);
    g_ptr_array_add(names, NULL);
    char *list = g_strjoinv(", ", (char **)names->pdata);
    g_ptr_array_free(names, TRUE);
    return list;
}

static void arg_free(gpointer data) {
    Arg *arg = data;
    g_free(arg->text);
    g_free(arg);
}

GPtrArray *args_new(void) {
    return g_ptr_array_new_with_free_func(arg_free);
}

void args_text(GPtrArray *args, const char *text) {
    Arg *arg = g_new0(Arg, 1);
    arg->text = g_strdup(text);
    g_ptr_array_add(args, arg);
}

void args_int(GPtrArray *args, gint64 number) {
    Arg *arg = g_new0(Arg, 1);
    arg->integer = TRUE;
    arg->number = number;
    g_ptr_array_add(args, arg);
}

int args_bind(sqlite3_stmt *statement, GPtrArray *args, int start) {
    for (guint i = 0; i < args->len; i++) {
        Arg *arg = args->pdata[i];
        if (arg->integer)
            sqlite3_bind_int64(statement, start++, arg->number);
        else
            sqlite3_bind_text(statement, start++, arg->text, -1, SQLITE_TRANSIENT);
    }
    return start;
}

typedef struct {
    GPtrArray *tokens;
    guint index;
    GPtrArray *args;
    GError **error;
    int depth;
} Parser;

static gboolean bare(gunichar c) {
    return c && !py_isspace(c) && !strchr("()=!<>\"", (int)(c < 0x80 ? c : 'x'));
}

static gboolean tokenize(const char *text, GPtrArray *tokens, GError **error) {
    const char *p = text;
    while (*p) {
        const char *start = p;
        while (*p && py_isspace(g_utf8_get_char(p)))
            p = g_utf8_next_char(p);
        const char *token = p;
        if (*p == '"') {
            p++;
            while (*p && *p != '"') {
                if (*p == '\\') {
                    if (!p[1] || p[1] == '\n')
                        break;
                    p++;
                }
                p = g_utf8_next_char(p);
            }
            if (*p != '"')
                token = NULL;
            else
                p++;
        } else if (p[0] && p[1] == '=' && strchr("!><=", p[0])) {
            p += 2;
        } else if (*p && strchr("()=<>", *p)) {
            p++;
        } else if (bare(g_utf8_get_char(p))) {
            while (bare(g_utf8_get_char(p)))
                p = g_utf8_next_char(p);
        } else {
            token = NULL;
        }
        if (!token) {
            bec_fail(error, "Invalid filter near character %ld", g_utf8_pointer_to_offset(text, start) + 1);
            return FALSE;
        }
        g_ptr_array_add(tokens, g_strndup(token, p - token));
    }
    return TRUE;
}

static gboolean take(Parser *parser, const char *token) {
    if (parser->index < parser->tokens->len && !g_ascii_strcasecmp(parser->tokens->pdata[parser->index], token)) {
        parser->index++;
        return TRUE;
    }
    return FALSE;
}

static const char *next(Parser *parser) {
    if (parser->index >= parser->tokens->len) {
        bec_fail(parser->error, "Incomplete filter");
        return NULL;
    }
    return parser->tokens->pdata[parser->index++];
}

static char *unquote(Parser *parser, const char *literal) {
    JDoc *doc = j_parse(literal, -1, 0, NULL);
    if (!doc || doc->root->t != J_STR) {
        j_free(doc);
        bec_fail(parser->error, "Invalid quoted text %s", literal);
        return NULL;
    }
    char *text = g_strdup(doc->root->u.s);
    j_free(doc);
    return text;
}

static char *expression(Parser *parser);

static char *comparison(const char *expr, const char *op) {
    // Timestamps compare as stored.
    if (!strcmp(expr, "e.time"))
        return g_strdup_printf(op[0] == '<' ? "(e.time!='' AND e.time %s ?)" : "e.time %s ?", op);
    // Whole records stay unfolded.
    if (!strcmp(op, "contains"))
        return g_strdup_printf(strcmp(expr, "e.raw") ? "instr(bql_fold(%s),bql_fold(?))>0" : "instr(lower(%s),lower(?))>0", expr);
    if (!strcmp(op, "=") || !strcmp(op, "==") || !strcmp(op, "!="))
        return g_strdup_printf("bql_fold(%s) %s bql_fold(?)", expr, op);
    return g_strdup_printf("%s %s ? COLLATE NOCASE", expr, op);
}

static char *term(Parser *parser) {
    if (++parser->depth > 200) {
        bec_fail(parser->error, "Filter is nested too deeply");
        return NULL;
    }
    char *result = NULL, *field = NULL, *pointer = NULL, *value = NULL, *op = NULL;
    if (take(parser, "not")) {
        char *inner = term(parser);
        if (inner)
            result = g_strdup_printf("(NOT %s)", inner);
        g_free(inner);
        goto done;
    }
    if (take(parser, "(")) {
        result = expression(parser);
        if (result && !take(parser, ")")) {
            g_clear_pointer(&result, g_free);
            bec_fail(parser->error, "Missing closing parenthesis");
        }
        goto done;
    }
    const char *token = next(parser);
    if (!token)
        goto done;
    field = g_utf8_strdown(token, -1);
    gboolean path = !strcmp(field, "field"), exists = !strcmp(field, "exists");
    if (path || exists) {
        const char *literal = next(parser);
        if (!literal)
            goto done;
        if (literal[0] != '"') {
            bec_fail(parser->error, "Use field \"/Header/nested/key\" = \"value\"");
            goto done;
        }
        pointer = unquote(parser, literal);
        if (!pointer)
            goto done;
        if (pointer[0] != '/' || g_utf8_strlen(pointer, -1) > 4096) {
            bec_fail(parser->error, "Field paths start with / and use up to 4096 characters");
            goto done;
        }
        if (exists) {
            args_text(parser->args, pointer);
            result = g_strdup("match_path(l.headers,e.raw,?,'exists','')");
            goto done;
        }
    }
    token = next(parser);
    if (!token)
        goto done;
    op = g_utf8_strdown(token, -1);
    static const char *const operators[] = {"=", "==", "!=", "<", "<=", ">", ">=", "contains", NULL};
    if (!g_strv_contains(operators, op)) {
        bec_fail(parser->error, "Expected comparison or contains");
        goto done;
    }
    token = next(parser);
    if (!token)
        goto done;
    value = token[0] == '"' ? unquote(parser, token) : g_strdup(token);
    if (!value)
        goto done;
    gboolean equality = !strcmp(op, "=") || !strcmp(op, "==") || !strcmp(op, "!=");
    gboolean contains = !strcmp(op, "contains");
    if (path) {
        if (!equality && !contains) {
            bec_fail(parser->error, "Use equality or contains with a source field");
            goto done;
        }
        args_text(parser->args, pointer);
        args_text(parser->args, op);
        args_text(parser->args, value);
        result = g_strdup("match_path(l.headers,e.raw,?,?,?)");
        goto done;
    }
    if (!strcmp(field, "marked")) {
        gboolean yes = !g_ascii_strcasecmp(value, "true"), no = !g_ascii_strcasecmp(value, "false");
        if ((!yes && !no) || !equality) {
            bec_fail(parser->error, "Use marked = true or marked = false");
            goto done;
        }
        gboolean invert = no != !strcmp(op, "!=");
        result = g_strdup_printf("(%s %s 'Unmarked')", VERDICT, invert ? "=" : "!=");
        goto done;
    }
    if (!strcmp(field, "time")) {
        char *stamp = utc_normalize(value);
        g_free(value);
        value = stamp;
        if (!*value || contains) {
            bec_fail(parser->error, "Compare time with an ISO date or timestamp");
            goto done;
        }
    }
    if (slot_find(field)) {
        if (!equality && !contains) {
            bec_fail(parser->error, "Use equality or contains with %s", field);
            goto done;
        }
        args_text(parser->args, field);
        args_text(parser->args, op);
        args_text(parser->args, value);
        result = g_strdup("event_match(l.headers,e.raw,?,?,?)");
        goto done;
    }
    if (!strcmp(field, "row") || !strcmp(field, "id")) {
        gboolean decimal = *value != 0 && strlen(value) <= 19;
        for (const char *p = value; decimal && *p; p++)
            decimal = g_ascii_isdigit(*p);
        if (contains || !decimal || g_ascii_strtoull(value, NULL, 10) > G_MAXINT64) {
            bec_fail(parser->error, "Compare %s with an integer in range", field);
            goto done;
        }
        args_int(parser->args, g_ascii_strtoll(value, NULL, 10));
        if (!strcmp(field, "id"))
            result = g_strdup_printf("e.id IN (SELECT event FROM timeline_ids WHERE number %s ?)", op);
        else
            result = g_strdup_printf("e.rownum %s ?", op);
        goto done;
    }
    gboolean ip = !strcmp(field, "ip");
    if (ip || !strcmp(field, "mailbox")) {
        if (!equality && !contains) {
            bec_fail(parser->error, "Use equality or contains with %s", field);
            goto done;
        }
        if (ip && !contains) {
            char *address = ip_normalize(value);
            g_free(value);
            value = address;
            if (!*value) {
                bec_fail(parser->error, "Invalid IP address");
                goto done;
            }
        }
        const char *column = ip ? "ip" : "value";
        char *condition = contains ? g_strdup_printf("instr(lower(%s),lower(?))>0", column)
                                   : g_strdup_printf("%s = ? COLLATE NOCASE", column);
        args_text(parser->args, value);
        result = g_strdup_printf("%sEXISTS (SELECT 1 FROM %s WHERE event=e.id AND %s)",
                                 !strcmp(op, "!=") ? "NOT " : "", ip ? "ips" : "identities", condition);
        g_free(condition);
        goto done;
    }
    const char *column = field_sql(field);
    if (!column) {
        char *known = bql_field_list();
        bec_fail(parser->error, "Unknown field: %s. Fields: %s. Nested: field \"/Header/key\" = \"value\".", field, known);
        g_free(known);
        goto done;
    }
    if (!strcmp(field, "source")) {
        if (equality) {
            char *label = source_label(value);
            g_free(value);
            value = label;
        }
        // Native sources use log indexes.
        char *native = comparison("source_label(kind)", op), *mixed = comparison(SQL_SOURCE, op);
        args_text(parser->args, value);
        args_text(parser->args, value);
        result = g_strdup_printf("(e.log IN (SELECT id FROM logs WHERE kind!='Timeline' AND %s) OR "
                                 "(e.log IN (SELECT id FROM logs WHERE kind='Timeline') AND %s))",
                                 native, mixed);
        g_free(native);
        g_free(mixed);
        goto done;
    }
    args_text(parser->args, value);
    result = comparison(column, op);
done:
    parser->depth--;
    g_free(field);
    g_free(pointer);
    g_free(value);
    g_free(op);
    return result;
}

static char *joined(Parser *parser, char *(*part)(Parser *), const char *keyword, const char *glue) {
    char *first = part(parser);
    if (!first)
        return NULL;
    GString *out = g_string_new("(");
    g_string_append(out, first);
    g_free(first);
    while (take(parser, keyword)) {
        char *more = part(parser);
        if (!more) {
            g_string_free(out, TRUE);
            return NULL;
        }
        g_string_append_printf(out, " %s %s", glue, more);
        g_free(more);
    }
    g_string_append_c(out, ')');
    return g_string_free(out, FALSE);
}

static char *conjunction(Parser *parser) {
    return joined(parser, term, "and", "AND");
}

static char *expression(Parser *parser) {
    return joined(parser, conjunction, "or", "OR");
}

Query *query_new(const char *text, GError **error) {
    Query *query = g_new0(Query, 1);
    query->args = args_new();
    char *stripped = py_strip(text ? text : "");
    GPtrArray *tokens = g_ptr_array_new_with_free_func(g_free);
    gboolean ok = tokenize(stripped, tokens, error);
    if (ok) {
        Parser parser = {tokens, 0, query->args, error, 0};
        query->sql = tokens->len ? expression(&parser) : g_strdup("1");
        if (query->sql && parser.index != tokens->len) {
            bec_fail(error, "Unexpected token %s", (char *)tokens->pdata[parser.index]);
            g_clear_pointer(&query->sql, g_free);
        }
        ok = query->sql != NULL;
    }
    g_ptr_array_free(tokens, TRUE);
    g_free(stripped);
    if (!ok) {
        query_free(query);
        return NULL;
    }
    return query;
}

void query_free(Query *query) {
    if (!query)
        return;
    g_free(query->sql);
    g_ptr_array_free(query->args, TRUE);
    g_free(query);
}
