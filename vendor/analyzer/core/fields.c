#include "core.h"

#include <string.h>

// Column and AuditData aliases.
const Slot SLOTS[] = {
    {"device", {"Device ID"}, {"DeviceId"}},
    {"session", {"Session ID"}, {"SessionId", "AADSessionId"}},
    {"correlation", {"Correlation ID", "CorrelationId"}, {"CorrelationId"}},
    {"application", {"Application"}, {"ApplicationDisplayName"}},
    {"appid", {"Application ID"}, {"AppId", "ClientAppId"}},
    {"location", {"Location"}, {NULL}},
    {"os", {"Operating System"}, {NULL}},
    {"client", {"Client app"}, {"ClientInfoString"}},
    {"authmethod", {"Authentication method"}, {NULL}},
    {"conditionalaccess", {"Conditional Access"}, {NULL}},
    {"serviceprincipal", {"Service principal ID", "ActorServicePrincipalId"}, {NULL}},
    {"workload", {"Service"}, {"Workload"}},
    {"messageid", {"message_id", "MessageId", "Message ID"}, {NULL}},
    {"recipient", {"recipient_address", "RecipientAddress", "Recipient address", "recipient_status"}, {NULL}},
    {"delivery", {"recipient_status", "Status"}, {NULL}},
    {"subject", {"message_subject", "Subject"}, {NULL}},
    {"rule", {NULL}, {NULL}},
    {"mailitem", {NULL}, {NULL}},
    {"access", {NULL}, {NULL}},
    {"folder", {NULL}, {NULL}},
    {"target", {NULL}, {NULL}},
};
const int SLOT_COUNT = G_N_ELEMENTS(SLOTS);

const Slot *slot_find(const char *name) {
    for (int i = 0; i < SLOT_COUNT; i++)
        if (!strcmp(SLOTS[i].name, name))
            return &SLOTS[i];
    return NULL;
}

static void free_positions(gpointer data) {
    g_array_free(data, TRUE);
}

Columns *columns_new(const char *headers_json) {
    Columns *columns = g_new0(Columns, 1);
    columns->names = g_ptr_array_new_with_free_func(g_free);
    columns->clean = g_ptr_array_new();
    columns->positions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_positions);
    JDoc *doc = j_parse(headers_json, -1, 0, NULL);
    if (doc && doc->root->t == J_ARR) {
        for (guint i = 0; i < doc->root->n; i++) {
            char *name = j_text(doc->root->u.a[i], TRUE);
            char *clean = clean_header(name);
            g_ptr_array_add(columns->names, name);
            GArray *list = g_hash_table_lookup(columns->positions, clean);
            if (!list) {
                list = g_array_new(FALSE, FALSE, sizeof(int));
                g_hash_table_insert(columns->positions, clean, list);
                g_ptr_array_add(columns->clean, clean);
            } else {
                g_free(clean);
            }
            int index = (int)i;
            g_array_append_val(list, index);
        }
    }
    j_free(doc);
    return columns;
}

void columns_free(Columns *columns) {
    if (!columns)
        return;
    g_ptr_array_free(columns->names, TRUE);
    g_ptr_array_free(columns->clean, TRUE);
    g_hash_table_destroy(columns->positions);
    g_free(columns);
}

GArray *columns_get(const Columns *columns, const char *name) {
    char *folded = casefold(name);
    GArray *found = g_hash_table_lookup(columns->positions, folded);
    g_free(folded);
    return found;
}

static gboolean has(const Columns *columns, const char *clean) {
    return g_hash_table_contains(columns->positions, clean);
}

// Flat audit records lack AuditData.
static gboolean flat_audit(const Columns *columns) {
    return !has(columns, "auditdata") && has(columns, "creationtime") && has(columns, "operation") &&
           has(columns, "recordtype");
}

gboolean columns_support(const Columns *columns, const char *field) {
    if (has(columns, "auditdata") || flat_audit(columns))
        return TRUE;
    const Slot *slot = slot_find(field);
    for (int i = 0; slot && i < 5 && slot->outer[i]; i++)
        if (columns_get(columns, slot->outer[i]))
            return TRUE;
    if (!strcmp(field, "target"))
        for (guint i = 0; i < columns->clean->len; i++)
            if (g_str_has_prefix(columns->clean->pdata[i], "target"))
                return TRUE;
    return FALSE;
}

// JSON rows may record presence.
static gboolean row_has(const JV *row, guint width, guint index) {
    if (index >= row->n)
        return FALSE;
    if (row->n != width + 1 || row->u.a[width]->t != J_ARR)
        return TRUE;
    if (index >= width)
        return FALSE;
    const JV *present = row->u.a[width];
    for (guint i = 0; i < present->n; i++)
        if (present->u.a[i]->t == J_NUM && (guint)atoi(present->u.a[i]->u.s) == index)
            return TRUE;
    return FALSE;
}

EventFields *event_fields_new(const char *headers, const char *raw) {
    EventFields *fields = g_new0(EventFields, 1);
    fields->columns = columns_new(headers);
    fields->own_columns = TRUE;
    fields->row = j_parse(raw, -1, 0, NULL);
    return fields;
}

void event_fields_free(EventFields *fields) {
    if (!fields)
        return;
    if (fields->own_columns)
        columns_free(fields->columns);
    j_free(fields->row);
    j_free(fields->audit_doc);
    g_free(fields);
}

static void outer(EventFields *fields, const char *name, GPtrArray *out) {
    GArray *positions = columns_get(fields->columns, name);
    const JV *row = fields->row ? fields->row->root : NULL;
    if (!positions || !row || row->t != J_ARR)
        return;
    for (guint i = 0; i < positions->len; i++) {
        guint index = (guint)g_array_index(positions, int, i);
        if (row_has(row, fields->columns->names->len, index))
            g_ptr_array_add(out, row->u.a[index]);
    }
}

static const JV *audit(EventFields *fields) {
    static const JV empty = {J_OBJ, 0, {NULL}};
    if (fields->audit)
        return fields->audit;
    fields->audit = &empty;
    const JV *row = fields->row ? fields->row->root : NULL;
    if (!row || row->t != J_ARR)
        return fields->audit;
    if (flat_audit(fields->columns)) {
        // Present the row as AuditData.
        GString *text = g_string_new("{");
        guint width = fields->columns->names->len;
        for (guint i = 0; i < width; i++) {
            if (!row_has(row, width, i))
                continue;
            if (text->len > 1)
                g_string_append_c(text, ',');
            j_quote(text, fields->columns->names->pdata[i], -1);
            g_string_append_c(text, ':');
            j_dump(text, row->u.a[i], J_RAW_NUMBERS);
        }
        g_string_append_c(text, '}');
        fields->audit_doc = j_parse(text->str, text->len, 0, NULL);
        g_string_free(text, TRUE);
        if (fields->audit_doc)
            fields->audit = fields->audit_doc->root;
        return fields->audit;
    }
    GPtrArray *cells = g_ptr_array_new();
    outer(fields, "AuditData", cells);
    if (cells->len) {
        const JV *decoded = j_decode(fields->row, cells->pdata[0]);
        if (decoded->t == J_OBJ)
            fields->audit = decoded;
    }
    g_ptr_array_free(cells, TRUE);
    return fields->audit;
}

static gboolean truthy(const JV *value) {
    if (!value)
        return FALSE;
    switch (value->t) {
    case J_NULL:
    case J_FALSE:
        return FALSE;
    case J_TRUE:
        return TRUE;
    case J_NUM:
        return g_ascii_strtod(value->u.s, NULL) != 0 || g_ascii_isalpha(value->u.s[0]);
    default:
        return value->n > 0;
    }
}

static const JV *first_truthy(const JV *object, const char *a, const char *b, const char *c) {
    const JV *value = j_get(object, a);
    if (!truthy(value))
        value = j_get(object, b);
    if (!truthy(value))
        value = j_get(object, c);
    return value;
}

static void add_text(GPtrArray *texts, const JV *value) {
    if (value && value->t == J_STR)
        g_ptr_array_add(texts, g_strdup(value->u.s));
}

static void split_recipients(GPtrArray *texts, const char *cell, gboolean statuses) {
    char **entries = g_strsplit(cell, ";", -1);
    for (char **entry = entries; *entry; entry++) {
        char *mark = strstr(*entry, "##");
        if (statuses) {
            if (mark)
                g_ptr_array_add(texts, g_strdup(mark + 2));
        } else {
            if (mark)
                *mark = 0;
            g_ptr_array_add(texts, py_strip(*entry));
        }
    }
    g_strfreev(entries);
}

static gboolean target_column(const char *clean) {
    if (!g_str_has_prefix(clean, "target") || !g_ascii_isdigit(clean[6]))
        return FALSE;
    const char *p = clean + 6;
    while (g_ascii_isdigit(*p))
        p++;
    return !strcmp(p, "userprincipalname") || !strcmp(p, "displayname") || !strcmp(p, "objectid");
}

GPtrArray *event_values(EventFields *fields, const char *field) {
    GPtrArray *texts = g_ptr_array_new_with_free_func(g_free);
    const Slot *slot = slot_find(field);
    if (!slot)
        return texts;
    GPtrArray *cells = g_ptr_array_new();
    for (int i = 0; i < 5 && slot->outer[i]; i++)
        outer(fields, slot->outer[i], cells);
    const JV *record = audit(fields);
    for (int i = 0; i < 3 && slot->inner[i]; i++) {
        JV *value = j_get(record, slot->inner[i]);
        if (value)
            g_ptr_array_add(cells, value);
    }
    const JV *item = j_get(record, "Item");
    if (!strcmp(field, "recipient")) {
        for (guint i = 0; i < cells->len; i++) {
            const JV *cell = cells->pdata[i];
            if (cell->t == J_STR)
                split_recipients(texts, cell->u.s, FALSE);
        }
        const JV *recipients = j_get(item, "Recipients");
        for (guint i = 0; recipients && recipients->t == J_ARR && i < recipients->n; i++) {
            const JV *entry = recipients->u.a[i];
            if (entry->t == J_OBJ)
                add_text(texts, first_truthy(entry, "Address", "EmailAddress", "SmtpAddress"));
            else
                add_text(texts, entry);
        }
    } else if (!strcmp(field, "delivery")) {
        g_ptr_array_set_size(cells, 0);
        outer(fields, "Status", cells);
        for (guint i = 0; i < cells->len; i++)
            add_text(texts, cells->pdata[i]);
        g_ptr_array_set_size(cells, 0);
        outer(fields, "recipient_status", cells);
        for (guint i = 0; i < cells->len; i++) {
            const JV *cell = cells->pdata[i];
            if (cell->t == J_STR)
                split_recipients(texts, cell->u.s, TRUE);
        }
    } else {
        for (guint i = 0; i < cells->len; i++)
            add_text(texts, cells->pdata[i]);
        if (!strcmp(field, "session")) {
            add_text(texts, j_get(j_get(record, "AppAccessContext"), "AADSessionId"));
        } else if (!strcmp(field, "subject")) {
            add_text(texts, j_get(item, "Subject"));
        } else if (!strcmp(field, "messageid")) {
            add_text(texts, j_get(item, "InternetMessageId"));
        } else if (!strcmp(field, "folder") || !strcmp(field, "mailitem")) {
            const JV *folders = j_get(record, "Folders");
            for (guint i = 0; folders && folders->t == J_ARR && i < folders->n; i++) {
                const JV *folder = folders->u.a[i];
                if (folder->t != J_OBJ)
                    continue;
                if (!strcmp(field, "folder")) {
                    add_text(texts, j_get(folder, "Path"));
                    continue;
                }
                const JV *items = j_get(folder, "FolderItems");
                for (guint k = 0; items && items->t == J_ARR && k < items->n; k++)
                    if (items->u.a[k]->t == J_OBJ)
                        add_text(texts, first_truthy(items->u.a[k], "InternetMessageId", "ImmutableId", "Id"));
            }
        } else if (!strcmp(field, "rule") || !strcmp(field, "access")) {
            gboolean rule = !strcmp(field, "rule");
            gboolean wanted = TRUE;
            if (rule) {
                char *operation = j_text(j_get(record, "Operation"), FALSE);
                wanted = contains_folded(operation, "rule");
                g_free(operation);
            }
            const JV *list = j_get(record, rule ? "Parameters" : "OperationProperties");
            for (guint i = 0; wanted && list && list->t == J_ARR && i < list->n; i++) {
                const JV *name = j_get(list->u.a[i], "Name");
                if (!name || name->t != J_STR)
                    continue;
                if (rule ? (!strcmp(name->u.s, "Name") || !strcmp(name->u.s, "Identity"))
                         : !strcmp(name->u.s, "MailAccessType"))
                    add_text(texts, j_get(list->u.a[i], "Value"));
            }
        } else if (!strcmp(field, "target")) {
            for (guint i = 0; i < fields->columns->clean->len; i++) {
                const char *clean = fields->columns->clean->pdata[i];
                if (!target_column(clean))
                    continue;
                g_ptr_array_set_size(cells, 0);
                outer(fields, clean, cells);
                for (guint k = 0; k < cells->len; k++)
                    add_text(texts, cells->pdata[k]);
            }
        }
    }
    g_ptr_array_free(cells, TRUE);
    // Keep first distinct spelling.
    GPtrArray *unique = g_ptr_array_new_with_free_func(g_free);
    GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    for (guint i = 0; i < texts->len; i++) {
        char *value = py_strip(texts->pdata[i]);
        char *folded = casefold(value);
        if (*value && g_hash_table_add(seen, folded)) {
            g_ptr_array_add(unique, value);
        } else {
            if (!*value)
                g_free(folded);
            g_free(value);
        }
    }
    g_hash_table_destroy(seen);
    g_ptr_array_free(texts, TRUE);
    return unique;
}

char *escape_pointer(const char *key) {
    GString *out = g_string_new(NULL);
    for (const char *p = key; *p; p++) {
        if (*p == '~')
            g_string_append(out, "~0");
        else if (*p == '/')
            g_string_append(out, "~1");
        else
            g_string_append_c(out, *p);
    }
    return g_string_free(out, FALSE);
}

static char *unescape_part(const char *part) {
    GString *out = g_string_new(NULL);
    // Decode slashes before tildes.
    for (const char *p = part; *p; p++) {
        if (p[0] == '~' && p[1] == '1') {
            g_string_append_c(out, '/');
            p++;
        } else {
            g_string_append_c(out, *p);
        }
    }
    char *first = g_string_free(out, FALSE);
    out = g_string_new(NULL);
    for (const char *p = first; *p; p++) {
        g_string_append_c(out, *p);
        if (p[0] == '~' && p[1] == '0')
            p++;
    }
    g_free(first);
    return g_string_free(out, FALSE);
}

typedef struct {
    JDoc *doc;
    char **parts;
    guint count;
    gboolean presence;
    gboolean done;
    GPtrArray *out;
} Walk;

static void walk(Walk *state, const JV *actual, guint depth) {
    if (state->done)
        return;
    if (depth == state->count) {
        if (state->presence) {
            g_ptr_array_add(state->out, g_strdup(""));
            state->done = TRUE;
        } else if (!j_is_container(actual)) {
            g_ptr_array_add(state->out, j_scalar(actual));
        }
        return;
    }
    const JV *object = j_decode(state->doc, actual);
    const char *key = state->parts[depth];
    if (object->t == J_OBJ) {
        JV *child = j_get(object, key);
        if (child)
            walk(state, child, depth + 1);
    } else if (object->t == J_ARR) {
        if (!strcmp(key, "*")) {
            for (guint i = 0; i < object->n; i++)
                walk(state, object->u.a[i], depth + 1);
        } else {
            size_t length = strlen(key);
            gboolean decimal = length > 0 && length < 10;
            for (const char *p = key; decimal && *p; p++)
                decimal = g_ascii_isdigit(*p);
            if (decimal && (guint)atoi(key) < object->n)
                walk(state, object->u.a[atoi(key)], depth + 1);
        }
    }
}

GPtrArray *pointer_values(Columns *columns, const char *raw, const char *pointer, gboolean presence) {
    GPtrArray *out = g_ptr_array_new_with_free_func(g_free);
    if (!pointer || pointer[0] != '/')
        return out;
    char **split = g_strsplit(pointer + 1, "/", -1);
    guint total = g_strv_length(split);
    for (guint i = 0; i < total; i++) {
        char *part = unescape_part(split[i]);
        g_free(split[i]);
        split[i] = part;
    }
    const char *head = split[0];
    int ordinal = -1;
    if (head[0] == '@' && head[1] >= '1' && head[1] <= '9') {
        const char *p = head + 1;
        while (g_ascii_isdigit(*p) && p - head <= 6)
            p++;
        if (*p == ':') {
            ordinal = atoi(head + 1) - 1;
            head = p + 1;
        }
    }
    char *clean = clean_header(head);
    GArray *positions = g_hash_table_lookup(columns->positions, clean);
    g_free(clean);
    JDoc *doc = positions ? j_parse(raw, -1, 0, NULL) : NULL;
    if (doc && doc->root->t == J_ARR) {
        Walk state = {doc, split + 1, total - 1, presence, FALSE, out};
        for (guint i = 0; i < positions->len; i++) {
            if (ordinal >= 0 && (int)i != ordinal)
                continue;
            guint index = (guint)g_array_index(positions, int, i);
            if (row_has(doc->root, columns->names->len, index))
                walk(&state, doc->root->u.a[index], 0);
        }
    }
    j_free(doc);
    g_strfreev(split);
    return out;
}

char *source_label(const char *kind) {
    static const char *const families[] = {"Interactive", "Non-interactive", "Application",
                                           "Managed identity", "Workload",       "User"};
    static const char *const reports[] = {"sign-ins", "auth details"};
    char *folded = casefold(kind);
    char *result = NULL;
    for (guint f = 0; f < G_N_ELEMENTS(families) && !result; f++) {
        for (guint r = 0; r < 2 && !result; r++) {
            char *name = g_strdup_printf("%s %s", families[f], reports[r]);
            char *lower = g_ascii_strdown(name, -1);
            if (!strcmp(lower, folded))
                result = g_strdup_printf("Entra \xc2\xb7 %s", name);
            g_free(lower);
            g_free(name);
        }
    }
    g_free(folded);
    return result ? result : g_strdup(kind);
}

/* SQL functions share column caches. */

static Columns *cached_columns(sqlite3_context *context, const char *headers) {
    GHashTable *cache = sqlite3_user_data(context);
    Columns *columns = g_hash_table_lookup(cache, headers);
    if (!columns) {
        if (g_hash_table_size(cache) > 256)
            g_hash_table_remove_all(cache);
        columns = columns_new(headers);
        g_hash_table_insert(cache, g_strdup(headers), columns);
    }
    return columns;
}

static const char *arg(sqlite3_value **values, int index) {
    const char *text = (const char *)sqlite3_value_text(values[index]);
    return text ? text : "";
}

static void fn_source_label(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    sqlite3_result_text(context, source_label(arg(values, 0)), -1, g_free);
}

static EventFields *borrowed_fields(sqlite3_context *context, sqlite3_value **values) {
    EventFields *fields = g_new0(EventFields, 1);
    fields->columns = cached_columns(context, arg(values, 0));
    fields->row = j_parse(arg(values, 1), -1, 0, NULL);
    return fields;
}

static void fn_event_values(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    EventFields *fields = borrowed_fields(context, values);
    GPtrArray *found = event_values(fields, arg(values, 2));
    GString *out = g_string_new("[");
    for (guint i = 0; i < found->len; i++) {
        if (i)
            g_string_append_c(out, ',');
        j_quote(out, found->pdata[i], -1);
    }
    g_string_append_c(out, ']');
    g_ptr_array_free(found, TRUE);
    event_fields_free(fields);
    sqlite3_result_text(context, g_string_free(out, FALSE), -1, g_free);
}

static void fn_event_match(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    const char *field = arg(values, 2), *op = arg(values, 3);
    gboolean negate = !strcmp(op, "!=");
    Columns *columns = cached_columns(context, arg(values, 0));
    if (!columns_support(columns, field)) {
        sqlite3_result_int(context, negate);
        return;
    }
    EventFields *fields = borrowed_fields(context, values);
    GPtrArray *found = event_values(fields, field);
    char *needle = casefold(arg(values, 4));
    gboolean contains = !strcmp(op, "contains"), hit = FALSE;
    for (guint i = 0; i < found->len && !hit; i++)
        hit = contains ? contains_folded(found->pdata[i], needle) : equals_folded(found->pdata[i], needle);
    g_free(needle);
    g_ptr_array_free(found, TRUE);
    event_fields_free(fields);
    sqlite3_result_int(context, negate ? !hit : hit);
}

static void fn_match_path(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    const char *op = arg(values, 3);
    Columns *columns = cached_columns(context, arg(values, 0));
    gboolean exists = !strcmp(op, "exists");
    GPtrArray *found = pointer_values(columns, arg(values, 1), arg(values, 2), exists);
    gboolean hit = FALSE;
    if (exists) {
        hit = found->len > 0;
    } else {
        char *needle = casefold(arg(values, 4));
        gboolean contains = !strcmp(op, "contains");
        for (guint i = 0; i < found->len && !hit; i++)
            hit = contains ? contains_folded(found->pdata[i], needle) : equals_folded(found->pdata[i], needle);
        g_free(needle);
        if (!strcmp(op, "!="))
            hit = !hit;
    }
    g_ptr_array_free(found, TRUE);
    sqlite3_result_int(context, hit);
}

char *field_display(Columns *columns, const char *raw, const char *pointer) {
    GPtrArray *found = pointer_values(columns, raw, pointer, FALSE);
    GString *out = g_string_new(NULL);
    for (guint i = 0; i < found->len; i++) {
        gboolean repeat = FALSE;
        for (guint k = 0; k < i && !repeat; k++)
            repeat = !strcmp(found->pdata[k], found->pdata[i]);
        if (repeat)
            continue;
        if (out->len)
            g_string_append(out, " \xc2\xb7 ");
        g_string_append(out, found->pdata[i]);
    }
    g_ptr_array_free(found, TRUE);
    return g_string_free(out, FALSE);
}

static void fn_field_display(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    Columns *columns = cached_columns(context, arg(values, 0));
    sqlite3_result_text(context, field_display(columns, arg(values, 1), arg(values, 2)), -1, g_free);
}

static int collate_folded(void *unused, int left_size, const void *left, int right_size, const void *right) {
    (void)unused;
    char *a = g_strndup(left, left_size), *b = g_strndup(right, right_size);
    char *fa = casefold(a), *fb = casefold(b);
    int order = strcmp(fa, fb);
    g_free(a);
    g_free(b);
    g_free(fa);
    g_free(fb);
    return order;
}

static void free_cache(void *cache) {
    g_hash_table_destroy(cache);
}

void register_functions(sqlite3 *db) {
    static const struct {
        const char *name;
        int count;
        void (*call)(sqlite3_context *, int, sqlite3_value **);
    } functions[] = {
        {"source_label", 1, fn_source_label}, {"event_values", 3, fn_event_values},
        {"event_match", 5, fn_event_match},   {"match_path", 5, fn_match_path},
        {"field_display", 3, fn_field_display},
    };
    for (guint i = 0; i < G_N_ELEMENTS(functions); i++) {
        GHashTable *cache =
            g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)columns_free);
        sqlite3_create_function_v2(db, functions[i].name, functions[i].count, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                   cache, functions[i].call, NULL, NULL, free_cache);
    }
    sqlite3_create_collation(db, "BQL_TEXT", SQLITE_UTF8, NULL, collate_folded);
}
