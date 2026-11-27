#include "core.h"

#include <string.h>

// Column and AuditData aliases.
const Slot SLOTS[] = {
    {"device", {"Device ID"}, {"DeviceId"}},
    {"session", {"Session ID"}, {"SessionId", "AADSessionId"}},
    {"correlation", {"Correlation ID", "CorrelationId"}, {"CorrelationId"}},
    {"application", {"Application", "appDisplayName"}, {"ApplicationDisplayName"}},
    {"appid", {"Application ID", "appId"}, {"AppId", "ClientAppId"}},
    {"location", {"Location"}, {NULL}},
    {"os", {"Operating System"}, {NULL}},
    {"client", {"Client app", "clientAppUsed"}, {"ClientInfoString"}},
    {"authmethod", {"Authentication method"}, {NULL}},
    {"conditionalaccess", {"Conditional Access", "conditionalAccessStatus"}, {NULL}},
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
    // Graph nests device details.
    if ((!strcmp(field, "device") || !strcmp(field, "os")) && has(columns, "devicedetail"))
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
        if (!strcmp(field, "location")) {
            // Graph locations are objects.
            for (guint i = 0; i < cells->len; i++) {
                const JV *place = cells->pdata[i];
                GString *joined = g_string_new(NULL);
                static const char *const parts[] = {"city", "state", "countryOrRegion"};
                for (guint k = 0; place->t == J_OBJ && k < G_N_ELEMENTS(parts); k++) {
                    const JV *part = j_get(place, parts[k]);
                    if (part && part->t == J_STR && *part->u.s)
                        g_string_append_printf(joined, "%s%s", joined->len ? ", " : "", part->u.s);
                }
                if (joined->len)
                    g_ptr_array_add(texts, g_strdup(joined->str));
                g_string_free(joined, TRUE);
            }
        } else if (!strcmp(field, "device") || !strcmp(field, "os")) {
            g_ptr_array_set_size(cells, 0);
            outer(fields, "deviceDetail", cells);
            for (guint i = 0; i < cells->len; i++)
                add_text(texts, j_get(cells->pdata[i], field[0] == 'd' ? "deviceId" : "operatingSystem"));
        }
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
    gboolean json;
} Walk;

static void walk(Walk *state, const JV *actual, guint depth) {
    if (state->done)
        return;
    if (depth == state->count) {
        if (state->presence) {
            g_ptr_array_add(state->out, g_strdup(""));
            state->done = TRUE;
        } else if (state->json) {
            GString *text = g_string_new(NULL);
            j_dump(text, j_decode(state->doc, actual), J_RAW_NUMBERS);
            g_ptr_array_add(state->out, g_string_free(text, FALSE));
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

typedef JDoc *(*RowSource)(gpointer user);
static GPtrArray *pointer_walk(Columns *columns, const char *raw, const char *pointer, gboolean presence, gboolean json,
                               RowSource source, gpointer user);

GPtrArray *pointer_values(Columns *columns, const char *raw, const char *pointer, gboolean presence) {
    return pointer_walk(columns, raw, pointer, presence, FALSE, NULL, NULL);
}

// Returns matched nodes as JSON.
char *field_json(Columns *columns, const char *raw, const char *pointer) {
    GPtrArray *found = pointer_walk(columns, raw, pointer, FALSE, TRUE, NULL, NULL);
    char *out = NULL;
    if (found->len == 1) {
        out = g_strdup(found->pdata[0]);
    } else if (found->len > 1) {
        GString *list = g_string_new("[");
        for (guint i = 0; i < found->len; i++)
            g_string_append_printf(list, "%s%s", i ? "," : "", (char *)found->pdata[i]);
        out = g_string_free(g_string_append_c(list, ']'), FALSE);
    }
    g_ptr_array_free(found, TRUE);
    return out;
}

static GPtrArray *pointer_walk(Columns *columns, const char *raw, const char *pointer, gboolean presence, gboolean json,
                               RowSource source, gpointer user) {
    GPtrArray *out = g_ptr_array_new_with_free_func(g_free);
    if (!pointer || pointer[0] != '/')
        return out;
    char **split = g_strsplit(pointer + 1, "/", -1);
    guint total = g_strv_length(split);
    // A lone slash names nothing.
    if (!total) {
        g_strfreev(split);
        return out;
    }
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
    // Borrowed rows stay cached.
    JDoc *doc = !positions ? NULL : source ? source(user) : j_parse(raw, -1, 0, NULL);
    if (doc && doc->root->t == J_ARR) {
        Walk state = {doc, split + 1, total - 1, presence, FALSE, out, json};
        for (guint i = 0; i < positions->len; i++) {
            if (ordinal >= 0 && (int)i != ordinal)
                continue;
            guint index = (guint)g_array_index(positions, int, i);
            if (row_has(doc->root, columns->names->len, index))
                walk(&state, doc->root->u.a[index], 0);
        }
    }
    if (!source)
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

typedef struct {
    int refs;
    GHashTable *columns;
    // Last looked-up headers.
    char *headers;
    Columns *layout;
    // Last parsed row.
    char *raw;
    EventFields *fields;
} Shared;

static void forget_row(Shared *shared) {
    event_fields_free(shared->fields);
    g_free(shared->raw);
    shared->fields = NULL;
    shared->raw = NULL;
}

static Columns *cached_columns(sqlite3_context *context, const char *headers) {
    Shared *shared = sqlite3_user_data(context);
    if (shared->headers && !strcmp(shared->headers, headers))
        return shared->layout;
    GHashTable *cache = shared->columns;
    Columns *columns = g_hash_table_lookup(cache, headers);
    if (!columns) {
        if (g_hash_table_size(cache) > 256) {
            forget_row(shared);
            g_hash_table_remove_all(cache);
        }
        columns = columns_new(headers);
        g_hash_table_insert(cache, g_strdup(headers), columns);
    }
    g_free(shared->headers);
    shared->headers = g_strdup(headers);
    shared->layout = columns;
    return columns;
}

// Folds case and outer spaces.
static char *fold_trimmed(const char *text) {
    char *stripped = py_strip(text);
    char *folded = casefold(stripped);
    g_free(stripped);
    return folded;
}

static gboolean folded_hit(GPtrArray *found, const char *value, gboolean contains) {
    char *needle = contains ? casefold(value) : fold_trimmed(value);
    gboolean hit = FALSE;
    for (guint i = 0; i < found->len && !hit; i++) {
        if (contains) {
            hit = contains_folded(found->pdata[i], needle);
        } else {
            char *folded = fold_trimmed(found->pdata[i]);
            hit = !strcmp(folded, needle);
            g_free(folded);
        }
    }
    g_free(needle);
    return hit;
}



// Plain logs skip tree parsing.
static gboolean plain_slot_values(Columns *columns, const char *field, const char *raw, GPtrArray *out) {
    if (has(columns, "auditdata") || flat_audit(columns) || !strcmp(field, "recipient") || !strcmp(field, "delivery") ||
        !strcmp(field, "target") || has(columns, "devicedetail"))
        return FALSE;
    const Slot *slot = slot_find(field);
    int indexes[32];
    guint count = 0;
    for (int i = 0; slot && i < 5 && slot->outer[i]; i++) {
        GArray *positions = columns_get(columns, slot->outer[i]);
        for (guint k = 0; positions && k < positions->len; k++) {
            if (count == G_N_ELEMENTS(indexes))
                return FALSE;
            indexes[count++] = g_array_index(positions, int, k);
        }
    }
    return slot && j_row_strings(raw, indexes, count, columns->names->len, FALSE, out);
}

static const char *arg(sqlite3_value **values, int index) {
    const char *text = (const char *)sqlite3_value_text(values[index]);
    return text ? text : "";
}

static void fn_fold(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    sqlite3_result_text(context, fold_trimmed(arg(values, 0)), -1, g_free);
}

static void fn_source_label(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    sqlite3_result_text(context, source_label(arg(values, 0)), -1, g_free);
}

// Filter terms reuse one parse.
static EventFields *borrowed_fields(sqlite3_context *context, sqlite3_value **values) {
    Shared *shared = sqlite3_user_data(context);
    Columns *columns = cached_columns(context, arg(values, 0));
    const char *raw = arg(values, 1);
    if (shared->fields && shared->fields->columns == columns && !strcmp(shared->raw, raw))
        return shared->fields;
    forget_row(shared);
    EventFields *fields = g_new0(EventFields, 1);
    fields->columns = columns;
    fields->row = j_parse(raw, -1, 0, NULL);
    shared->fields = fields;
    shared->raw = g_strdup(raw);
    return fields;
}

typedef struct {
    sqlite3_context *context;
    sqlite3_value **values;
} Borrow;

static JDoc *borrowed_row(gpointer user) {
    Borrow *borrow = user;
    return borrowed_fields(borrow->context, borrow->values)->row;
}

static void fn_event_values(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    EventFields *fields = borrowed_fields(context, values);
    GPtrArray *found = event_values(fields, arg(values, 2));
    GString *out = g_string_new("[");
    for (guint i = 0; i < found->len; i++) {
        if (i)
            g_string_append_c(out, ',');
        // Groups ignore outer spaces.
        char *stripped = py_strip(found->pdata[i]);
        j_quote(out, stripped, -1);
        g_free(stripped);
    }
    g_string_append_c(out, ']');
    g_ptr_array_free(found, TRUE);
    sqlite3_result_text(context, g_string_free(out, FALSE), -1, g_free);
}

// Shows a named field.
static void fn_slot_display(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    EventFields *fields = borrowed_fields(context, values);
    GPtrArray *found = event_values(fields, arg(values, 2));
    GString *out = g_string_new(NULL);
    for (guint i = 0; i < found->len; i++) {
        gboolean repeat = FALSE;
        for (guint k = 0; k < i && !repeat; k++)
            repeat = !strcmp(found->pdata[k], found->pdata[i]);
        if (!repeat)
            g_string_append_printf(out, "%s%s", out->len ? " · " : "", (char *)found->pdata[i]);
    }
    g_ptr_array_free(found, TRUE);
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
    GPtrArray *found = g_ptr_array_new_with_free_func(g_free);
    if (!plain_slot_values(columns, field, arg(values, 1), found)) {
        g_ptr_array_free(found, TRUE);
        found = event_values(borrowed_fields(context, values), field);
    }
    gboolean hit = folded_hit(found, arg(values, 4), !strcmp(op, "contains"));
    g_ptr_array_free(found, TRUE);
    sqlite3_result_int(context, negate ? !hit : hit);
}

static void fn_match_path(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    const char *op = arg(values, 3);
    Columns *columns = cached_columns(context, arg(values, 0));
    gboolean exists = !strcmp(op, "exists");
    Borrow borrow = {context, values};
    const char *pointer = arg(values, 2);
    GPtrArray *found = NULL;
    // Top-level text cells skip trees.
    if (!exists && pointer[0] == '/' && pointer[1] != '@' && !strchr(pointer + 1, '/') && !strchr(pointer, '~')) {
        char *clean = clean_header(pointer + 1);
        GArray *positions = g_hash_table_lookup(columns->positions, clean);
        g_free(clean);
        found = g_ptr_array_new_with_free_func(g_free);
        if (positions && (positions->len > 32 || !j_row_strings(arg(values, 1), (const int *)positions->data,
                                                               positions->len, columns->names->len, TRUE, found)))
            g_clear_pointer(&found, g_ptr_array_unref);
    }
    if (!found)
        found = pointer_walk(columns, arg(values, 1), pointer, exists, FALSE, borrowed_row, &borrow);
    gboolean hit = FALSE;
    if (exists) {
        hit = found->len > 0;
    } else {
        hit = folded_hit(found, arg(values, 4), !strcmp(op, "contains"));
        if (!strcmp(op, "!="))
            hit = !hit;
    }
    g_ptr_array_free(found, TRUE);
    sqlite3_result_int(context, hit);
}

static char *joined_values(GPtrArray *found) {
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

char *field_display(Columns *columns, const char *raw, const char *pointer) {
    return joined_values(pointer_values(columns, raw, pointer, FALSE));
}

static void fn_field_display(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;
    Columns *columns = cached_columns(context, arg(values, 0));
    Borrow borrow = {context, values};
    GPtrArray *found = pointer_walk(columns, arg(values, 1), arg(values, 2), FALSE, FALSE, borrowed_row, &borrow);
    sqlite3_result_text(context, joined_values(found), -1, g_free);
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

static void free_cache(void *data) {
    Shared *shared = data;
    if (--shared->refs)
        return;
    forget_row(shared);
    g_free(shared->headers);
    g_hash_table_destroy(shared->columns);
    g_free(shared);
}

void register_functions(sqlite3 *db) {
    static const struct {
        const char *name;
        int count;
        void (*call)(sqlite3_context *, int, sqlite3_value **);
    } functions[] = {
        {"source_label", 1, fn_source_label}, {"event_values", 3, fn_event_values},
        {"event_match", 5, fn_event_match},   {"match_path", 5, fn_match_path},
        {"field_display", 3, fn_field_display}, {"slot_display", 3, fn_slot_display},
        {"bql_fold", 1, fn_fold},
    };
    // One cache per connection.
    Shared *shared = g_new0(Shared, 1);
    shared->columns = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)columns_free);
    shared->refs = G_N_ELEMENTS(functions);
    for (guint i = 0; i < G_N_ELEMENTS(functions); i++)
        sqlite3_create_function_v2(db, functions[i].name, functions[i].count, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                   shared, functions[i].call, NULL, NULL, free_cache);
    sqlite3_create_collation(db, "BQL_TEXT", SQLITE_UTF8, NULL, collate_folded);
}
