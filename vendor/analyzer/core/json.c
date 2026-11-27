#include "core.h"

#include <math.h>
#include <string.h>
#include <yyjson.h>

#define BLOCK (64 * 1024)
#define MAX_DEPTH 990

static void *arena(JDoc *doc, gsize size) {
    size = (size + 7) & ~(gsize)7;
    if (size > BLOCK / 4) {
        // Large values get blocks.
        void *block = g_malloc(size);
        if (doc->blocks)
            doc->blocks->next = g_slist_prepend(doc->blocks->next, block);
        else {
            doc->blocks = g_slist_prepend(NULL, block);
            doc->used = BLOCK;
        }
        return block;
    }
    if (!doc->blocks || doc->used + size > BLOCK) {
        doc->blocks = g_slist_prepend(doc->blocks, g_malloc(BLOCK));
        doc->used = 0;
    }
    void *out = (char *)doc->blocks->data + doc->used;
    doc->used += size;
    return out;
}

static const char *arena_text(JDoc *doc, const char *text, gsize length) {
    char *copy = arena(doc, length + 1);
    memcpy(copy, text, length);
    copy[length] = 0;
    return copy;
}

static JV *convert(JDoc *doc, yyjson_val *value, int depth, int flags, GError **error) {
    if (depth > MAX_DEPTH) {
        bec_fail(error, "JSON nesting is too deep");
        return NULL;
    }
    JV *out = arena(doc, sizeof(JV));
    out->n = 0;
    out->u.s = NULL;
    switch (yyjson_get_type(value)) {
    case YYJSON_TYPE_NULL:
        out->t = J_NULL;
        break;
    case YYJSON_TYPE_BOOL:
        out->t = yyjson_get_bool(value) ? J_TRUE : J_FALSE;
        break;
    case YYJSON_TYPE_RAW:
    case YYJSON_TYPE_NUM:
        out->t = J_NUM;
        out->n = (guint)yyjson_get_len(value);
        out->u.s = arena_text(doc, yyjson_get_raw(value), out->n);
        break;
    case YYJSON_TYPE_STR:
        out->t = J_STR;
        out->n = (guint)yyjson_get_len(value);
        out->u.s = arena_text(doc, yyjson_get_str(value), out->n);
        break;
    case YYJSON_TYPE_ARR: {
        out->t = J_ARR;
        gsize count = yyjson_arr_size(value);
        out->u.a = arena(doc, sizeof(JV *) * MAX(count, 1));
        yyjson_arr_iter iter = yyjson_arr_iter_with(value);
        yyjson_val *item;
        while ((item = yyjson_arr_iter_next(&iter))) {
            JV *child = convert(doc, item, depth + 1, flags, error);
            if (!child)
                return NULL;
            out->u.a[out->n++] = child;
        }
        break;
    }
    case YYJSON_TYPE_OBJ: {
        out->t = J_OBJ;
        gsize count = yyjson_obj_size(value);
        out->u.m = arena(doc, sizeof(JMember) * MAX(count, 1));
        GHashTable *seen = count > 12 ? g_hash_table_new(g_str_hash, g_str_equal) : NULL;
        yyjson_obj_iter iter = yyjson_obj_iter_with(value);
        yyjson_val *key;
        while ((key = yyjson_obj_iter_next(&iter))) {
            JV *child = convert(doc, yyjson_obj_iter_get_val(key), depth + 1, flags, error);
            if (!child) {
                if (seen)
                    g_hash_table_destroy(seen);
                return NULL;
            }
            const char *name = arena_text(doc, yyjson_get_str(key), yyjson_get_len(key));
            gssize found = -1;
            if (seen) {
                gpointer slot;
                if (g_hash_table_lookup_extended(seen, name, NULL, &slot))
                    found = GPOINTER_TO_INT(slot);
            } else {
                for (guint i = 0; i < out->n && found < 0; i++)
                    if (!strcmp(out->u.m[i].key, name))
                        found = i;
            }
            if (found >= 0) {
                if (flags & J_STRICT_KEYS) {
                    bec_fail(error, "Duplicate key \"%s\" makes this record ambiguous", name);
                    if (seen)
                        g_hash_table_destroy(seen);
                    return NULL;
                }
                // Later duplicates win.
                out->u.m[found].v = child;
                continue;
            }
            if (seen)
                g_hash_table_insert(seen, (gpointer)name, GINT_TO_POINTER(out->n));
            out->u.m[out->n].key = name;
            out->u.m[out->n++].v = child;
        }
        if (seen)
            g_hash_table_destroy(seen);
        break;
    }
    default:
        bec_fail(error, "Unsupported JSON value");
        return NULL;
    }
    return out;
}

static JV *parse_into(JDoc *doc, const char *text, gsize length, int flags, GError **error) {
    yyjson_read_err problem;
    yyjson_doc *source = yyjson_read_opts((char *)text, length,
                                          YYJSON_READ_NUMBER_AS_RAW | YYJSON_READ_ALLOW_INF_AND_NAN, NULL, &problem);
    if (!source) {
        bec_fail(error, "Malformed JSON near byte %" G_GSIZE_FORMAT ": %s", problem.pos + 1, problem.msg);
        return NULL;
    }
    JV *root = convert(doc, yyjson_doc_get_root(source), 0, flags, error);
    yyjson_doc_free(source);
    return root;
}

JDoc *j_parse(const char *text, gssize length, int flags, GError **error) {
    JDoc *doc = g_new0(JDoc, 1);
    doc->root = parse_into(doc, text, length < 0 ? strlen(text) : (gsize)length, flags, error);
    if (!doc->root) {
        j_free(doc);
        return NULL;
    }
    return doc;
}

void j_free(JDoc *doc) {
    if (!doc)
        return;
    g_slist_free_full(doc->blocks, g_free);
    g_free(doc);
}

JV *j_get(const JV *object, const char *key) {
    if (!object || object->t != J_OBJ)
        return NULL;
    for (guint i = 0; i < object->n; i++)
        if (!strcmp(object->u.m[i].key, key))
            return object->u.m[i].v;
    return NULL;
}

gboolean j_is_container(const JV *value) {
    return value && (value->t == J_ARR || value->t == J_OBJ);
}

const JV *j_decode(JDoc *doc, const JV *value) {
    if (!value || value->t != J_STR)
        return value;
    const char *p = value->u.s;
    while (*p && py_isspace(g_utf8_get_char(p)))
        p = g_utf8_next_char(p);
    if (*p != '{' && *p != '[')
        return value;
    JV *decoded = parse_into(doc, value->u.s, value->n, 0, NULL);
    return decoded ? decoded : value;
}

void j_quote(GString *out, const char *text, gssize length) {
    if (length < 0)
        length = (gssize)strlen(text);
    g_string_append_c(out, '"');
    for (gssize i = 0; i < length; i++) {
        unsigned char c = (unsigned char)text[i];
        switch (c) {
        case '"':
            g_string_append(out, "\\\"");
            break;
        case '\\':
            g_string_append(out, "\\\\");
            break;
        case '\n':
            g_string_append(out, "\\n");
            break;
        case '\r':
            g_string_append(out, "\\r");
            break;
        case '\t':
            g_string_append(out, "\\t");
            break;
        case '\b':
            g_string_append(out, "\\b");
            break;
        case '\f':
            g_string_append(out, "\\f");
            break;
        default:
            if (c < 0x20)
                g_string_append_printf(out, "\\u%04x", c);
            else
                g_string_append_c(out, (char)c);
        }
    }
    g_string_append_c(out, '"');
}

char *j_quoted(const char *text) {
    GString *out = g_string_new(NULL);
    j_quote(out, text, -1);
    return g_string_free(out, FALSE);
}

static gboolean integer_literal(const char *s) {
    if (*s == '-')
        s++;
    if (!g_ascii_isdigit(*s))
        return FALSE;
    while (g_ascii_isdigit(*s))
        s++;
    return *s == 0;
}

// Matches Python float repr.
char *py_float_repr(double value) {
    if (isnan(value))
        return g_strdup("NaN");
    if (isinf(value))
        return g_strdup(value < 0 ? "-Infinity" : "Infinity");
    char buffer[64], format[16];
    for (int precision = 0; precision <= 16; precision++) {
        g_snprintf(format, sizeof format, "%%.%de", precision);
        g_ascii_formatd(buffer, sizeof buffer, format, value);
        if (g_ascii_strtod(buffer, NULL) == value)
            break;
    }
    const char *p = buffer;
    GString *out = g_string_new(NULL);
    if (*p == '-') {
        g_string_append_c(out, '-');
        p++;
    }
    char mantissa[32];
    int count = 0;
    for (; *p && *p != 'e'; p++)
        if (g_ascii_isdigit(*p))
            mantissa[count++] = *p;
    while (count > 1 && mantissa[count - 1] == '0')
        count--;
    mantissa[count] = 0;
    int exponent = atoi(p + 1);
    if (exponent >= -4 && exponent < 16) {
        if (exponent < 0) {
            g_string_append(out, "0.");
            for (int i = -1; i > exponent; i--)
                g_string_append_c(out, '0');
            g_string_append(out, mantissa);
        } else {
            for (int i = 0; i <= exponent; i++)
                g_string_append_c(out, i < count ? mantissa[i] : '0');
            g_string_append_c(out, '.');
            g_string_append(out, count > exponent + 1 ? mantissa + exponent + 1 : "0");
        }
    } else {
        g_string_append_c(out, mantissa[0]);
        if (count > 1)
            g_string_append_printf(out, ".%s", mantissa + 1);
        g_string_append_printf(out, "e%c%02d", exponent < 0 ? '-' : '+', abs(exponent));
    }
    return g_string_free(out, FALSE);
}

char *j_number_text(const JV *number) {
    const char *raw = number->u.s;
    if (integer_literal(raw))
        return g_strdup(!strcmp(raw, "-0") ? "0" : raw);
    if (g_ascii_isalpha(raw[0]) || g_ascii_isalpha(raw[1])) {
        if (g_ascii_tolower(raw[0]) == 'n')
            return g_strdup("NaN");
        return g_strdup(raw[0] == '-' ? "-Infinity" : "Infinity");
    }
    return py_float_repr(g_ascii_strtod(raw, NULL));
}

static void indent(GString *out, int depth) {
    g_string_append_c(out, '\n');
    for (int i = 0; i < depth * 2; i++)
        g_string_append_c(out, ' ');
}

static void dump_string(GString *out, const char *text, gssize length, int flags) {
    if (!(flags & J_LINE_SEPARATORS)) {
        j_quote(out, text, length);
        return;
    }
    gsize start = out->len;
    j_quote(out, text, length);
    // Keep separators on one line.
    if (strstr(out->str + start, "\xe2\x80\xa8") || strstr(out->str + start, "\xe2\x80\xa9")) {
        char *copy = g_strdup(out->str + start);
        g_string_truncate(out, start);
        for (const char *p = copy; *p; p++) {
            if (!strncmp(p, "\xe2\x80\xa8", 3) || !strncmp(p, "\xe2\x80\xa9", 3)) {
                g_string_append(out, p[2] == '\xa8' ? "\\u2028" : "\\u2029");
                p += 2;
            } else {
                g_string_append_c(out, *p);
            }
        }
        g_free(copy);
    }
}

static void dump(GString *out, const JV *value, int flags, int depth) {
    switch (value->t) {
    case J_NULL:
        g_string_append(out, "null");
        break;
    case J_TRUE:
        g_string_append(out, "true");
        break;
    case J_FALSE:
        g_string_append(out, "false");
        break;
    case J_NUM:
        if (flags & J_RAW_NUMBERS) {
            g_string_append(out, value->u.s);
        } else {
            char *text = j_number_text(value);
            g_string_append(out, text);
            g_free(text);
        }
        break;
    case J_STR:
        dump_string(out, value->u.s, value->n, flags);
        break;
    case J_ARR:
        g_string_append_c(out, '[');
        for (guint i = 0; i < value->n; i++) {
            if (i)
                g_string_append_c(out, ',');
            if (flags & J_INDENT)
                indent(out, depth + 1);
            dump(out, value->u.a[i], flags, depth + 1);
        }
        if (value->n && (flags & J_INDENT))
            indent(out, depth);
        g_string_append_c(out, ']');
        break;
    case J_OBJ:
        g_string_append_c(out, '{');
        for (guint i = 0; i < value->n; i++) {
            if (i)
                g_string_append_c(out, ',');
            if (flags & J_INDENT)
                indent(out, depth + 1);
            dump_string(out, value->u.m[i].key, -1, flags);
            g_string_append(out, flags & J_INDENT ? ": " : ":");
            dump(out, value->u.m[i].v, flags, depth + 1);
        }
        if (value->n && (flags & J_INDENT))
            indent(out, depth);
        g_string_append_c(out, '}');
        break;
    }
}

void j_dump(GString *out, const JV *value, int flags) {
    dump(out, value, flags, 0);
}

char *j_text(const JV *value, gboolean json_booleans) {
    if (!value)
        return g_strdup("");
    switch (value->t) {
    case J_NULL:
        return g_strdup("");
    case J_TRUE:
        return g_strdup(json_booleans ? "true" : "True");
    case J_FALSE:
        return g_strdup(json_booleans ? "false" : "False");
    case J_NUM:
        return j_number_text(value);
    case J_STR:
        return g_strdup(value->u.s);
    default: {
        GString *out = g_string_new(NULL);
        j_dump(out, value, J_COMPACT);
        return g_string_free(out, FALSE);
    }
    }
}

char *j_scalar(const JV *value) {
    if (value->t == J_STR)
        return g_strdup(value->u.s);
    GString *out = g_string_new(NULL);
    j_dump(out, value, J_COMPACT);
    return g_string_free(out, FALSE);
}
