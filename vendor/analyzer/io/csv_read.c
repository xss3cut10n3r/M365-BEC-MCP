#include "io.h"

#include <string.h>

#define FIELD_LIMIT (64 * 1024 * 1024)

static gboolean valid_utf8(const unsigned char *p, gsize length, gsize *bad) {
    gsize i = 0;
    while (i < length) {
        unsigned char c = p[i];
        gsize need = c < 0x80 ? 0 : c >= 0xc2 && c < 0xe0 ? 1 : c >= 0xe0 && c < 0xf0 ? 2 : c >= 0xf0 && c < 0xf5 ? 3 : 9;
        if (need == 9 || i + need >= length + (need == 0)) {
            *bad = i;
            return FALSE;
        }
        for (gsize k = 1; k <= need; k++) {
            unsigned char next = p[i + k];
            unsigned char low = 0x80, high = 0xbf;
            if (k == 1) {
                // Reject overlongs and surrogates.
                if (c == 0xe0)
                    low = 0xa0;
                else if (c == 0xed)
                    high = 0x9f;
                else if (c == 0xf0)
                    low = 0x90;
                else if (c == 0xf4)
                    high = 0x8f;
            }
            if (next < low || next > high) {
                *bad = i;
                return FALSE;
            }
        }
        i += need + 1;
    }
    return TRUE;
}

// Returns validated UTF-8 text.
char *decode_text(const char *data, gsize length, gsize *out_length, GError **error) {
    const unsigned char *bytes = (const unsigned char *)data;
    char *text;
    if (length >= 2 && ((bytes[0] == 0xff && bytes[1] == 0xfe) || (bytes[0] == 0xfe && bytes[1] == 0xff))) {
        GError *problem = NULL;
        gsize written = 0;
        text = g_convert(data + 2, (gssize)(length - 2), "UTF-8", bytes[0] == 0xff ? "UTF-16LE" : "UTF-16BE", NULL,
                         &written, &problem);
        if (!text) {
            bec_fail(error, "File is not valid UTF-16 text");
            g_clear_error(&problem);
            return NULL;
        }
        length = written;
    } else {
        gsize skip = length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf ? 3 : 0;
        gsize bad = 0;
        if (!valid_utf8(bytes + skip, length - skip, &bad)) {
            bec_fail(error, "File is not valid UTF-8 text near byte %" G_GSIZE_FORMAT, bad + skip + 1);
            return NULL;
        }
        length -= skip;
        text = g_malloc(length + 1);
        memcpy(text, data + skip, length);
        text[length] = 0;
    }
    // Keep strings NUL-free.
    if (memchr(text, 0, length)) {
        GString *clean = g_string_sized_new(length + 16);
        for (gsize i = 0; i < length; i++) {
            if (text[i])
                g_string_append_c(clean, text[i]);
            else
                g_string_append(clean, "\xef\xbf\xbd");
        }
        g_free(text);
        length = clean->len;
        text = g_string_free(clean, FALSE);
    }
    *out_length = length;
    return text;
}

static gboolean word(gunichar c) {
    return c == '_' || g_unichar_isalnum(c);
}

static gboolean delimiter_candidate(gunichar c) {
    return c && !word(c) && c != '\n' && c != '"' && c != '\'';
}

// Returns the end of a quoted body.
static const char *quoted_body(const char *p, const char *end, char quote) {
    while (p < end) {
        if (*p == quote) {
            if (p + 1 < end && p[1] == quote) {
                p += 2;
                continue;
            }
            return p;
        }
        p++;
    }
    return NULL;
}

static void tally(int counts[3], int *order, int next_order[1], gunichar c) {
    int slot = c == ',' ? 0 : c == ';' ? 1 : c == '\t' ? 2 : -1;
    if (slot < 0)
        return;
    if (!counts[slot])
        order[slot] = next_order[0]++;
    counts[slot]++;
}

// Mirrors csv.Sniffer delimiter choice.
static char sniff(const char *line, gsize length) {
    const char *end = line + length;
    int counts[3] = {0, 0, 0}, order[3] = {0, 0, 0}, next_order[1] = {1};
    gboolean matched = FALSE;
    for (int pattern = 0; pattern < 4 && !matched; pattern++) {
        const char *p = line;
        while (p < end) {
            const char *start = p, *q = p;
            gunichar delimiter = 0;
            gboolean ok = TRUE;
            if (pattern == 0 || pattern == 2) {
                delimiter = g_utf8_get_char(q);
                ok = delimiter_candidate(delimiter);
                q = g_utf8_next_char(q);
                if (ok && q < end && *q == ' ')
                    q++;
            } else {
                ok = start == line || start[-1] == '\n';
            }
            char quote = ok && q < end ? *q : 0;
            ok = ok && (quote == '"' || quote == '\'');
            const char *close = ok ? quoted_body(q + 1, end, quote) : NULL;
            ok = ok && close;
            if (ok) {
                q = close + 1;
                if (pattern == 0) {
                    ok = q < end && g_utf8_get_char(q) == delimiter;
                    if (ok)
                        q = g_utf8_next_char(q);
                } else if (pattern == 1) {
                    delimiter = q < end ? g_utf8_get_char(q) : 0;
                    ok = delimiter_candidate(delimiter);
                    if (ok) {
                        q = g_utf8_next_char(q);
                        if (q < end && *q == ' ')
                            q++;
                    }
                } else {
                    ok = q == end || *q == '\n';
                }
            }
            if (ok) {
                matched = TRUE;
                tally(counts, order, next_order, delimiter);
                p = q > start ? q : g_utf8_next_char(start);
            } else {
                p = g_utf8_next_char(start);
            }
        }
    }
    static const char symbols[3] = {',', ';', '\t'};
    int best = -1;
    for (int i = 0; i < 3; i++)
        if (counts[i] && (best < 0 || counts[i] > counts[best] || (counts[i] == counts[best] && order[i] < order[best])))
            best = i;
    if (best >= 0)
        return symbols[best];
    // Fall back on preference order.
    if (memchr(line, ',', length))
        return ',';
    if (memchr(line, '\t', length))
        return '\t';
    if (memchr(line, ';', length))
        return ';';
    return ',';
}

typedef struct {
    GPtrArray *fields;
    GString *field;
    gsize characters;
} Record;

static void save_field(Record *record) {
    g_ptr_array_add(record->fields, g_strndup(record->field->str, record->field->len));
    g_string_truncate(record->field, 0);
    record->characters = 0;
}

gboolean csv_read(const char *data, gsize length, const RowSink *sink, GError **error) {
    gsize size = 0;
    char *text = decode_text(data, length, &size, error);
    if (!text)
        return FALSE;
    gsize first = 0;
    while (first < size && text[first] != '\n' && text[first] != '\r')
        first++;
    if (first < size)
        first += text[first] == '\r' && first + 1 < size && text[first + 1] == '\n' ? 2 : 1;
    char delimiter = sniff(text, first);
    enum { START_RECORD, START_FIELD, IN_FIELD, IN_QUOTED, QUOTE_IN_QUOTED, EAT_CRNL } state = START_RECORD;
    Record record = {g_ptr_array_new_with_free_func(g_free), g_string_new(NULL), 0};
    gboolean ok = sink->begin(""  , sink->user, error);
    gsize i = 0;
    while (ok && i <= size) {
        // Zero marks line ends.
        gboolean line_end = FALSE;
        char c = 0;
        if (i < size) {
            c = text[i];
        } else {
            if (size == 0 || text[size - 1] == '\n' || text[size - 1] == '\r')
                break;
            line_end = TRUE;
        }
        gboolean newline = c == '\n' || c == '\r';
        gsize advance = 1;
        if (newline && c == '\r' && i + 1 < size && text[i + 1] == '\n')
            advance = 2;
        for (int pass = 0; pass < (newline ? 2 : 1) && ok; pass++) {
            gboolean eol = line_end || pass == 1;
            switch (state) {
            case START_RECORD:
                if (eol)
                    break;
                if (newline) {
                    state = EAT_CRNL;
                    break;
                }
                state = START_FIELD;
                // fall through
            case START_FIELD:
                if (eol || newline) {
                    save_field(&record);
                    state = eol ? START_RECORD : EAT_CRNL;
                } else if (c == '"') {
                    state = IN_QUOTED;
                } else if (c == delimiter) {
                    save_field(&record);
                } else {
                    g_string_append_c(record.field, c);
                    state = IN_FIELD;
                }
                break;
            case IN_FIELD:
                if (eol || newline) {
                    save_field(&record);
                    state = eol ? START_RECORD : EAT_CRNL;
                } else if (c == delimiter) {
                    save_field(&record);
                    state = START_FIELD;
                } else {
                    g_string_append_c(record.field, c);
                }
                break;
            case IN_QUOTED:
                if (eol)
                    break;
                if (c == '"') {
                    state = QUOTE_IN_QUOTED;
                } else {
                    g_string_append_c(record.field, c);
                    if (advance == 2)
                        g_string_append_c(record.field, '\n');
                }
                break;
            case QUOTE_IN_QUOTED:
                if (!eol && !newline && c == '"') {
                    g_string_append_c(record.field, c);
                    state = IN_QUOTED;
                } else if (!eol && !newline && c == delimiter) {
                    save_field(&record);
                    state = START_FIELD;
                } else if (eol || newline) {
                    save_field(&record);
                    state = eol ? START_RECORD : EAT_CRNL;
                } else {
                    bec_fail(error, "'%c' expected after '\"'", delimiter);
                    ok = FALSE;
                }
                break;
            case EAT_CRNL:
                if (eol)
                    state = START_RECORD;
                break;
            }
            if (ok && record.field->len > FIELD_LIMIT) {
                bec_fail(error, "field larger than field limit (%d)", FIELD_LIMIT);
                ok = FALSE;
            }
            if (ok && eol && state == START_RECORD) {
                ok = sink->row(record.fields, sink->user, error);
                g_ptr_array_set_size(record.fields, 0);
            }
        }
        i += line_end ? 1 : advance;
    }
    if (ok && state != START_RECORD) {
        bec_fail(error, "unexpected end of data");
        ok = FALSE;
    }
    if (ok)
        ok = sink->end(sink->user, error);
    g_ptr_array_free(record.fields, TRUE);
    g_string_free(record.field, TRUE);
    g_free(text);
    return ok;
}
