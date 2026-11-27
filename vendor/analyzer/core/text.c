#include "core.h"

#include <string.h>

G_DEFINE_QUARK(bec-error, bec_error)

void bec_fail(GError **error, const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *message = g_strdup_vprintf(format, args);
    va_end(args);
    g_set_error_literal(error, BEC_ERROR, 1, message);
    g_free(message);
}

gboolean py_isspace(gunichar c) {
    return (c >= 9 && c <= 13) || (c >= 0x1c && c <= 0x20) || c == 0x85 || c == 0xa0 || c == 0x1680 ||
           (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f ||
           c == 0x3000;
}

char *py_strip(const char *text) {
    const char *start = text;
    while (*start && py_isspace(g_utf8_get_char(start)))
        start = g_utf8_next_char(start);
    const char *end = start + strlen(start);
    while (end > start) {
        const char *previous = g_utf8_prev_char(end);
        if (!py_isspace(g_utf8_get_char(previous)))
            break;
        end = previous;
    }
    return g_strndup(start, end - start);
}

static gboolean is_ascii(const char *text) {
    for (const unsigned char *p = (const unsigned char *)text; *p; p++)
        if (*p >= 0x80)
            return FALSE;
    return TRUE;
}

char *casefold(const char *text) {
    if (is_ascii(text))
        return g_ascii_strdown(text, -1);
    return g_utf8_casefold(text, -1);
}

char *clean_header(const char *text) {
    char *folded = casefold(text);
    GString *out = g_string_new(NULL);
    gboolean pending = FALSE;
    for (const char *p = folded; *p; p = g_utf8_next_char(p)) {
        gunichar c = g_utf8_get_char(p);
        if (py_isspace(c)) {
            pending = out->len > 0;
            continue;
        }
        if (pending)
            g_string_append_c(out, ' ');
        pending = FALSE;
        g_string_append_unichar(out, c);
    }
    g_free(folded);
    return g_string_free(out, FALSE);
}

gboolean contains_folded(const char *haystack, const char *folded_needle) {
    char *folded = casefold(haystack);
    gboolean found = strstr(folded, folded_needle) != NULL;
    g_free(folded);
    return found;
}

gboolean equals_folded(const char *value, const char *folded_needle) {
    char *folded = casefold(value);
    gboolean same = strcmp(folded, folded_needle) == 0;
    g_free(folded);
    return same;
}

char *group_digits(gint64 value) {
    char digits[32];
    g_snprintf(digits, sizeof digits, "%" G_GINT64_FORMAT, value < 0 ? -value : value);
    GString *out = g_string_new(value < 0 ? "-" : "");
    size_t length = strlen(digits);
    for (size_t i = 0; i < length; i++) {
        if (i && (length - i) % 3 == 0)
            g_string_append_c(out, ',');
        g_string_append_c(out, digits[i]);
    }
    return g_string_free(out, FALSE);
}

/* Timestamps follow datetime.fromisoformat. */

static gint64 days_from_civil(gint64 y, int m, int d) {
    y -= m <= 2;
    gint64 era = (y >= 0 ? y : y - 399) / 400;
    int yoe = (int)(y - era * 400);
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static void civil_from_days(gint64 z, gint64 *y, int *m, int *d) {
    z += 719468;
    gint64 era = (z >= 0 ? z : z - 146096) / 146097;
    int doe = (int)(z - era * 146097);
    int yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = yoe + era * 400 + (*m <= 2);
}

static int month_days(gint64 y, int m) {
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)))
        return 29;
    return days[m - 1];
}

static gboolean digits(const char *s, int count, int *out) {
    int value = 0;
    for (int i = 0; i < count; i++) {
        if (s[i] < '0' || s[i] > '9')
            return FALSE;
        value = value * 10 + (s[i] - '0');
    }
    *out = value;
    return TRUE;
}

static int find_separator(const char *s, int length) {
    if (length == 7)
        return 7;
    if (s[4] == '-') {
        if (s[5] == 'W') {
            if (length > 8 && s[8] == '-') {
                if (length == 9)
                    return -1;
                if (length > 10 && g_ascii_isdigit(s[10]))
                    return 8;
                return 10;
            }
            return 8;
        }
        return 10;
    }
    if (s[4] == 'W') {
        int index = 7;
        while (index < length && g_ascii_isdigit(s[index]))
            index++;
        if (index < 9)
            return index;
        return index % 2 == 0 ? 7 : 8;
    }
    return 8;
}

static gboolean parse_date(const char *s, int length, gint64 *year, int *month, int *day) {
    int y;
    if ((length != 7 && length != 8 && length != 10) || !digits(s, 4, &y))
        return FALSE;
    gboolean dash = s[4] == '-';
    int pos = 4 + dash;
    if (s[pos] == 'W') {
        int week, weekday = 1;
        pos++;
        if (pos + 2 > length || !digits(s + pos, 2, &week))
            return FALSE;
        pos += 2;
        if (length > pos) {
            if ((s[pos] == '-') != dash)
                return FALSE;
            pos += dash;
            if (pos >= length || !digits(s + pos, 1, &weekday))
                return FALSE;
            if (pos + 1 != length)
                return FALSE;
        }
        if (y < 1 || y > 9999 || week < 1 || week > 53 || weekday < 1 || weekday > 7)
            return FALSE;
        gint64 first = days_from_civil(y, 1, 1);
        int first_weekday = (int)(((first % 7) + 7 + 3) % 7);
        if (week == 53) {
            gboolean leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            if (!(first_weekday == 3 || (first_weekday == 2 && leap)))
                return FALSE;
        }
        gint64 week_one = first - first_weekday;
        if (first_weekday > 3)
            week_one += 7;
        gint64 ordinal = week_one + (week - 1) * 7 + (weekday - 1);
        civil_from_days(ordinal, year, month, day);
        return *year >= 1 && *year <= 9999;
    }
    int m, d;
    if (pos + 2 > length || !digits(s + pos, 2, &m))
        return FALSE;
    pos += 2;
    if ((pos < length && s[pos] == '-') != dash)
        return FALSE;
    pos += dash;
    if (pos + 2 != length || !digits(s + pos, 2, &d))
        return FALSE;
    if (y < 1 || m < 1 || m > 12 || d < 1 || d > month_days(y, m))
        return FALSE;
    *year = y;
    *month = m;
    *day = d;
    return TRUE;
}

// Returns one for trailing text.
static int parse_clock(const char *s, const char *end, int parts[4]) {
    const char *p = s;
    gboolean colon = TRUE;
    parts[0] = parts[1] = parts[2] = parts[3] = 0;
    int part;
    for (part = 0; part < 3; part++) {
        if (!digits(p, 2, &parts[part]))
            return -3;
        p += 2;
        char c = *p++;
        if (part == 0)
            colon = c == ':';
        if (p >= end)
            return c == '.' || c == ',' ? -3 : c != 0;
        if (colon && c == ':')
            continue;
        if (c == '.' || c == ',')
            break;
        if (colon)
            return -4;
        p--;
    }
    int available = (int)(end - p), used = MIN(available, 6);
    if (used < 1 || !digits(p, used, &parts[3]))
        return -3;
    p += used;
    for (int i = used; i < 6; i++)
        parts[3] *= 10;
    while (g_ascii_isdigit(*p))
        p++;
    return *p != 0;
}

// Returns microseconds since epoch.
static gboolean parse_iso(const char *input, gint64 *micros) {
    char *stripped = py_strip(input);
    GString *text = g_string_new(NULL);
    // Map characters onto bytes.
    for (const char *p = stripped; *p; p = g_utf8_next_char(p)) {
        gunichar c = g_utf8_get_char(p);
        if (c == 'Z') {
            g_string_append(text, "+00:00");
        } else {
            g_string_append_c(text, c < 0x80 ? (char)c : 1);
        }
    }
    g_free(stripped);
    gboolean ok = FALSE;
    const char *s = text->str;
    int length = (int)text->len;
    gint64 year;
    int month, day, clock[4] = {0, 0, 0, 0};
    gint64 offset = 0;
    if (length < 7)
        goto done;
    int separator = find_separator(s, length);
    if (separator < 0 || separator > length || !parse_date(s, separator, &year, &month, &day))
        goto done;
    if (length > separator) {
        const char *t = s + separator + 1, *end = s + length;
        if (t > end)
            goto done;
        const char *zone = t;
        do {
            if (*zone == '+' || *zone == '-')
                break;
        } while (++zone < end);
        int state = parse_clock(t, zone, clock);
        if (state < 0 || (zone >= end && state == 1))
            goto done;
        if (zone < end) {
            int parts[4];
            if (parse_clock(zone + 1, end, parts) != 0)
                goto done;
            gint64 total = ((gint64)parts[0] * 3600 + parts[1] * 60 + parts[2]) * G_USEC_PER_SEC + parts[3];
            if (total >= 86400 * (gint64)G_USEC_PER_SEC)
                goto done;
            offset = *zone == '-' ? -total : total;
        }
        if (clock[0] > 23 || clock[1] > 59 || clock[2] > 59)
            goto done;
    }
    *micros = (days_from_civil(year, month, day) * 86400 + clock[0] * 3600 + clock[1] * 60 + clock[2]) *
                  (gint64)G_USEC_PER_SEC +
              clock[3] - offset;
    ok = TRUE;
done:
    g_string_free(text, TRUE);
    return ok;
}

static char *format_micros(gint64 micros, gboolean fraction) {
    gint64 seconds = micros / G_USEC_PER_SEC;
    gint64 rest = micros % G_USEC_PER_SEC;
    if (rest < 0) {
        rest += G_USEC_PER_SEC;
        seconds--;
    }
    gint64 days = seconds / 86400;
    gint64 clock = seconds % 86400;
    if (clock < 0) {
        clock += 86400;
        days--;
    }
    gint64 year;
    int month, day;
    civil_from_days(days, &year, &month, &day);
    if (year < 1 || year > 9999)
        return g_strdup("");
    char *base = g_strdup_printf("%04d-%02d-%02dT%02d:%02d:%02d", (int)year, month, day, (int)(clock / 3600),
                                 (int)(clock / 60 % 60), (int)(clock % 60));
    char *out = fraction ? g_strdup_printf("%s.%06dZ", base, (int)rest) : g_strdup_printf("%sZ", base);
    g_free(base);
    return out;
}

char *utc_normalize(const char *value) {
    gint64 micros;
    if (!value || !*value || !parse_iso(value, &micros))
        return g_strdup("");
    return format_micros(micros, TRUE);
}

char *utc_from_epoch(gint64 seconds) {
    return format_micros(seconds * G_USEC_PER_SEC, FALSE);
}

char *utc_add_microsecond(const char *stamp) {
    gint64 micros;
    if (!parse_iso(stamp, &micros))
        return g_strdup("");
    return format_micros(micros + 1, TRUE);
}

/* Addresses follow ipaddress.ip_address. */

static gboolean parse_ipv4(const char *text, guint32 *out) {
    guint32 value = 0;
    int octets = 0;
    const char *p = text;
    for (;;) {
        int length = 0, octet = 0;
        while (p[length] >= '0' && p[length] <= '9') {
            octet = octet * 10 + (p[length] - '0');
            if (++length > 3)
                return FALSE;
        }
        if (!length || (length > 1 && p[0] == '0') || octet > 255)
            return FALSE;
        value = value << 8 | (guint32)octet;
        octets++;
        p += length;
        if (*p == '.' && octets < 4) {
            p++;
            continue;
        }
        break;
    }
    if (*p || octets != 4)
        return FALSE;
    *out = value;
    return TRUE;
}

static gboolean parse_hextet(const char *text, guint16 *out) {
    size_t length = strlen(text);
    if (!length || length > 4)
        return FALSE;
    guint value = 0;
    for (size_t i = 0; i < length; i++) {
        int digit = g_ascii_xdigit_value(text[i]);
        if (digit < 0)
            return FALSE;
        value = value << 4 | (guint)digit;
    }
    *out = (guint16)value;
    return TRUE;
}

static char *parse_ipv6(const char *text) {
    char *copy = g_strdup(text);
    char *scope = strchr(copy, '%');
    if (scope) {
        *scope++ = 0;
        if (!*scope || strchr(scope, '%')) {
            g_free(copy);
            return NULL;
        }
    }
    char **split = g_strsplit(copy, ":", -1);
    GPtrArray *parts = g_ptr_array_new_with_free_func(g_free);
    for (char **p = split; *p; p++)
        g_ptr_array_add(parts, g_strdup(*p));
    g_strfreev(split);
    char *result = NULL;
    guint16 words[8] = {0};
    if (parts->len < 3)
        goto done;
    const char *last = parts->pdata[parts->len - 1];
    if (strchr(last, '.')) {
        guint32 v4;
        if (!parse_ipv4(last, &v4))
            goto done;
        g_ptr_array_remove_index(parts, parts->len - 1);
        g_ptr_array_add(parts, g_strdup_printf("%x", v4 >> 16));
        g_ptr_array_add(parts, g_strdup_printf("%x", v4 & 0xffff));
    }
    if (parts->len > 9)
        goto done;
    int skip = -1;
    for (guint i = 1; i + 1 < parts->len; i++) {
        if (!*(char *)parts->pdata[i]) {
            if (skip >= 0)
                goto done;
            skip = (int)i;
        }
    }
    int high, low;
    if (skip >= 0) {
        high = skip;
        low = (int)parts->len - skip - 1;
        if (!*(char *)parts->pdata[0] && --high)
            goto done;
        if (!*(char *)parts->pdata[parts->len - 1] && --low)
            goto done;
        if (8 - (high + low) < 1)
            goto done;
    } else {
        if (parts->len != 8 || !*(char *)parts->pdata[0] || !*(char *)parts->pdata[7])
            goto done;
        high = 8;
        low = 0;
    }
    for (int i = 0; i < high; i++)
        if (!parse_hextet(parts->pdata[i], &words[i]))
            goto done;
    for (int i = 0; i < low; i++)
        if (!parse_hextet(parts->pdata[parts->len - low + i], &words[8 - low + i]))
            goto done;
    // Compress the longest zero run.
    int best = -1, best_length = 0, run = -1, run_length = 0;
    for (int i = 0; i < 8; i++) {
        if (words[i] == 0) {
            if (run < 0)
                run = i;
            if (++run_length > best_length) {
                best = run;
                best_length = run_length;
            }
        } else {
            run = -1;
            run_length = 0;
        }
    }
    GString *out = g_string_new(NULL);
    gboolean mapped = words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0 && words[4] == 0 &&
                      words[5] == 0xffff;
    if (mapped) {
        g_string_printf(out, "::ffff:%u.%u.%u.%u", words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255);
    } else {
        for (int i = 0; i < 8; i++) {
            if (best_length > 1 && i == best) {
                g_string_append(out, i == 0 ? "::" : ":");
                i += best_length - 1;
                continue;
            }
            g_string_append_printf(out, "%x", words[i]);
            if (i < 7)
                g_string_append_c(out, ':');
        }
    }
    if (scope)
        g_string_append_printf(out, "%%%s", scope);
    result = g_string_free(out, FALSE);
done:
    g_ptr_array_free(parts, TRUE);
    g_free(copy);
    return result;
}

char *ip_normalize(const char *value) {
    char *text = py_strip(value ? value : "");
    char *inner = NULL;
    size_t length = strlen(text);
    if (text[0] == '[') {
        // Bracketed host with port.
        const char *close = strchr(text, ']');
        if (close && close > text + 1) {
            const char *rest = close + 1;
            gboolean port = *rest == ':' && rest[1];
            for (const char *p = rest + 1; port && *p; p++)
                port = g_ascii_isdigit(*p);
            if (!*rest || port)
                inner = g_strndup(text + 1, close - text - 1);
        }
    } else if (length && strchr(text, ':') == strrchr(text, ':') && strchr(text, ':')) {
        const char *colon = strchr(text, ':');
        gboolean shape = colon[1] != 0 && colon > text;
        for (const char *p = colon + 1; shape && *p; p++)
            shape = g_ascii_isdigit(*p);
        int dots = 0;
        for (const char *p = text; shape && p < colon; p++) {
            if (*p == '.') {
                dots++;
                shape = p > text && p[-1] != '.' && p + 1 < colon;
            } else {
                shape = g_ascii_isdigit(*p);
            }
        }
        if (shape && dots == 3)
            inner = g_strndup(text, colon - text);
    }
    const char *candidate = inner ? inner : text;
    char *result = NULL;
    guint32 v4;
    if (parse_ipv4(candidate, &v4))
        result = g_strdup_printf("%u.%u.%u.%u", v4 >> 24, v4 >> 16 & 255, v4 >> 8 & 255, v4 & 255);
    else if (strchr(candidate, ':'))
        result = parse_ipv6(candidate);
    g_free(inner);
    g_free(text);
    return result ? result : g_strdup("");
}
