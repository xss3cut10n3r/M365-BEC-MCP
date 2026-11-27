#include "io.h"

#include <expat.h>
#include <math.h>
#include <string.h>
#include <zip.h>

typedef struct {
    zip_t *archive;
    GPtrArray *strings;
    GArray *date_styles;
    GArray *delta_styles;
    gboolean mac_epoch;
    const RowSink *sink;
    GError **error;
    XML_Parser parser;
    gboolean failed;
    // Element state follows.
    GString *text;
    gboolean collect;
    int phonetic;
    GHashTable *formats;
    gboolean in_xfs;
    GPtrArray *sheet_names;
    GPtrArray *sheet_ids;
    GHashTable *targets;
    gboolean relations_office;
    char *workbook_path;
    // Worksheet state follows.
    GPtrArray *row;
    gint64 row_number;
    gint64 emitted;
    int column;
    char *cell_type;
    int cell_style;
    gboolean has_value;
    gboolean has_formula;
    GString *value;
    GString *formula;
    GString *inline_text;
    int capture;
} Book;

static const char *local(const char *name) {
    const char *colon = strrchr(name, ':');
    return colon ? colon + 1 : name;
}

static const char *plain_attribute(const char **attributes, const char *name) {
    for (; attributes && *attributes; attributes += 2)
        if (!strcmp(attributes[0], name))
            return attributes[1];
    return NULL;
}

static void characters(void *user, const XML_Char *text, int length) {
    Book *book = user;
    if (book->collect && !book->phonetic)
        g_string_append_len(book->text, text, length);
    if (book->capture == 1)
        g_string_append_len(book->value, text, length);
    else if (book->capture == 2)
        g_string_append_len(book->formula, text, length);
    else if (book->capture == 3 && !book->phonetic)
        g_string_append_len(book->inline_text, text, length);
}

static gboolean parse_entry(Book *book, const char *name, XML_StartElementHandler start, XML_EndElementHandler end) {
    zip_file_t *file = zip_fopen(book->archive, name, 0);
    if (!file)
        return FALSE;
    XML_Parser parser = XML_ParserCreate(NULL);
    book->parser = parser;
    XML_SetUserData(parser, book);
    XML_SetElementHandler(parser, start, end);
    XML_SetCharacterDataHandler(parser, characters);
    char buffer[65536];
    gboolean ok = TRUE;
    for (;;) {
        zip_int64_t got = zip_fread(file, buffer, sizeof buffer);
        if (got < 0) {
            bec_fail(book->error, "Workbook part %s could not be read", name);
            ok = FALSE;
            break;
        }
        if (XML_Parse(parser, buffer, (int)got, got == 0) == XML_STATUS_ERROR) {
            if (!book->failed)
                bec_fail(book->error, "Workbook part %s is malformed: %s", name,
                         XML_ErrorString(XML_GetErrorCode(parser)));
            ok = FALSE;
            break;
        }
        if (got == 0)
            break;
    }
    XML_ParserFree(parser);
    zip_fclose(file);
    return ok && !book->failed;
}

/* Relationships and workbook parts. */

static void relation_start(void *user, const XML_Char *name, const XML_Char **attributes) {
    Book *book = user;
    if (strcmp(local(name), "Relationship"))
        return;
    const char *id = plain_attribute(attributes, "Id"), *target = plain_attribute(attributes, "Target");
    const char *type = plain_attribute(attributes, "Type");
    if (!id || !target)
        return;
    if (book->relations_office) {
        if (type && g_str_has_suffix(type, "/officeDocument") && !book->workbook_path)
            book->workbook_path = g_strdup(target[0] == '/' ? target + 1 : target);
    } else {
        g_hash_table_insert(book->targets, g_strdup(id), g_strdup(target));
    }
}

static void nothing_end(void *user, const XML_Char *name) {
    (void)user;
    (void)name;
}

static void workbook_start(void *user, const XML_Char *name, const XML_Char **attributes) {
    Book *book = user;
    const char *tag = local(name);
    if (!strcmp(tag, "workbookPr")) {
        const char *flag = plain_attribute(attributes, "date1904");
        book->mac_epoch = flag && (!strcmp(flag, "1") || !strcmp(flag, "true"));
    } else if (!strcmp(tag, "sheet")) {
        const char *title = plain_attribute(attributes, "name"), *id = NULL;
        for (const char **a = attributes; a && *a; a += 2)
            if (strchr(a[0], ':') && !strcmp(local(a[0]), "id"))
                id = a[1];
        g_ptr_array_add(book->sheet_names, g_strdup(title ? title : ""));
        g_ptr_array_add(book->sheet_ids, g_strdup(id ? id : ""));
    }
}

/* Shared strings and styles. */

static void strings_start(void *user, const XML_Char *name, const XML_Char **attributes) {
    (void)attributes;
    Book *book = user;
    const char *tag = local(name);
    if (!strcmp(tag, "si"))
        g_string_truncate(book->text, 0);
    else if (!strcmp(tag, "rPh"))
        book->phonetic++;
    else if (!strcmp(tag, "t"))
        book->collect = TRUE;
}

static char *unescape_cell(GString *text) {
    g_string_replace(text, "x005F_", "", 0);
    return g_strndup(text->str, text->len);
}

static void strings_end(void *user, const XML_Char *name) {
    Book *book = user;
    const char *tag = local(name);
    if (!strcmp(tag, "si"))
        g_ptr_array_add(book->strings, unescape_cell(book->text));
    else if (!strcmp(tag, "rPh"))
        book->phonetic--;
    else if (!strcmp(tag, "t"))
        book->collect = FALSE;
}

static char *first_section(const char *format) {
    const char *end = strchr(format, ';');
    return end ? g_strndup(format, end - format) : g_strdup(format);
}

static gboolean bracket_unit(const char *p, const char *units) {
    // Matches [h] or [hh].
    if (*p != '[' || !p[1] || !strchr(units, p[1]))
        return FALSE;
    p += 2;
    if (*p == p[-1])
        p++;
    return *p == ']';
}

static gboolean date_format(const char *format) {
    char *section = first_section(format);
    GString *kept = g_string_new(NULL);
    for (const char *p = section; *p;) {
        if (*p == '"') {
            const char *close = strchr(p + 1, '"');
            if (close) {
                p = close + 1;
                continue;
            }
        } else if (*p == '[' && !bracket_unit(p, "hms")) {
            const char *close = strchr(p, ']');
            if (close) {
                p = close + 1;
                continue;
            }
        }
        g_string_append_c(kept, *p++);
    }
    gboolean found = FALSE;
    for (gsize i = 0; i < kept->len && !found; i++)
        found = strchr("dmhysDMHYS", kept->str[i]) && (i == 0 || (kept->str[i - 1] != '_' && kept->str[i - 1] != '\\'));
    g_string_free(kept, TRUE);
    g_free(section);
    return found;
}

static gboolean delta_format(const char *format) {
    char *section = first_section(format);
    gboolean found = FALSE;
    for (const char *p = section; *p && !found; p++)
        found = bracket_unit(p, "hmsHMS");
    g_free(section);
    return found;
}

static const char *builtin_format(int id) {
    static const char *const dates[] = {"mm-dd-yy", "d-mmm-yy", "d-mmm", "mmm-yy", "h:mm AM/PM", "h:mm:ss AM/PM",
                                        "h:mm",     "h:mm:ss",  "m/d/yy h:mm"};
    if (id >= 14 && id <= 22)
        return dates[id - 14];
    if (id == 45)
        return "mm:ss";
    if (id == 46)
        return "[h]:mm:ss";
    if (id == 47)
        return "mmss.0";
    return NULL;
}

static void styles_start(void *user, const XML_Char *name, const XML_Char **attributes) {
    Book *book = user;
    const char *tag = local(name);
    if (!strcmp(tag, "numFmt")) {
        const char *id = plain_attribute(attributes, "numFmtId"), *code = plain_attribute(attributes, "formatCode");
        if (id && code)
            g_hash_table_insert(book->formats, GINT_TO_POINTER(atoi(id)), g_strdup(code));
    } else if (!strcmp(tag, "cellXfs")) {
        book->in_xfs = TRUE;
    } else if (!strcmp(tag, "xf") && book->in_xfs) {
        const char *id = plain_attribute(attributes, "numFmtId");
        int number = id ? atoi(id) : 0;
        const char *format = g_hash_table_lookup(book->formats, GINT_TO_POINTER(number));
        if (!format)
            format = builtin_format(number);
        gboolean is_date = format && date_format(format), is_delta = format && delta_format(format);
        g_array_append_val(book->date_styles, is_date);
        g_array_append_val(book->delta_styles, is_delta);
    }
}

static void styles_end(void *user, const XML_Char *name) {
    Book *book = user;
    if (!strcmp(local(name), "cellXfs"))
        book->in_xfs = FALSE;
}

/* Cell values follow openpyxl. */

static char *cast_number(const char *text, double *number, gboolean *is_float) {
    *is_float = strpbrk(text, ".Ee") != NULL;
    *number = g_ascii_strtod(text, NULL);
    if (*is_float)
        return py_float_repr(*number);
    const char *p = text;
    gboolean negative = *p == '-';
    if (*p == '-' || *p == '+')
        p++;
    while (*p == '0' && p[1])
        p++;
    for (const char *q = p; *q; q++)
        if (!g_ascii_isdigit(*q))
            return g_strdup(text);
    return g_strdup_printf("%s%s", negative && strcmp(p, "0") ? "-" : "", p);
}

static gint64 round_even(double value) {
    double floor_value = floor(value), difference = value - floor_value;
    if (difference > 0.5 || (difference == 0.5 && fmod(floor_value, 2.0) != 0))
        return (gint64)floor_value + 1;
    return (gint64)floor_value;
}

static char *clock_text(gint64 seconds, gint64 micros, gboolean pad_hours) {
    GString *out = g_string_new(NULL);
    g_string_printf(out, pad_hours ? "%02d:%02d:%02d" : "%d:%02d:%02d", (int)(seconds / 3600), (int)(seconds / 60 % 60),
                    (int)(seconds % 60));
    if (micros)
        g_string_append_printf(out, ".%06d", (int)micros);
    return g_string_free(out, FALSE);
}

static char *serial_date(double value, gboolean mac, gboolean delta) {
    if (delta) {
        gint64 total = round_even(value * 86400.0 * 1e6);
        gint64 micros = ((total % 1000000) + 1000000) % 1000000;
        if (micros)
            total = total - micros + round_even((double)micros / 1000.0) * 1000;
        gint64 day = 86400 * (gint64)1000000;
        gint64 days = total >= 0 ? total / day : -((-total + day - 1) / day);
        gint64 rest = total - days * day;
        char *clock = clock_text(rest / 1000000, rest % 1000000, FALSE);
        char *out = days ? g_strdup_printf("%" G_GINT64_FORMAT " day%s, %s", days, days == 1 || days == -1 ? "" : "s", clock)
                         : g_strdup(clock);
        g_free(clock);
        return out;
    }
    double whole = floor(value);
    gint64 millis = round_even((value - whole) * 86400.0 * 1000.0);
    if (value >= 0 && value < 1 && millis < 86400000)
        return clock_text(millis / 1000, millis % 1000 * 1000, TRUE);
    if (value > 0 && value < 60 && !mac)
        whole += 1;
    // Epochs are 1899-12-30 and 1904-01-01.
    double days = whole + (mac ? -24107.0 : -25569.0);
    if (fabs(days) > 4000000)
        return g_strdup("#VALUE!");
    char *stamp = utc_from_epoch((gint64)days * 86400 + millis / 1000);
    if (!*stamp) {
        g_free(stamp);
        return g_strdup("#VALUE!");
    }
    stamp[19] = 0;
    char *out = millis % 1000 ? g_strdup_printf("%s.%03d000", stamp, (int)(millis % 1000)) : g_strdup(stamp);
    g_free(stamp);
    return out;
}

static char *iso_cell(const char *text) {
    // Accepts date, time, both.
    int y, mo, d, h, mi, s = 0;
    const char *p = text;
    gboolean has_date = sscanf(p, "%4d-%2d-%2d", &y, &mo, &d) == 3 && strlen(p) >= 10 && p[4] == '-' && p[7] == '-';
    if (has_date)
        p += 10;
    if (*p == 'T')
        p++;
    gboolean has_time = sscanf(p, "%2d:%2d", &h, &mi) == 2 && strlen(p) >= 5 && p[2] == ':';
    int micros = 0;
    if (has_time) {
        p += 5;
        if (*p == ':' && g_ascii_isdigit(p[1]) && g_ascii_isdigit(p[2])) {
            s = (p[1] - '0') * 10 + (p[2] - '0');
            p += 3;
            if (*p == '.' && g_ascii_isdigit(p[1])) {
                int scale = 100000;
                for (p++; g_ascii_isdigit(*p) && scale >= 1000; p++, scale /= 10)
                    micros += (*p - '0') * scale;
            }
        }
    }
    if (!has_date && !has_time)
        return g_strdup(text);
    GString *out = g_string_new(NULL);
    if (has_date)
        g_string_append_printf(out, "%04d-%02d-%02d", y, mo, d);
    if (has_time) {
        g_string_append_printf(out, "%s%02d:%02d:%02d", has_date ? "T" : "", h, mi, s);
        if (micros)
            g_string_append_printf(out, ".%06d", micros);
    }
    return g_string_free(out, FALSE);
}

static int column_index(const char *reference) {
    int column = 0;
    for (const char *p = reference; g_ascii_isalpha(*p); p++)
        column = column * 26 + (g_ascii_toupper(*p) - 'A' + 1);
    return column;
}

static gboolean emit_row(Book *book, GPtrArray *row) {
    book->emitted++;
    if (!book->sink->row(row, book->sink->user, book->error)) {
        book->failed = TRUE;
        XML_StopParser(book->parser, XML_FALSE);
        return FALSE;
    }
    return TRUE;
}

static void sheet_start(void *user, const XML_Char *name, const XML_Char **attributes) {
    Book *book = user;
    const char *tag = local(name);
    if (!strcmp(tag, "row")) {
        const char *r = plain_attribute(attributes, "r");
        book->row_number = r ? g_ascii_strtoll(r, NULL, 10) : book->row_number + 1;
        book->column = 0;
        g_ptr_array_set_size(book->row, 0);
    } else if (!strcmp(tag, "c")) {
        const char *r = plain_attribute(attributes, "r"), *t = plain_attribute(attributes, "t");
        const char *s = plain_attribute(attributes, "s");
        book->column = r && column_index(r) ? column_index(r) : book->column + 1;
        g_free(book->cell_type);
        book->cell_type = g_strdup(t ? t : "n");
        book->cell_style = s ? atoi(s) : 0;
        book->has_value = book->has_formula = FALSE;
        g_string_truncate(book->value, 0);
        g_string_truncate(book->formula, 0);
        g_string_truncate(book->inline_text, 0);
    } else if (!strcmp(tag, "v")) {
        book->capture = 1;
        book->has_value = TRUE;
    } else if (!strcmp(tag, "f")) {
        book->capture = 2;
        book->has_formula = TRUE;
    } else if (!strcmp(tag, "rPh")) {
        book->phonetic++;
    } else if (!strcmp(tag, "t") && book->cell_type && !strcmp(book->cell_type, "inlineStr")) {
        book->capture = 3;
    }
}

static gboolean style_flag(GArray *flags, int style) {
    return style >= 0 && (guint)style < flags->len && g_array_index(flags, gboolean, style);
}

static void sheet_end(void *user, const XML_Char *name) {
    Book *book = user;
    const char *tag = local(name);
    if (!strcmp(tag, "v") || !strcmp(tag, "f") || !strcmp(tag, "t")) {
        book->capture = 0;
    } else if (!strcmp(tag, "rPh")) {
        book->phonetic--;
    } else if (!strcmp(tag, "c")) {
        const char *type = book->cell_type;
        char *value = NULL;
        if (book->has_formula) {
            value = g_strconcat("=", book->formula->str, NULL);
        } else if (!strcmp(type, "inlineStr")) {
            value = unescape_cell(book->inline_text);
        } else if (book->has_value && book->value->len) {
            const char *text = book->value->str;
            if (!strcmp(type, "n")) {
                double number;
                gboolean is_float;
                value = cast_number(text, &number, &is_float);
                if (style_flag(book->date_styles, book->cell_style)) {
                    g_free(value);
                    value = serial_date(number, book->mac_epoch, style_flag(book->delta_styles, book->cell_style));
                }
            } else if (!strcmp(type, "s")) {
                guint index = (guint)g_ascii_strtoull(text, NULL, 10);
                value = g_strdup(index < book->strings->len ? book->strings->pdata[index] : "");
            } else if (!strcmp(type, "b")) {
                value = g_strdup(atoi(text) ? "True" : "False");
            } else if (!strcmp(type, "d")) {
                value = iso_cell(text);
            } else {
                value = g_strdup(text);
            }
        }
        if (book->column < 1 || book->column > 16384) {
            g_free(value);
            return;
        }
        while ((int)book->row->len < book->column)
            g_ptr_array_add(book->row, g_strdup(""));
        g_free(book->row->pdata[book->column - 1]);
        book->row->pdata[book->column - 1] = value ? value : g_strdup("");
    } else if (!strcmp(tag, "row")) {
        // Missing rows become empty.
        GPtrArray *blank = g_ptr_array_new();
        while (book->emitted + 1 < book->row_number && book->emitted < 1048576)
            if (!emit_row(book, blank))
                break;
        g_ptr_array_free(blank, TRUE);
        if (!book->failed && book->emitted < book->row_number)
            emit_row(book, book->row);
    }
}

static char *join_target(const char *base, const char *target) {
    if (target[0] == '/')
        return g_strdup(target + 1);
    char *folder = g_path_get_dirname(base);
    GPtrArray *parts = g_ptr_array_new_with_free_func(g_free);
    char *joined = !strcmp(folder, ".") ? g_strdup(target) : g_strconcat(folder, "/", target, NULL);
    char **split = g_strsplit(joined, "/", -1);
    for (char **p = split; *p; p++) {
        if (!strcmp(*p, "..") && parts->len)
            g_ptr_array_remove_index(parts, parts->len - 1);
        else if (strcmp(*p, ".") && **p)
            g_ptr_array_add(parts, g_strdup(*p));
    }
    g_ptr_array_add(parts, NULL);
    char *out = g_strjoinv("/", (char **)parts->pdata);
    g_strfreev(split);
    g_free(joined);
    g_free(folder);
    g_ptr_array_free(parts, TRUE);
    return out;
}

gboolean xlsx_read(const char *data, gsize length, const RowSink *sink, GError **error) {
    zip_error_t problem;
    zip_error_init(&problem);
    zip_source_t *source = zip_source_buffer_create(data, length, 0, &problem);
    zip_t *archive = source ? zip_open_from_source(source, ZIP_RDONLY, &problem) : NULL;
    if (!archive) {
        if (source)
            zip_source_free(source);
        bec_fail(error, "File is not a zip file");
        return FALSE;
    }
    guint64 expanded = 0;
    for (zip_int64_t i = 0; i < zip_get_num_entries(archive, 0); i++) {
        zip_stat_t info;
        if (zip_stat_index(archive, (zip_uint64_t)i, 0, &info) == 0)
            expanded += info.size;
    }
    if (expanded > 2 * 1024 * 1024 * (guint64)1024) {
        zip_discard(archive);
        bec_fail(error, "Workbook exceeds the 2 GiB expanded import limit");
        return FALSE;
    }
    Book book = {0};
    book.archive = archive;
    book.sink = sink;
    book.error = error;
    book.strings = g_ptr_array_new_with_free_func(g_free);
    book.date_styles = g_array_new(FALSE, FALSE, sizeof(gboolean));
    book.delta_styles = g_array_new(FALSE, FALSE, sizeof(gboolean));
    book.text = g_string_new(NULL);
    book.formats = g_hash_table_new_full(NULL, NULL, NULL, g_free);
    book.sheet_names = g_ptr_array_new_with_free_func(g_free);
    book.sheet_ids = g_ptr_array_new_with_free_func(g_free);
    book.targets = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    book.row = g_ptr_array_new_with_free_func(g_free);
    book.value = g_string_new(NULL);
    book.formula = g_string_new(NULL);
    book.inline_text = g_string_new(NULL);
    book.relations_office = TRUE;
    parse_entry(&book, "_rels/.rels", relation_start, nothing_end);
    book.relations_office = FALSE;
    if (!book.workbook_path)
        book.workbook_path = g_strdup("xl/workbook.xml");
    gboolean ok = !book.failed && (error == NULL || *error == NULL);
    if (ok && !parse_entry(&book, book.workbook_path, workbook_start, nothing_end)) {
        if (error && !*error)
            bec_fail(error, "File is not an Excel workbook");
        ok = FALSE;
    }
    if (ok) {
        char *folder = g_path_get_dirname(book.workbook_path);
        char *base = g_path_get_basename(book.workbook_path);
        char *relations = g_strdup_printf("%s/_rels/%s.rels", folder, base);
        parse_entry(&book, relations, relation_start, nothing_end);
        g_free(relations);
        g_free(base);
        g_free(folder);
        ok = error == NULL || *error == NULL;
    }
    // Locate strings and styles.
    GHashTableIter iter;
    gpointer key, target;
    char *strings_path = NULL, *styles_path = NULL;
    g_hash_table_iter_init(&iter, book.targets);
    while (g_hash_table_iter_next(&iter, &key, &target)) {
        if (g_str_has_suffix(target, "sharedStrings.xml"))
            strings_path = join_target(book.workbook_path, target);
        else if (g_str_has_suffix(target, "styles.xml"))
            styles_path = join_target(book.workbook_path, target);
    }
    if (ok && strings_path && zip_name_locate(archive, strings_path, 0) >= 0)
        ok = parse_entry(&book, strings_path, strings_start, strings_end);
    book.collect = FALSE;
    if (ok && styles_path && zip_name_locate(archive, styles_path, 0) >= 0)
        ok = parse_entry(&book, styles_path, styles_start, styles_end);
    for (guint i = 0; ok && i < book.sheet_names->len; i++) {
        const char *relation = g_hash_table_lookup(book.targets, book.sheet_ids->pdata[i]);
        if (!relation || !strstr(relation, "worksheets/"))
            continue;
        char *path = join_target(book.workbook_path, relation);
        book.row_number = book.emitted = 0;
        book.capture = 0;
        book.phonetic = 0;
        ok = sink->begin(book.sheet_names->pdata[i], sink->user, error) &&
             parse_entry(&book, path, sheet_start, sheet_end) && sink->end(sink->user, error);
        g_free(path);
    }
    g_free(strings_path);
    g_free(styles_path);
    g_free(book.workbook_path);
    g_free(book.cell_type);
    g_ptr_array_free(book.strings, TRUE);
    g_array_free(book.date_styles, TRUE);
    g_array_free(book.delta_styles, TRUE);
    g_string_free(book.text, TRUE);
    g_hash_table_destroy(book.formats);
    g_ptr_array_free(book.sheet_names, TRUE);
    g_ptr_array_free(book.sheet_ids, TRUE);
    g_hash_table_destroy(book.targets);
    g_ptr_array_free(book.row, TRUE);
    g_string_free(book.value, TRUE);
    g_string_free(book.formula, TRUE);
    g_string_free(book.inline_text, TRUE);
    zip_discard(archive);
    return ok;
}
