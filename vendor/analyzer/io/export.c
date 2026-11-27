#include "io.h"

#include <glib/gstdio.h>
#include <string.h>
#include <xlsxwriter.h>
#include <zlib.h>

#ifdef G_OS_UNIX
#include <unistd.h>
#else
#include <io.h>
#endif

enum { C_ID, C_ROW, C_TIME, C_ACTOR, C_OP, C_RESULT, C_IP, C_ISSUE, C_KIND, C_NAME, C_SHEET, C_SOURCE, C_NUMBER, C_VERDICT, C_REASON, C_CUSTOM };

static const char *const EXPORT_HEADER[] = {"Source", "File",   "Sheet",        "Source row",   "Time (UTC)", "Actor", "Operation",
                                            "Result", "IP",     "Analyst mark", "Import issue", "ID",         "Verdict"};

char *temporary_beside(const char *destination, GError **error) {
    char *folder = g_path_get_dirname(destination);
    const char *dot = strrchr(destination, '.');
    const char *slash = strrchr(destination, G_DIR_SEPARATOR);
    char *suffix = g_strdup(dot && (!slash || dot > slash) ? dot : "");
    char *path = g_strdup_printf("%s%c.bec-XXXXXX%s", folder, G_DIR_SEPARATOR, suffix);
    int handle = g_mkstemp(path);
    g_free(folder);
    g_free(suffix);
    if (handle < 0) {
        bec_fail(error, "Destination folder is not writable");
        g_free(path);
        return NULL;
    }
    close(handle);
    return path;
}

gboolean replace_file(const char *temporary, const char *destination, GError **error) {
    if (g_rename(temporary, destination) != 0) {
        bec_fail(error, "Could not write %s", destination);
        return FALSE;
    }
    return TRUE;
}

static gboolean formula_like(const char *text) {
    while (*text && py_isspace(g_utf8_get_char(text)))
        text = g_utf8_next_char(text);
    return *text == '=' || *text == '+' || *text == '-' || *text == '@';
}

// Matches csv.writer minimal quoting.
char *csv_line(GPtrArray *cells, gboolean neutralize) {
    GString *out = g_string_new(NULL);
    for (guint i = 0; i < cells->len; i++) {
        const char *cell = cells->pdata[i] ? cells->pdata[i] : "";
        if (i)
            g_string_append_c(out, ',');
        gboolean guard = neutralize && formula_like(cell);
        if (!strpbrk(cell, ",\"\r\n") && !(cells->len == 1 && !*cell && !guard)) {
            if (guard)
                g_string_append_c(out, '\'');
            g_string_append(out, cell);
            continue;
        }
        g_string_append_c(out, '"');
        if (guard)
            g_string_append_c(out, '\'');
        for (const char *p = cell; *p; p++) {
            if (*p == '"')
                g_string_append_c(out, '"');
            g_string_append_c(out, *p);
        }
        g_string_append_c(out, '"');
    }
    g_string_append(out, "\r\n");
    return g_string_free(out, FALSE);
}

typedef struct {
    sqlite3_stmt *rows;
    guint custom;
    GPtrArray *cells;
    gboolean numeric[32];
} Cursor;

// Builds one export row.
static gboolean next_row(Cursor *cursor, sqlite3 *db, GError **error) {
    int state = sqlite3_step(cursor->rows);
    if (state != SQLITE_ROW) {
        if (state != SQLITE_DONE)
            bec_fail(error, "%s", sqlite3_errmsg(db));
        return FALSE;
    }
    sqlite3_stmt *r = cursor->rows;
    g_ptr_array_set_size(cursor->cells, 0);
    static const int order[] = {C_SOURCE, C_NAME, C_SHEET, C_ROW, C_TIME, C_ACTOR, C_OP, C_RESULT, C_IP, -1, C_ISSUE, C_NUMBER, C_VERDICT};
    for (guint i = 0; i < G_N_ELEMENTS(order); i++) {
        if (order[i] < 0) {
            const char *reason = column_text(r, C_REASON);
            g_ptr_array_add(cursor->cells, *reason ? g_strdup_printf("%s \xc2\xb7 %s", column_text(r, C_VERDICT), reason)
                                                   : g_strdup(""));
        } else {
            g_ptr_array_add(cursor->cells, g_strdup(column_text(r, order[i])));
        }
    }
    for (guint i = 0; i < cursor->custom; i++)
        g_ptr_array_add(cursor->cells, g_strdup(column_text(r, C_CUSTOM + (int)i)));
    return TRUE;
}

static GPtrArray *headings(GPtrArray *custom) {
    GPtrArray *cells = g_ptr_array_new_with_free_func(g_free);
    for (guint i = 0; i < G_N_ELEMENTS(EXPORT_HEADER); i++)
        g_ptr_array_add(cells, g_strdup(EXPORT_HEADER[i]));
    for (guint i = 0; custom && i < custom->len; i++)
        g_ptr_array_add(cells, g_strconcat("Field ", ((CustomColumn *)custom->pdata[i])->path, NULL));
    return cells;
}

static gboolean write_csv(Cursor *cursor, sqlite3 *db, const char *path, GPtrArray *titles, GError **error) {
    FILE *out = g_fopen(path, "wb");
    if (!out) {
        bec_fail(error, "Could not write %s", path);
        return FALSE;
    }
    fputs("\xef\xbb\xbf", out);
    char *line = csv_line(titles, FALSE);
    fputs(line, out);
    g_free(line);
    GError *problem = NULL;
    while (next_row(cursor, db, &problem)) {
        line = csv_line(cursor->cells, TRUE);
        // Numbers stay unguarded.
        fputs(line, out);
        g_free(line);
    }
    gboolean ok = !problem && !ferror(out);
    ok = fclose(out) == 0 && ok;
    if (problem)
        g_propagate_error(error, problem);
    else if (!ok)
        bec_fail(error, "Could not write %s", path);
    return ok;
}

static gboolean write_xlsx(Cursor *cursor, sqlite3 *db, const char *path, GPtrArray *titles, GError **error) {
    char *folder = g_path_get_dirname(path);
    lxw_workbook_options options = {.constant_memory = LXW_TRUE, .tmpdir = folder};
    lxw_workbook *book = workbook_new_opt(path, &options);
    lxw_worksheet *sheet = workbook_add_worksheet(book, "Timeline");
    // Blank cells keep row widths.
    lxw_format *plain = workbook_add_format(book);
    lxw_format *bold = workbook_add_format(book);
    format_set_bold(bold);
    // Excel good, bad, neutral.
    static const struct {
        const char *verdict;
        lxw_color_t fill, text;
    } tints[] = {{"Good", 0xC6EFCE, 0x006100}, {"Bad", 0xFFC7CE, 0x9C0006}, {"Unsure", 0xFFEB9C, 0x9C5700}};
    lxw_format *fills[G_N_ELEMENTS(tints)];
    for (guint i = 0; i < G_N_ELEMENTS(tints); i++) {
        fills[i] = workbook_add_format(book);
        format_set_bg_color(fills[i], tints[i].fill);
        format_set_font_color(fills[i], tints[i].text);
    }
    static const double widths[] = {24, 30, 10, 11, 27, 34, 34, 14, 22, 16, 14, 9, 10};
    GError *problem = NULL;
    lxw_row_t line = 0;
    gint64 index = 0;
    gboolean fresh = TRUE;
    while (!problem && (fresh || next_row(cursor, db, &problem))) {
        if (!fresh)
            index++;
        if (fresh || (index > 1 && (index - 1) % 1048575 == 0)) {
            if (!fresh)
                sheet = workbook_add_worksheet(book, NULL);
            for (guint i = 0; i < titles->len; i++) {
                worksheet_set_column(sheet, (lxw_col_t)i, (lxw_col_t)i, i < G_N_ELEMENTS(widths) ? widths[i] : 28, NULL);
                worksheet_write_string(sheet, 0, (lxw_col_t)i, titles->pdata[i], bold);
            }
            worksheet_freeze_panes(sheet, 1, 0);
            line = 0;
            if (fresh) {
                fresh = FALSE;
                continue;
            }
        }
        line++;
        lxw_format *tint = NULL;
        for (guint i = 0; i < G_N_ELEMENTS(tints); i++)
            if (!strcmp(cursor->cells->pdata[12], tints[i].verdict))
                tint = fills[i];
        for (guint i = 0; i < cursor->cells->len && !problem; i++) {
            const char *cell = cursor->cells->pdata[i];
            if (i == 3 || i == 11) {
                worksheet_write_number(sheet, line, (lxw_col_t)i, (double)g_ascii_strtoll(cell, NULL, 10), tint);
            } else if (g_utf8_strlen(cell, -1) > 32767) {
                bec_fail(&problem, "Value exceeds Excel cell limit. Export CSV instead.");
            } else if (*cell) {
                worksheet_write_string(sheet, line, (lxw_col_t)i, cell, tint);
            } else {
                worksheet_write_blank(sheet, line, (lxw_col_t)i, tint ? tint : plain);
            }
        }
    }
    lxw_error status = workbook_close(book);
    g_free(folder);
    if (problem) {
        g_propagate_error(error, problem);
        return FALSE;
    }
    if (status != LXW_NO_ERROR) {
        bec_fail(error, "Could not write workbook: %s", lxw_strerror(status));
        return FALSE;
    }
    return TRUE;
}

static void member(GString *out, const char *key, const char *text, gboolean number) {
    j_quote(out, key, -1);
    g_string_append_c(out, ':');
    if (number)
        g_string_append(out, *text ? text : "null");
    else
        j_quote(out, text, -1);
    g_string_append_c(out, ',');
}

// Rebuilds the original record.
static void write_record(GString *out, Columns *columns, const char *raw, gboolean json) {
    JDoc *doc = j_parse(raw, -1, 0, NULL);
    g_string_append_c(out, '{');
    if (doc && doc->root->t == J_ARR) {
        const JV *row = doc->root;
        guint width = columns->names->len, written = 0;
        const JV *present = row->n == width + 1 && row->u.a[width]->t == J_ARR ? row->u.a[width] : NULL;
        guint total = present ? present->n : row->n;
        GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        for (guint i = 0; i < total; i++) {
            guint index = present ? (guint)atoi(present->u.a[i]->u.s) : i;
            if (index >= row->n || (present && index >= width))
                continue;
            char *label;
            if (index >= width) {
                label = g_strdup_printf("Extra column %u", index + 1);
            } else if (json) {
                label = g_strdup(columns->names->pdata[index]);
            } else {
                // Number repeated headers.
                char *clean = clean_header(columns->names->pdata[index]);
                GArray *positions = g_hash_table_lookup(columns->positions, clean);
                guint ordinal = 1;
                for (guint k = 0; positions && k < positions->len; k++)
                    if ((guint)g_array_index(positions, int, k) == index)
                        ordinal = k + 1;
                label = positions && positions->len > 1
                            ? g_strdup_printf("%s [%u]", (char *)columns->names->pdata[index], ordinal)
                            : g_strdup(columns->names->pdata[index]);
                g_free(clean);
            }
            while (g_hash_table_contains(seen, label)) {
                char *longer = g_strconcat(label, " ", NULL);
                g_free(label);
                label = longer;
            }
            if (written++)
                g_string_append_c(out, ',');
            j_quote(out, label, -1);
            g_string_append_c(out, ':');
            j_dump(out, row->u.a[index], J_RAW_NUMBERS);
            g_hash_table_add(seen, label);
        }
        g_hash_table_destroy(seen);
    }
    g_string_append_c(out, '}');
    j_free(doc);
}

static gboolean write_json(Cursor *cursor, sqlite3 *db, const char *path, GPtrArray *custom, GError **error) {
    FILE *out = g_fopen(path, "wb");
    if (!out) {
        bec_fail(error, "Could not write %s", path);
        return FALSE;
    }
    sqlite3_stmt *origin = sql_prepare(db,
                                       "SELECT l.headers,e.raw,f.digest FROM events e JOIN logs l ON l.id=e.log "
                                       "JOIN files f ON f.id=l.file WHERE e.id=?",
                                       error);
    GError *problem = NULL;
    char *cached = NULL;
    Columns *columns = NULL;
    GString *line = g_string_new(NULL);
    gboolean first = TRUE;
    fputs("[", out);
    while (origin && next_row(cursor, db, &problem)) {
        sqlite3_stmt *r = cursor->rows;
        const char *name = column_text(r, C_NAME), *sheet = column_text(r, C_SHEET);
        gint64 rownum = sqlite3_column_int64(r, C_ROW);
        gboolean json = log_is_json(name);
        sqlite3_bind_int64(origin, 1, sqlite3_column_int64(r, C_ID));
        if (sqlite3_step(origin) != SQLITE_ROW) {
            sqlite3_reset(origin);
            continue;
        }
        const char *headers = column_text(origin, 0);
        if (!cached || strcmp(cached, headers)) {
            columns_free(columns);
            g_free(cached);
            cached = g_strdup(headers);
            columns = columns_new(headers);
        }
        g_string_assign(line, first ? "\n{" : ",\n{");
        first = FALSE;
        member(line, "ID", column_text(r, C_NUMBER), TRUE);
        member(line, "Time (UTC)", column_text(r, C_TIME), FALSE);
        member(line, "Source", column_text(r, C_SOURCE), FALSE);
        member(line, "File", name, FALSE);
        member(line, "Sheet", json ? "" : sheet, FALSE);
        member(line, "Source row", column_text(r, C_ROW), TRUE);
        char *location = json ? json_path(sheet, rownum)
                              : *sheet ? g_strdup_printf("%s \xc2\xb7 row %" G_GINT64_FORMAT, sheet, rownum)
                                       : g_strdup_printf("row %" G_GINT64_FORMAT, rownum);
        member(line, "Location", location, FALSE);
        g_free(location);
        member(line, "SHA-256", column_text(origin, 2), FALSE);
        member(line, "Actor", column_text(r, C_ACTOR), FALSE);
        member(line, "Operation", column_text(r, C_OP), FALSE);
        member(line, "Result", column_text(r, C_RESULT), FALSE);
        member(line, "IP", column_text(r, C_IP), FALSE);
        member(line, "Analyst mark", cursor->cells->pdata[9], FALSE);
        member(line, "Import issue", column_text(r, C_ISSUE), FALSE);
        member(line, "Verdict", column_text(r, C_VERDICT), FALSE);
        for (guint i = 0; custom && i < custom->len; i++) {
            char *key = g_strconcat("Field ", ((CustomColumn *)custom->pdata[i])->path, NULL);
            member(line, key, column_text(r, C_CUSTOM + (int)i), FALSE);
            g_free(key);
        }
        j_quote(line, "Record", -1);
        g_string_append_c(line, ':');
        write_record(line, columns, column_text(origin, 1), json);
        g_string_append_c(line, '}');
        fwrite(line->str, 1, line->len, out);
        sqlite3_reset(origin);
    }
    fputs(first ? "]\n" : "\n]\n", out);
    gboolean ok = origin && !problem && !ferror(out);
    ok = fclose(out) == 0 && ok;
    sqlite3_finalize(origin);
    columns_free(columns);
    g_free(cached);
    g_string_free(line, TRUE);
    if (problem)
        g_propagate_error(error, problem);
    else if (!ok && error && !*error)
        bec_fail(error, "Could not write %s", path);
    return ok;
}

gboolean export_events(sqlite3 *db, const char *destination, gint64 log, const char *query, gboolean descending,
                       const char *order_by, GPtrArray *custom, GError **error) {
    char *target = absolute_path(destination);
    const char *dot = strrchr(target, '.');
    const char *suffix = dot ? dot : "";
    gboolean csv = !g_ascii_strcasecmp(suffix, ".csv"), xlsx = !g_ascii_strcasecmp(suffix, ".xlsx");
    gboolean json = !g_ascii_strcasecmp(suffix, ".json"), ok = FALSE;
    char *temporary = NULL;
    if (!guard_destination(db, target, error))
        goto done;
    if (!csv && !xlsx && !json) {
        bec_fail(error, "Choose CSV, XLSX or JSON");
        goto done;
    }
    Cursor cursor = {0};
    cursor.rows = query_rows(db, log, query, descending, order_by, custom, error);
    if (!cursor.rows)
        goto done;
    cursor.custom = custom ? custom->len : 0;
    cursor.cells = g_ptr_array_new_with_free_func(g_free);
    temporary = temporary_beside(target, error);
    if (temporary) {
        GPtrArray *titles = headings(custom);
        ok = xlsx ? write_xlsx(&cursor, db, temporary, titles, error)
                  : csv ? write_csv(&cursor, db, temporary, titles, error)
                        : write_json(&cursor, db, temporary, custom, error);
        g_ptr_array_free(titles, TRUE);
    }
    sqlite3_finalize(cursor.rows);
    g_ptr_array_free(cursor.cells, TRUE);
    ok = ok && replace_file(temporary, target, error);
done:
    if (temporary && !ok)
        g_unlink(temporary);
    g_free(temporary);
    g_free(target);
    return ok;
}

gboolean extract_evidence(sqlite3 *db, gint64 file_id, const char *destination, GError **error) {
    char *target = absolute_path(destination);
    char *temporary = NULL, *wanted = NULL;
    gboolean ok = FALSE;
    if (!guard_destination(db, target, error))
        goto done;
    sqlite3_stmt *lookup = sql_prepare(db, "SELECT digest FROM files WHERE id=?", error);
    if (!lookup)
        goto done;
    sqlite3_bind_int64(lookup, 1, file_id);
    if (sqlite3_step(lookup) == SQLITE_ROW)
        wanted = g_strdup(column_text(lookup, 0));
    sqlite3_finalize(lookup);
    if (!wanted) {
        bec_fail(error, "Evidence file is not in this case");
        goto done;
    }
    temporary = temporary_beside(target, error);
    if (!temporary)
        goto done;
    FILE *out = g_fopen(temporary, "wb");
    sqlite3_stmt *chunks = sql_prepare(db, "SELECT data FROM chunks WHERE file=? ORDER BY part", error);
    GChecksum *digest = g_checksum_new(G_CHECKSUM_SHA256);
    gsize room = 2 * 1024 * 1024;
    Bytef *buffer = g_malloc(room);
    ok = out && chunks;
    if (chunks)
        sqlite3_bind_int64(chunks, 1, file_id);
    while (ok && sqlite3_step(chunks) == SQLITE_ROW) {
        uLongf size = (uLongf)room;
        int state;
        while ((state = uncompress(buffer, &size, sqlite3_column_blob(chunks, 0), (uLong)sqlite3_column_bytes(chunks, 0))) ==
               Z_BUF_ERROR && room < 1024 * 1024 * 1024) {
            room *= 2;
            buffer = g_realloc(buffer, room);
            size = (uLongf)room;
        }
        if (state != Z_OK) {
            bec_fail(error, "Archived bytes could not be expanded");
            ok = FALSE;
            break;
        }
        g_checksum_update(digest, buffer, (gssize)size);
        ok = fwrite(buffer, 1, size, out) == size;
    }
    if (out)
        ok = fclose(out) == 0 && ok;
    if (ok && strcmp(g_checksum_get_string(digest), wanted)) {
        bec_fail(error, "Archived bytes failed SHA-256 verification");
        ok = FALSE;
    }
    if (!ok && error && !*error)
        bec_fail(error, "Could not write %s", target);
    g_checksum_free(digest);
    g_free(buffer);
    sqlite3_finalize(chunks);
    ok = ok && replace_file(temporary, target, error);
done:
    if (temporary && !ok)
        g_unlink(temporary);
    g_free(temporary);
    g_free(wanted);
    g_free(target);
    return ok;
}
