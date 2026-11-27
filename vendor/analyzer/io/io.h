#ifndef BEC_IO_H
#define BEC_IO_H

#include "../core/core.h"

// Readers push rows here.
typedef struct {
    gboolean (*begin)(const char *sheet, gpointer user, GError **error);
    gboolean (*row)(GPtrArray *values, gpointer user, GError **error);
    gboolean (*end)(gpointer user, GError **error);
    gpointer user;
} RowSink;

gboolean csv_read(const char *data, gsize length, const RowSink *sink, GError **error);
gboolean xlsx_read(const char *data, gsize length, const RowSink *sink, GError **error);
char *decode_text(const char *data, gsize length, gsize *out_length, GError **error);

typedef void (*ProgressFn)(const char *message, gpointer user);
typedef enum { IMPORT_FAILED, IMPORT_DONE, IMPORT_DUPLICATE } ImportState;
ImportState import_file(sqlite3 *db, const char *path, ProgressFn progress, gpointer user, GError **error);
gboolean import_supported(const char *path);

typedef struct Importer Importer;
gboolean importer_begin(Importer *importer, const char *sheet, GError **error);
gboolean importer_row(Importer *importer, GPtrArray *values, const char *raw, const JV *record, GError **error);
gboolean importer_end(Importer *importer, GError **error);
void importer_warn(Importer *importer, const char *warning);
gboolean json_import(Importer *importer, const char *data, gsize length, GError **error);

gboolean export_events(sqlite3 *db, const char *destination, gint64 log, const char *query, gboolean descending,
                       const char *order_by, GPtrArray *custom, GError **error);
gboolean extract_evidence(sqlite3 *db, gint64 file_id, const char *destination, GError **error);
char *csv_line(GPtrArray *cells, gboolean neutralize);
gboolean replace_file(const char *temporary, const char *destination, GError **error);
char *temporary_beside(const char *destination, GError **error);

#endif
