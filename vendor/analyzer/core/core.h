#ifndef BEC_CORE_H
#define BEC_CORE_H

#include <glib.h>
#include <sqlite3.h>

#define APP_TITLE "M365 Email Log Analyzer"
#define APP_ID 0x42454331

// Errors use this domain.
#define BEC_ERROR bec_error_quark()
GQuark bec_error_quark(void);
void bec_fail(GError **error, const char *format, ...) G_GNUC_PRINTF(2, 3);

/* text.c */
gboolean py_isspace(gunichar c);
char *py_strip(const char *text);
char *casefold(const char *text);
char *clean_header(const char *text);
gboolean contains_folded(const char *haystack, const char *folded_needle);
gboolean equals_folded(const char *value, const char *folded_needle);
char *utc_normalize(const char *value);
char *utc_from_epoch(gint64 seconds);
char *utc_add_microsecond(const char *stamp);
char *ip_normalize(const char *value);
char *group_digits(gint64 value);

/* json.c */
typedef enum { J_NULL, J_FALSE, J_TRUE, J_NUM, J_STR, J_ARR, J_OBJ } JType;
typedef struct JV JV;
typedef struct {
    const char *key;
    JV *v;
} JMember;
struct JV {
    JType t;
    guint n;
    union {
        const char *s;
        JV **a;
        JMember *m;
    } u;
};
typedef struct JDoc JDoc;
struct JDoc {
    JV *root;
    GSList *blocks;
    gsize used;
};
enum { J_STRICT_KEYS = 1 };
JDoc *j_parse(const char *text, gssize length, int flags, GError **error);
void j_free(JDoc *doc);
JV *j_get(const JV *object, const char *key);
gboolean j_is_container(const JV *value);
enum { J_COMPACT = 0, J_INDENT = 1, J_RAW_NUMBERS = 2, J_LINE_SEPARATORS = 4 };
void j_dump(GString *out, const JV *value, int flags);
void j_quote(GString *out, const char *text, gssize length);
char *j_quoted(const char *text);
char *j_number_text(const JV *number);
char *py_float_repr(double value);
char *j_text(const JV *value, gboolean json_booleans);
char *j_scalar(const JV *value);
// Decode embedded JSON cells.
const JV *j_decode(JDoc *doc, const JV *value);

/* fields.c */
typedef struct {
    const char *name;
    const char *outer[5];
    const char *inner[3];
} Slot;
extern const Slot SLOTS[];
extern const int SLOT_COUNT;
const Slot *slot_find(const char *name);
typedef struct {
    GPtrArray *names;
    GHashTable *positions;
    GPtrArray *clean;
} Columns;
Columns *columns_new(const char *headers_json);
void columns_free(Columns *columns);
GArray *columns_get(const Columns *columns, const char *name);
gboolean columns_support(const Columns *columns, const char *field);
typedef struct {
    Columns *columns;
    gboolean own_columns;
    JDoc *row;
    JDoc *audit_doc;
    const JV *audit;
} EventFields;
EventFields *event_fields_new(const char *headers, const char *raw);
void event_fields_free(EventFields *fields);
GPtrArray *event_values(EventFields *fields, const char *field);
GPtrArray *pointer_values(Columns *columns, const char *raw, const char *pointer, gboolean presence);
char *escape_pointer(const char *key);
void register_functions(sqlite3 *db);
char *source_label(const char *kind);
char *field_display(Columns *columns, const char *raw, const char *pointer);

/* bql.c */
extern const char SQL_SOURCE[];
extern const char *SQL_CASE_ID;
char *sql_verdict(void);
char *sql_reason(void);
typedef struct {
    char *sql;
    GPtrArray *args;
} Query;
typedef struct {
    gboolean integer;
    gint64 number;
    char *text;
} Arg;
Query *query_new(const char *text, GError **error);
void query_free(Query *query);
void args_text(GPtrArray *args, const char *text);
void args_int(GPtrArray *args, gint64 number);
GPtrArray *args_new(void);
int args_bind(sqlite3_stmt *statement, GPtrArray *args, int start);
extern const char *const BQL_FIELDS[];

/* store.c */
extern const char *const VERDICTS[4];
sqlite3 *case_connect(const char *path, GError **error);
sqlite3 *case_read(const char *path, GError **error);
gboolean sql_run(sqlite3 *db, const char *sql, GError **error);
gint64 sql_int(sqlite3 *db, const char *sql, GError **error);
sqlite3_stmt *sql_prepare(sqlite3 *db, const char *sql, GError **error);
gboolean assign_verdict(sqlite3 *db, const char *kind, GPtrArray *pairs, const char *verdict, GError **error);
gboolean undo_verdict(sqlite3 *db, GError **error);
typedef struct {
    char *label;
    char *path;
} CustomColumn;
char *select_sql(GPtrArray *custom, GPtrArray *args);
char *sort_sql(const char *key, gboolean descending, GPtrArray *args, GError **error);
char *where_sql(gint64 log, const char *query, GPtrArray *args, GError **error);
sqlite3_stmt *query_rows(sqlite3 *db, gint64 log, const char *query, gboolean descending, const char *order_by,
                         GPtrArray *custom, GError **error);
gint64 count_rows(sqlite3 *db, gint64 log, const char *query, GError **error);
gboolean guard_destination(sqlite3 *db, const char *destination, GError **error);
char *absolute_path(const char *path);
const char *column_text(sqlite3_stmt *statement, int index);
gboolean log_is_json(const char *name);
char *source_location(const char *name, const char *sheet, gint64 rownum);
char *json_path(const char *sheet, gint64 rownum);

/* stats.c */
typedef struct {
    const char *key;
    const char *title;
    const char *fields[3];
    const char *headings[3];
    const char *subset;
} Report;
extern const Report REPORTS[];
extern const int REPORT_COUNT;
const Report *report_find(const char *key);
int report_width(const Report *report);
typedef struct {
    char *values[3];
    gint64 epoch;
    gint64 count;
    char *first;
    char *last;
} StatRow;
void stat_row_free(StatRow *row);
GPtrArray *stats_calculate(sqlite3 *db, const char *key, gint64 log, const char *filter, int interval,
                           GError **error);
char *stats_drilldown(const char *key, const StatRow *row, int interval);
char *combine_filters(const char *first, const char *second);
typedef struct {
    gint64 id;
    char *name;
    char *sheet;
    char *kind;
    gint64 total;
    gint64 issues;
    char *warning;
    gint64 linked;
    gint64 missing;
} QualityRow;
void quality_row_free(QualityRow *row);
GPtrArray *stats_quality(sqlite3 *db, GError **error);

#endif
