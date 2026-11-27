#include "core.h"

#include <stdlib.h>
#include <string.h>

static const char *const DDL[] = {
    "CREATE TABLE files(id INTEGER PRIMARY KEY, path TEXT, digest TEXT, size INTEGER, UNIQUE(path,digest))",
    "CREATE TABLE chunks(file INTEGER, part INTEGER, data BLOB, PRIMARY KEY(file,part))",
    "CREATE TABLE logs(id INTEGER PRIMARY KEY, file INTEGER, name TEXT, sheet TEXT, kind TEXT,"
    " headers TEXT, total INTEGER DEFAULT 0, issues INTEGER DEFAULT 0, warning TEXT DEFAULT '')",
    "CREATE TABLE events(id INTEGER PRIMARY KEY, log INTEGER, rownum INTEGER, time TEXT, actor TEXT,"
    " op TEXT, result TEXT, request TEXT, ip TEXT, raw TEXT, issue TEXT)",
    "CREATE INDEX event_time ON events(time,id)",
    "CREATE INDEX log_time ON events(log,time,id)",
    "CREATE INDEX request_id ON events(request) WHERE request!=''",
    "CREATE TABLE ips(event INTEGER, ip TEXT, PRIMARY KEY(event,ip))",
    "CREATE INDEX ips_value ON ips(ip,event)",
    "CREATE TABLE identities(event INTEGER, value TEXT COLLATE NOCASE, PRIMARY KEY(event,value))",
    "CREATE INDEX identity_value ON identities(value,event)",
    "CREATE TABLE marks(id INTEGER PRIMARY KEY,kind TEXT,lo TEXT,hi TEXT,UNIQUE(kind,lo,hi))",
};

const char *const VERDICTS[4] = {"Good", "Bad", "Unsure", "Unmarked"};

#define RULE_TABLE                                                                                            \
    "verdict_rules(id INTEGER PRIMARY KEY, batch INTEGER NOT NULL, kind TEXT NOT NULL,"                       \
    " lo TEXT NOT NULL, hi TEXT NOT NULL, verdict TEXT NOT NULL)"
#define TIMELINE_ROWS "SELECT e.id,row_number() OVER (ORDER BY (e.time=''),e.time,e.id) FROM events e"
#define EVENT_JOIN " FROM events e JOIN logs l ON l.id=e.log"

gboolean sql_run(sqlite3 *db, const char *sql, GError **error) {
    char *message = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &message) != SQLITE_OK) {
        bec_fail(error, "%s", message ? message : sqlite3_errmsg(db));
        sqlite3_free(message);
        return FALSE;
    }
    return TRUE;
}

sqlite3_stmt *sql_prepare(sqlite3 *db, const char *sql, GError **error) {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) {
        bec_fail(error, "%s", sqlite3_errmsg(db));
        return NULL;
    }
    return statement;
}

gint64 sql_int(sqlite3 *db, const char *sql, GError **error) {
    sqlite3_stmt *statement = sql_prepare(db, sql, error);
    if (!statement)
        return -1;
    gint64 value = -1;
    int state = sqlite3_step(statement);
    if (state == SQLITE_ROW)
        value = sqlite3_column_int64(statement, 0);
    else if (state != SQLITE_DONE)
        bec_fail(error, "%s", sqlite3_errmsg(db));
    else
        value = 0;
    sqlite3_finalize(statement);
    return value;
}

const char *column_text(sqlite3_stmt *statement, int index) {
    const char *text = (const char *)sqlite3_column_text(statement, index);
    return text ? text : "";
}

static gboolean transact(sqlite3 *db, const char *const *statements, int count, GError **error) {
    if (!sql_run(db, "BEGIN IMMEDIATE", error))
        return FALSE;
    for (int i = 0; i < count; i++) {
        if (!sql_run(db, statements[i], error)) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            return FALSE;
        }
    }
    return sql_run(db, "COMMIT", error);
}

static gboolean ensure_review_schema(sqlite3 *db, GError **error) {
    if (sql_int(db, "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='refresh_timeline_ids'",
                NULL) > 0)
        return TRUE;
    static const char *const steps[] = {
        "CREATE TABLE IF NOT EXISTS " RULE_TABLE,
        "CREATE INDEX IF NOT EXISTS verdict_scope ON verdict_rules(kind,lo,id)",
        "CREATE INDEX IF NOT EXISTS verdict_batch ON verdict_rules(batch)",
        "CREATE INDEX IF NOT EXISTS chronological_events ON events((time=''),time,id)",
        "CREATE TABLE IF NOT EXISTS timeline_ids(event INTEGER PRIMARY KEY, number INTEGER UNIQUE)",
        "DELETE FROM timeline_ids",
        "INSERT INTO timeline_ids " TIMELINE_ROWS,
        // Renumber after each completed sheet.
        "CREATE TRIGGER IF NOT EXISTS refresh_timeline_ids AFTER UPDATE OF total ON logs"
        " WHEN NEW.total != OLD.total BEGIN DELETE FROM timeline_ids;"
        " INSERT INTO timeline_ids " TIMELINE_ROWS "; END",
    };
    return transact(db, steps, G_N_ELEMENTS(steps), error);
}

// Archived evidence stays immutable.
static gboolean protect_evidence(sqlite3 *db, GError **error) {
    if (sql_int(db, "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='evidence_events_fixed'",
                NULL) > 0)
        return TRUE;
#define FIXED(name, when, table)                                                                              \
    "CREATE TRIGGER IF NOT EXISTS " name " BEFORE " when " ON " table                                         \
    " BEGIN SELECT RAISE(ABORT,'Archived evidence is read-only'); END"
    static const char *const steps[] = {
        FIXED("evidence_chunks_kept", "DELETE", "chunks"), FIXED("evidence_chunks_fixed", "UPDATE", "chunks"),
        FIXED("evidence_files_kept", "DELETE", "files"),   FIXED("evidence_files_fixed", "UPDATE", "files"),
        FIXED("evidence_events_kept", "DELETE", "events"), FIXED("evidence_events_fixed", "UPDATE OF raw", "events"),
    };
    return transact(db, steps, G_N_ELEMENTS(steps), error);
}

sqlite3 *case_connect(const char *path, GError **error) {
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        bec_fail(error, "%s", db ? sqlite3_errmsg(db) : "Case file could not be opened");
        sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 30000);
    GError *problem = NULL;
    gint64 identity = sql_int(db, "PRAGMA application_id", &problem);
    if (!problem && identity != APP_ID) {
        if (sql_run(db, "BEGIN IMMEDIATE", &problem)) {
            if (sql_int(db, "SELECT count(*) FROM sqlite_master", &problem) != 0) {
                if (!problem)
                    bec_fail(&problem, "Choose a valid M365 BEC case file");
            }
            for (guint i = 0; !problem && i < G_N_ELEMENTS(DDL); i++)
                sql_run(db, DDL[i], &problem);
            if (!problem)
                sql_run(db, "PRAGMA application_id=1111835441", &problem);
            if (!problem)
                sql_run(db, "PRAGMA user_version=2", &problem);
            if (!problem)
                sql_run(db, "COMMIT", &problem);
        }
    }
    if (!problem && sql_int(db, "PRAGMA user_version", &problem) == 1) {
        static const char *const migrate[] = {
            "ALTER TABLE files RENAME TO previous_files",
            "CREATE TABLE files(id INTEGER PRIMARY KEY, path TEXT, digest TEXT, size INTEGER, UNIQUE(path,digest))",
            "INSERT INTO files SELECT id,path,digest,size FROM previous_files",
            "DROP TABLE previous_files",
            "PRAGMA user_version=2",
        };
        transact(db, migrate, G_N_ELEMENTS(migrate), &problem);
    }
    if (!problem && sql_int(db, "PRAGMA user_version", &problem) != 2 && !problem)
        bec_fail(&problem, "Unsupported case format");
    if (!problem)
        ensure_review_schema(db, &problem);
    if (!problem)
        protect_evidence(db, &problem);
    if (problem) {
        g_propagate_error(error, problem);
        sqlite3_close(db);
        return NULL;
    }
    register_functions(db);
    sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    return db;
}

sqlite3 *case_read(const char *path, GError **error) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        bec_fail(error, "%s", db ? sqlite3_errmsg(db) : "Case file could not be opened");
        sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 30000);
    if (sql_int(db, "SELECT count(*) FROM sqlite_master WHERE name='verdict_rules'", NULL) == 0) {
        sql_run(db, "CREATE TEMP TABLE " RULE_TABLE, NULL);
        sql_run(db, "CREATE TEMP TABLE timeline_ids(event INTEGER PRIMARY KEY, number INTEGER UNIQUE)", NULL);
        sql_run(db, "INSERT INTO timeline_ids " TIMELINE_ROWS, NULL);
    }
    register_functions(db);
    return db;
}

gboolean assign_verdict(sqlite3 *db, const char *kind, GPtrArray *pairs, const char *verdict, GError **error) {
    gboolean known = !strcmp(kind, "event") || !strcmp(kind, "ip") || !strcmp(kind, "time");
    if (!known || !g_strv_contains((const char *const[]){"Good", "Bad", "Unsure", "Unmarked", NULL}, verdict)) {
        bec_fail(error, "Unknown verdict or scope");
        return FALSE;
    }
    if (!sql_run(db, "BEGIN IMMEDIATE", error))
        return FALSE;
    GError *problem = NULL;
    gint64 batch = sql_int(db, "SELECT coalesce(max(batch),0)+1 FROM verdict_rules", &problem);
    sqlite3_stmt *insert = problem ? NULL
                                   : sql_prepare(db, "INSERT INTO verdict_rules(batch,kind,lo,hi,verdict) VALUES(?,?,?,?,?)",
                                                 &problem);
    for (guint i = 0; insert && !problem && i + 1 < pairs->len; i += 2) {
        sqlite3_bind_int64(insert, 1, batch);
        sqlite3_bind_text(insert, 2, kind, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert, 3, pairs->pdata[i], -1, SQLITE_STATIC);
        sqlite3_bind_text(insert, 4, pairs->pdata[i + 1], -1, SQLITE_STATIC);
        sqlite3_bind_text(insert, 5, verdict, -1, SQLITE_STATIC);
        if (sqlite3_step(insert) != SQLITE_DONE)
            bec_fail(&problem, "%s", sqlite3_errmsg(db));
        sqlite3_reset(insert);
    }
    sqlite3_finalize(insert);
    if (problem) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        g_propagate_error(error, problem);
        return FALSE;
    }
    return sql_run(db, "COMMIT", error);
}

gboolean undo_verdict(sqlite3 *db, GError **error) {
    if (!sql_run(db, "BEGIN IMMEDIATE", error))
        return FALSE;
    gboolean ok = sql_run(db, "DELETE FROM verdict_rules WHERE batch=(SELECT max(batch) FROM verdict_rules)", error);
    if (ok && !sqlite3_changes(db))
        ok = sql_run(db, "DELETE FROM marks WHERE id=(SELECT max(id) FROM marks)", error);
    if (!ok) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return FALSE;
    }
    return sql_run(db, "COMMIT", error);
}

char *select_sql(GPtrArray *custom, GPtrArray *args) {
    GString *sql = g_string_new("SELECT e.id,e.rownum,e.time,e.actor,e.op,e.result,e.ip,e.issue,l.kind,l.name,l.sheet,");
    char *verdict = sql_verdict(), *reason = sql_reason();
    g_string_append_printf(sql, "%s AS source,%s AS timeline_id,%s AS verdict,%s AS reason", SQL_SOURCE, SQL_CASE_ID,
                           verdict, reason);
    g_free(verdict);
    g_free(reason);
    for (guint i = 0; custom && i < custom->len; i++) {
        g_string_append_printf(sql, ",field_display(l.headers,e.raw,?) AS custom_%u", i);
        args_text(args, ((CustomColumn *)custom->pdata[i])->path);
    }
    g_string_append(sql, EVENT_JOIN);
    return g_string_free(sql, FALSE);
}

char *sort_sql(const char *key, gboolean descending, GPtrArray *args, GError **error) {
    const char *order = descending ? "DESC" : "ASC";
    gboolean number = !strcmp(key, "timeline_id");
    if (number || !strcmp(key, "time"))
        return g_strdup_printf(" ORDER BY (e.time='') %s, e.time %s, e.id %s", number ? order : "ASC", order, order);
    if (g_str_has_prefix(key, "ptr:")) {
        args_text(args, key + 4);
        return g_strdup_printf(" ORDER BY field_display(l.headers,e.raw,?) %s, e.id %s", order, order);
    }
    static const char *const keys[] = {"rownum", "source", "name", "actor", "ip", "op", "result", "marks", NULL};
    char *verdict = sql_verdict();
    const char *exprs[] = {"e.rownum", SQL_SOURCE, "l.name", "e.actor", "e.ip", "e.op", "e.result", verdict};
    char *sql = NULL;
    for (int i = 0; keys[i]; i++)
        if (!strcmp(keys[i], key))
            sql = g_strdup_printf(" ORDER BY %s %s, e.id %s", exprs[i], order, order);
    g_free(verdict);
    if (!sql)
        bec_fail(error, "Unknown sort column");
    return sql;
}

char *where_sql(gint64 log, const char *query, GPtrArray *args, GError **error) {
    Query *parsed = query_new(query, error);
    if (!parsed)
        return NULL;
    char *sql = g_strdup_printf(" WHERE %s%s", parsed->sql, log ? " AND e.log=?" : "");
    for (guint i = 0; i < parsed->args->len; i++) {
        Arg *arg = parsed->args->pdata[i];
        if (arg->integer)
            args_int(args, arg->number);
        else
            args_text(args, arg->text);
    }
    if (log)
        args_int(args, log);
    query_free(parsed);
    return sql;
}

sqlite3_stmt *query_rows(sqlite3 *db, gint64 log, const char *query, gboolean descending, const char *order_by,
                         GPtrArray *custom, GError **error) {
    GPtrArray *args = args_new();
    char *select = select_sql(custom, args);
    char *clause = where_sql(log, query, args, error);
    char *order = clause ? sort_sql(order_by ? order_by : "time", descending, args, error) : NULL;
    sqlite3_stmt *statement = NULL;
    if (order) {
        char *sql = g_strconcat(select, clause, order, NULL);
        statement = sql_prepare(db, sql, error);
        if (statement)
            args_bind(statement, args, 1);
        g_free(sql);
    }
    g_free(select);
    g_free(clause);
    g_free(order);
    g_ptr_array_free(args, TRUE);
    return statement;
}

gint64 count_rows(sqlite3 *db, gint64 log, const char *query, GError **error) {
    GPtrArray *args = args_new();
    char *clause = where_sql(log, query, args, error);
    gint64 count = -1;
    if (clause) {
        char *sql = g_strconcat("SELECT count(*) FROM events e JOIN logs l ON e.log=l.id", clause, NULL);
        sqlite3_stmt *statement = sql_prepare(db, sql, error);
        if (statement) {
            args_bind(statement, args, 1);
            if (sqlite3_step(statement) == SQLITE_ROW)
                count = sqlite3_column_int64(statement, 0);
            else
                bec_fail(error, "%s", sqlite3_errmsg(db));
            sqlite3_finalize(statement);
        }
        g_free(sql);
    }
    g_free(clause);
    g_ptr_array_free(args, TRUE);
    return count;
}

char *absolute_path(const char *path) {
#ifdef G_OS_WIN32
    return g_canonicalize_filename(path, NULL);
#else
    char *resolved = realpath(path, NULL);
    if (resolved) {
        char *copy = g_strdup(resolved);
        free(resolved);
        return copy;
    }
    return g_canonicalize_filename(path, NULL);
#endif
}

static gboolean same_path(const char *left, const char *right) {
    char *a = absolute_path(left), *b = absolute_path(right);
#ifdef G_OS_WIN32
    char *fa = casefold(a), *fb = casefold(b);
    gboolean same = !strcmp(fa, fb);
    g_free(fa);
    g_free(fb);
#else
    gboolean same = !strcmp(a, b);
#endif
    g_free(a);
    g_free(b);
    return same;
}

gboolean guard_destination(sqlite3 *db, const char *destination, GError **error) {
    gboolean clash = FALSE;
    sqlite3_stmt *statement = sql_prepare(db, "SELECT path FROM files", NULL);
    while (statement && !clash && sqlite3_step(statement) == SQLITE_ROW)
        clash = same_path(destination, column_text(statement, 0));
    sqlite3_finalize(statement);
    statement = sql_prepare(db, "PRAGMA database_list", NULL);
    if (statement && sqlite3_step(statement) == SQLITE_ROW) {
        const char *base = column_text(statement, 2);
        static const char *const suffixes[] = {"", "-wal", "-shm", "-journal"};
        for (guint i = 0; i < G_N_ELEMENTS(suffixes) && !clash; i++) {
            char *path = g_strconcat(base, suffixes[i], NULL);
            clash = same_path(destination, path);
            g_free(path);
        }
    }
    sqlite3_finalize(statement);
    if (clash)
        bec_fail(error, "Choose a destination separate from evidence and case files");
    return !clash;
}

gboolean log_is_json(const char *name) {
    size_t length = strlen(name);
    return length > 5 && !g_ascii_strcasecmp(name + length - 5, ".json");
}

char *json_path(const char *sheet, gint64 rownum) {
    if (!strcmp(sheet, "#"))
        return g_strdup("#");
    return g_strdup_printf("%s/%" G_GINT64_FORMAT, sheet, rownum - 1);
}

char *source_location(const char *name, const char *sheet, gint64 rownum) {
    if (log_is_json(name)) {
        char *path = json_path(sheet, rownum);
        char *out = g_strdup_printf("%s \xc2\xb7 %s", name, path);
        g_free(path);
        return out;
    }
    if (*sheet)
        return g_strdup_printf("%s \xc2\xb7 %s \xc2\xb7 row %" G_GINT64_FORMAT, name, sheet, rownum);
    return g_strdup_printf("%s \xc2\xb7 row %" G_GINT64_FORMAT, name, rownum);
}
