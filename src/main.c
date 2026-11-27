#include "server.h"
#include <stdio.h>
#ifdef G_OS_WIN32
#include <glib/gwin32.h>
#endif

int main(int argc, char **argv) {
    (void)argc;
    char *case_path = NULL, *export_dir = NULL;
    char **inputs = NULL;
    Session session = {0};
    GOptionEntry entries[] = {
        {"case", 0, 0, G_OPTION_ARG_FILENAME, &case_path, "Analyzer case to read, or to create with --input", "CASE.bec"},
        {"input", 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &inputs, "Import into the case, or a temporary one (repeatable)", "FILE"},
        {"allow-marks", 0, 0, G_OPTION_ARG_NONE, &session.allow_marks, "Let mark_events save verdicts in --case", NULL},
        {"export-dir", 0, 0, G_OPTION_ARG_FILENAME, &export_dir, "Enable filtered exports here", "DIRECTORY"},
        {"full-output", 0, 0, G_OPTION_ARG_NONE, &session.full_output, "Include full fields and structured MCP results", NULL},
        {NULL}
    };
    GOptionContext *options = g_option_context_new(NULL);
    g_option_context_add_main_entries(options, entries, NULL);
#ifdef G_OS_WIN32
    (void)argv;
    char **arguments = g_win32_get_command_line();
#else
    char **arguments = g_strdupv(argv);
#endif
    GError *error = NULL;
    if (!g_option_context_parse_strv(options, &arguments, &error))
        goto done;
    if (arguments[1] || (!case_path && !inputs)) {
        bec_fail(&error, "Choose --case, one or more --input files, or both. Use --help for usage.");
        goto done;
    }
    gboolean exists = case_path && g_file_test(case_path, G_FILE_TEST_EXISTS);
    if (case_path && !exists && !inputs) {
        bec_fail(&error, "Case not found: %s. Add --input files to create it.", case_path);
        goto done;
    }
    // Temporary cases always take marks.
    if (!case_path) session.allow_marks = TRUE;
    gboolean writes = !case_path || inputs || session.allow_marks;
    if (export_dir && !g_file_test(export_dir, G_FILE_TEST_IS_DIR)) {
        bec_fail(&error, "Export directory must already exist");
        goto done;
    }
    session.export_dir = export_dir;
    if (exists) {
        // Reject files that aren't cases.
        sqlite3 *probe = case_read(case_path, &error);
        if (!probe) goto done;
        gint64 version = sql_int(probe, "PRAGMA user_version", NULL);
        gboolean valid = sql_int(probe, "PRAGMA application_id", NULL) == APP_ID && (version == 1 || version == 2);
        if (writes) sqlite3_close(probe);
        else session.db = probe;
        if (!valid) {
            bec_fail(&error, "Unsupported analyzer case");
            goto done;
        }
    }
    if (!session.db) session.db = case_connect(case_path ? case_path : "", &error);
    if (!session.db) goto done;
    for (int i = 0; inputs && inputs[i]; ++i) {
        if (import_file(session.db, inputs[i], NULL, NULL, &error) == IMPORT_FAILED) {
            if (!error) bec_fail(&error, "Could not import %s", inputs[i]);
            goto done;
        }
    }
    if (sql_run(session.db, "PRAGMA query_only=ON", &error))
        serve(&session);
done:
    if (error) fprintf(stderr, "%s\n", error->message);
    int status = error != NULL;
    g_clear_error(&error);
    if (session.db) sqlite3_close(session.db);
    g_option_context_free(options);
    g_strfreev(arguments);
    g_strfreev(inputs);
    g_free(case_path);
    g_free(export_dir);
    return status;
}
