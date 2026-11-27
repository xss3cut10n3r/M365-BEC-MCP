#include "server.h"
#include <stdio.h>
#ifdef G_OS_WIN32
#include <glib/gwin32.h>
#endif

int main(int argc, char **argv) {
    (void)argc;
    char *case_path = NULL, *export_dir = NULL;
    char **inputs = NULL;
    GOptionEntry entries[] = {
        {"case", 0, 0, G_OPTION_ARG_FILENAME, &case_path, "Read existing analyzer case", "CASE.bec"},
        {"input", 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &inputs, "Import into temporary case (repeatable)", "FILE"},
        {"export-dir", 0, 0, G_OPTION_ARG_FILENAME, &export_dir, "Enable filtered exports here", "DIRECTORY"},
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
    Session session = {0};
    if (!g_option_context_parse_strv(options, &arguments, &error))
        goto done;
    if (arguments[1] || (!!case_path == !!inputs)) {
        bec_fail(&error, "Choose --case or one or more --input files. Use --help for usage.");
        goto done;
    }
    if (export_dir && !g_file_test(export_dir, G_FILE_TEST_IS_DIR)) {
        bec_fail(&error, "Export directory must already exist");
        goto done;
    }
    session.export_dir = export_dir;
    session.db = case_path ? case_read(case_path, &error) : case_connect("", &error);
    if (!session.db) goto done;
    if (case_path) {
        gint64 version = sql_int(session.db, "PRAGMA user_version", NULL);
        if (sql_int(session.db, "PRAGMA application_id", NULL) != APP_ID || (version != 1 && version != 2)) {
            bec_fail(&error, "Unsupported analyzer case");
            goto done;
        }
    }
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
