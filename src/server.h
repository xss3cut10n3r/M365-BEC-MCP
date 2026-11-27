#pragma once

#include "io/io.h"
#include <yyjson.h>

typedef struct {
    sqlite3 *db;
    const char *export_dir;
    gboolean full_output;
    gboolean allow_marks;
} Session;

typedef yyjson_mut_doc JsonDoc;
typedef yyjson_mut_val Json;
typedef yyjson_val Input;

void serve(Session *session);
Json *list_prompts(JsonDoc *doc);
Json *get_prompt(JsonDoc *doc, const char *name);
Json *compare_containment(JsonDoc *doc, Session *session, Input *args, GError **error);
Json *list_tools(JsonDoc *doc, const Session *session);
Json *call_tool(JsonDoc *doc, Session *session, const char *name, Input *args, GError **error);

static inline void put_text(JsonDoc *doc, Json *obj, const char *key, const char *value) {
    if (value)
        yyjson_mut_obj_add_strcpy(doc, obj, key, value);
    else
        yyjson_mut_obj_add_null(doc, obj, key);
}
