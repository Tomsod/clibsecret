/*
 *    clibsecret: CLI for GNOME libsecret
 *    Copyright 2015 Mihail Sh. <tomsod-m@ya.ru>
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <glib.h>
#define SECRET_API_SUBJECT_TO_CHANGE
#include <libsecret/secret.h>
#include <gio/gio.h> // g_dbus_proxy_get_object_path()

#include <stdio.h> // printf(), fgets(), fputs()
#include <string.h> // strchr(), strstr(), strlen()
#include <unistd.h> // getpass()

#define print(string) fputs(string, stdout)

static const gchar SUMMARY[] = "[LABEL] [ATTRIBUTE VALUE...]"
                               " - manage libsecret collections";

static struct
{
    gchar *keyring;
    gchar *alias;
    gboolean unlock;
    gboolean lock;
    gboolean show_keyring_info;
    gboolean new_keyring;
    gboolean delete_keyring;
    gboolean no_auto_unlock;
    gboolean new;
    gboolean delete;
    gboolean move;
    gchar *read;
    gchar *info;
    gchar *secret;
    gboolean change_secret;
} options = { NULL };

static const GOptionEntry opt_entries[] =
{
      { "keyring", 'k', 0, G_OPTION_ARG_STRING, &options.keyring,
        "Keyring to use (defaults to all)", "KEYRING" },
      { "alias", 'a', 0, G_OPTION_ARG_STRING, &options.alias,
        "Specify keyring by ALIAS (e.g. \"default\")", "ALIAS" },
      { "unlock", 'u', 0, G_OPTION_ARG_NONE, &options.unlock,
        "Unlock the keyring(s)", NULL },
      { "lock", 'l', 0, G_OPTION_ARG_NONE, &options.lock,
        "Lock the keyring(s) when done", NULL },
      { "keyring-info", 'I', 0, G_OPTION_ARG_NONE, &options.show_keyring_info,
        "Print keyring info", NULL },
      { "new-keyring", 'N', 0, G_OPTION_ARG_NONE, &options.new_keyring,
        "Create new keyring", NULL },
      { "delete-keyring", 'D', 0, G_OPTION_ARG_NONE, &options.delete_keyring,
        "Delete specified keyring", NULL },
      { "no-auto-unlock", 'U', 0, G_OPTION_ARG_NONE, &options.no_auto_unlock,
        "Exit with error if have to unlock anything", NULL },

      { "new", 'n', 0, G_OPTION_ARG_NONE, &options.new,
        "Add new item(s)", NULL },
      { "delete", 'd', 0, G_OPTION_ARG_NONE, &options.delete,
        "Delete items", NULL },
      { "move", 'm', 0, G_OPTION_ARG_NONE, &options.move,
        "Copy items to specified keyring", NULL },
      { "read", 'r', 0, G_OPTION_ARG_STRING, &options.read,
        "Read data from input using FORMAT", "FORMAT" },
      { "info", 'i', 0, G_OPTION_ARG_STRING, &options.info,
        "Print item info using FORMAT", "FORMAT" },
      { "secret", 's', 0, G_OPTION_ARG_STRING, &options.secret,
        "Set item secret to SECRET", "SECRET" },
      { "change-secret", 'S', 0, G_OPTION_ARG_NONE, &options.change_secret,
        "Prompt for new item secret", NULL },
      { NULL }
};

static const char DESCRIPTION[] =
    "FORMAT consists of %-prefixed specifiers separated by delimiters.\n"
    "Note that when using --read, every delimiter, including whitespace,\n"
    "must match exactly.\n"
    "\n"
    "Valid specifiers are:\n"
    "\n"
    "%i - item D-Bus ID.\n"
    "%l - item label.\n"
    "%s - item secret.\n"
    "%a - next attribute.\n"
    "%A - next attribute; if format string ends before all attributes are\n"
          "\texhausted, it is re-parsed from last %A.\n"
    "%v - next value.\n"
    "%c - new collection.\n"
    "%C - new collection by alias.\n"
    "%t - item creation time.\n"
    "%m - item modify time.\n"
    "%* - this specifier is parsed and discarded.\n"
    "%% - matches a single percent sign.\n"
    ;

/// For --read and --info. Corresponds to string "%" + option + delim.
struct format_parsed
{
    gchar option;
    gchar *delim;
};

void
format_parsed_free(gpointer format)
{
    struct format_parsed *self = format;
    g_free(self->delim);
    g_free(self);
}

//TODO: configurable type?
static const gchar TEXT_PLAIN[] = "text/plain";

static gchar *
print_time(const gchar *unknown, guint64 time)
{
    GTimeVal time_struct =
      {
        .tv_sec = time,
        .tv_usec = 0,
      };
    if (time) return g_time_val_to_iso8601(&time_struct);
    else return g_strdup(unknown);
}

/// Callback for g_hash_table_foreach(). Basically, it clones the table.
static void
ght_add(gpointer key, gpointer value, gpointer user_data)
{
    GHashTable *ght = user_data;
    g_hash_table_insert(ght, g_strdup(key), g_strdup(value));
}

static SecretCollection *
find_collection(SecretService *service, gchar *label)
{
    SecretCollection *collection = NULL;
    GList *all_collections = secret_service_get_collections(service);
    for (GList *elem = all_collections; elem; elem = elem->next)
      {
        SecretCollection *col = elem->data;
        gchar *col_label = secret_collection_get_label(col);
        if (!g_strcmp0(col_label, label))
          {
            collection = g_object_ref(col);
            g_free(col_label);
            break;
          }
        g_free(col_label);
      }
    g_list_free_full(all_collections, &g_object_unref);
    if (!collection) g_warning("Could not find collection \"%s\"!", label);
    return collection;
}

/// e.g. "foo %i bar" -> {{0, "foo "}, {'i', " bar"}}
static GList *
parse_format(gchar *spec)
{
    gchar **chunks = g_strsplit(spec, "%", -1);
    struct format_parsed *first = g_new(struct format_parsed, 1);
    first->option = 0;
    first->delim = g_strdup(chunks[0]);
    GList *format = g_list_append(NULL, first);
    for (gchar **chunk = &chunks[1]; *chunk; chunk++)
      {
        if (!**chunk)
          {
            // "%%" format
            chunk++;
            struct format_parsed *elem = format->data;
            gchar *old = elem->delim;
            elem->delim = g_strconcat(old, "%", *chunk, NULL);
            g_free(old);
            if (!*chunk) break;
            else continue;
          }
        struct format_parsed *parse = g_new(struct format_parsed, 1);
        parse->option = **chunk;
        parse->delim = g_strdup(*chunk + 1);
        format = g_list_prepend(format, parse);
      }
    g_strfreev(chunks);
    return g_list_reverse(format);
}

/// Initialised and used in process_item(), freed in main()
static GList *info_parsed = NULL;

/**
 * Most item options are handled here.
 * Parameters (except 'item') are what needs to be changed.
 */
static void
process_item(SecretItem *item, SecretCollection *collection, gchar *label,
             GHashTable *attributes, SecretValue *secret)
{
    GError *error = NULL;
    if (!secret && options.change_secret)
      {
        //TODO: secret for what?
        const char PROMPT[] = "Enter new secret: ";
        char *password = getpass(PROMPT);
        if (!password) g_warning("Error reading the secret.");
        else secret = secret_value_new(password, -1, TEXT_PLAIN);
      }

    gboolean free_item = FALSE;
    if (options.new)
      {
        if (!label)
            g_warning("Cannot create item: label not specified");
        else if (!collection)
            g_warning("Cannot create item \"%s\": collection not specified",
                      label);
        else
          {
            item = secret_item_create_sync(collection, NULL, attributes, label,
                                secret, SECRET_ITEM_CREATE_NONE, NULL, &error);
            if (error)
              {
                g_warning("Could not create item \"%s\": %s",
                          label, error->message);
                g_clear_error(&error);
              }
            else free_item = TRUE;
          }
      }
    else if (item)
      {
        if (label)
            if (!secret_item_set_label_sync(item, label, NULL, &error))
              {
                g_warning("Couldn't change the label to \"%s\": %s",
                          label, error->message);
                g_clear_error(&error);
              }
        if (secret)
            if (!secret_item_set_secret_sync(item, secret, NULL, &error))
              {
                g_warning("Couldn't change the secret: %s", error->message);
                g_clear_error(&error);
              }
        if (attributes && g_hash_table_size(attributes) > 0)
            if (!secret_item_set_attributes_sync(item, NULL, attributes,
                                                 NULL, &error))
              {
                g_warning("Couldn't change attributes: %s", error->message);
                g_clear_error(&error);
              }
      }

    if (!item)
      {
        g_warning("Item not specified, skipping");
        return;
      }

    if (options.info)
      {
        SecretValue *secret = NULL;
        GHashTable *item_attrs;
        GHashTableIter iter;
        gboolean init_iter = FALSE;
        gpointer attr_name = NULL;
        gpointer attr_value = NULL;
        gchar *ctime = NULL;
        gchar *mtime = NULL;
        if (!info_parsed) info_parsed = parse_format(options.info);
        GList *elem = info_parsed;
        GList *format_A = NULL;
        do for (elem; elem; elem = elem->next)
          {
            struct format_parsed *parse = elem->data;
            const gchar UNKNOWN[] = "unknown";
            switch (parse->option)
              {
                case  0 :
                    break;
                case 'i':
                    print(g_dbus_proxy_get_object_path
                          (&item->parent_instance));
                    break;
                case 'l':
                    print(secret_item_get_label(item));
                    break;
                case 's':
                    if (!secret)
                      {
                        if (!secret_item_load_secret_sync(item, NULL, &error))
                          {
                            g_warning("Failed to load secret: %s",
                                      error->message);
                            g_clear_error(&error);
                          }
                        secret = secret_item_get_secret(item);
                      }
                    if (secret) print(secret_value_get_text(secret));
                    break;
                case 'A':
                    format_A = elem;
                    //FALLTHROUGH
                case 'a':
                    if (!init_iter)
                      {
                        item_attrs = secret_item_get_attributes(item);
                        g_hash_table_iter_init(&iter, item_attrs);
                        init_iter = TRUE;
                      }
                    if (!attr_name && !g_hash_table_iter_next(&iter,
                                                      &attr_name, &attr_value))
                        goto out;
                    print(attr_name);
                    attr_name = NULL;
                    break;
                case 'v':
                    if (!init_iter)
                      {
                        item_attrs = secret_item_get_attributes(item);
                        g_hash_table_iter_init(&iter, item_attrs);
                        init_iter = TRUE;
                      }
                    if (!attr_value && !g_hash_table_iter_next(&iter,
                                                      &attr_name, &attr_value))
                        goto out;
                    print(attr_value);
                    attr_value = NULL;
                    break;
                case 't':
                    if (!ctime) ctime = print_time(UNKNOWN,
                                                secret_item_get_created(item));
                    print(ctime);
                    break;
                case 'm':
                    if (!mtime) mtime = print_time(UNKNOWN,
                                               secret_item_get_modified(item));
                    print(mtime);
                    break;
                default:
                    g_warning("Unrecognized format specifier: %c",
                              parse->option);
                    break;
              }
            print(parse->delim);
          }
        while (elem = format_A);
        out:
        print("\n");
        if (secret) secret_value_unref(secret);
        if (init_iter) g_hash_table_unref(item_attrs);
        g_free(ctime);
        g_free(mtime);
      }
    if (options.move)
        if (!collection)
            g_warning("Cannot copy item: collection not specified");
        else
          {
            GHashTable *attributes = secret_item_get_attributes(item);
            gchar *label = secret_item_get_label(item);
            if (!secret_item_load_secret_sync(item, NULL, &error))
              {
                g_warning("Failed to load secret: %s", error->message);
                g_clear_error(&error);
              }
            SecretValue *secret = secret_item_get_secret(item);
            if (secret)
              {
                SecretItem *new_item = secret_item_create_sync(collection,
                                               NULL, attributes, label, secret,
                                     SECRET_ITEM_CREATE_REPLACE, NULL, &error);
                if (error)
                  {
                    g_warning("Couldn't move item: %s", error->message);
                    g_clear_error(&error);
                  }
                else g_object_unref(new_item);
                secret_value_unref(secret);
              }
            g_free(label);
            g_hash_table_unref(attributes);
          }
    if (options.delete)
        if (!secret_item_delete_sync(item, NULL, &error))
          {
            g_warning("Could not delete item: %s", error->message);
            g_clear_error(&error);
          }

    if (free_item) g_object_unref(item);
}

static const gchar UNLOCK_ABORT[] = "Collection unlock requested; aborting";

static GVariant *
prompt_sync_dummy(SecretService *foo, SecretPrompt *bar, GCancellable *baz,
                  const GVariantType *qux, GError **quux)
{
    g_critical(UNLOCK_ABORT);
    return NULL;
}

static void
prompt_async_dummy(SecretService *foo, SecretPrompt *bar,
                   const GVariantType *baz, GCancellable *qux,
                   GAsyncReadyCallback quux, gpointer corge)
{
    g_critical(UNLOCK_ABORT);
    return;
}

static GVariant *
prompt_finish_dummy(SecretService *foo, GAsyncResult *bar, GError **baz)
{
    g_critical(UNLOCK_ABORT);
    return NULL;
}

int
main(int argc, char *argv[])
{
    g_log_set_always_fatal(G_LOG_LEVEL_CRITICAL);
    GError *error = NULL;

    GOptionContext *opt_context = g_option_context_new(SUMMARY);
    g_option_context_add_main_entries(opt_context, opt_entries, NULL);
    g_option_context_set_description(opt_context, DESCRIPTION);
    if (!g_option_context_parse(opt_context, &argc, &argv, &error))
        g_critical("Option parse error: %s", error->message);
    g_option_context_free(opt_context);

    GHashTable *attributes = g_hash_table_new(&g_str_hash, &g_str_equal);
    int arg = 1;
    char *name = NULL;
    if (argc % 2 == 0) name = argv[arg++];
    for (arg; arg < argc; arg += 2)
        g_hash_table_insert(attributes, argv[arg], argv[arg+1]);

    SecretService *serv = secret_service_get_sync(SECRET_SERVICE_OPEN_SESSION
                              | SECRET_SERVICE_LOAD_COLLECTIONS, NULL, &error);
    if (error)
        g_critical("Error while obtaining service proxy: %s", error->message);
    if (options.no_auto_unlock)
      {
        SecretServiceClass *class = SECRET_SERVICE_GET_CLASS(serv);
        class->prompt_sync = &prompt_sync_dummy;
        class->prompt_async = &prompt_async_dummy;
        class->prompt_finish = &prompt_finish_dummy;
      }

    SecretCollection *collection = NULL;
    if (options.new_keyring)
      {
        collection = secret_collection_create_sync(serv, options.keyring,
                                               options.alias, 0, NULL, &error);
        if (error)
          {
            g_warning("Failed to create collection: %s", error->message);
            g_clear_error(&error);
          }
      }
    else if (options.alias)
      {
        collection = secret_collection_for_alias_sync(serv, options.alias,
                                   SECRET_COLLECTION_LOAD_ITEMS, NULL, &error);
        if (error)
          {
            g_warning("Could not find collection for alias \"%s\": %s",
                      options.alias, error->message);
            g_clear_error(&error);
          }
      }
    else if (options.keyring)
        collection = find_collection(serv, options.keyring);
    if ((!collection || options.move) && argc == 1 && (options.move
                                              || options.delete || options.info
                                   || options.secret || options.change_secret))
        // default action
        options.read = g_strdup("%i");
    GList *collections;
    if (collection) collections = g_list_append(NULL, collection);
    else collections = secret_service_get_collections(serv);

    SecretValue *secret = NULL;
    if (options.secret)
        secret = secret_value_new(options.secret, -1, TEXT_PLAIN);

    if (options.unlock)
      {
        secret_service_unlock_sync(serv, collections, NULL, NULL, &error);
        if (error)
          {
            g_warning("Couldn't unlock the collection(s): %s", error->message);
            g_clear_error(&error);
          }
      }

    if (options.show_keyring_info)
      {
        print("LABEL\tALIAS\tSTATE\tCTIME\t\t\tMTIME\n");
        for (GList *elem = collections; elem; elem = elem->next)
          {
            const char UNKNOWN[] = "unknown\t\t";
            const gchar *const aliases[] =
              {
                "session",
                "default",
                ""
              };
            SecretCollection *col = elem->data;
            gchar *ctime = print_time(UNKNOWN,
                                      secret_collection_get_created(col));
            gchar *mtime = print_time(UNKNOWN,
                                      secret_collection_get_modified(col));
            gchar *label = secret_collection_get_label(col);
            const gchar *alias_path =
                g_dbus_proxy_get_object_path(&col->parent);
            const gchar *const *alias;
            for (alias = aliases; **alias; alias++)
              {
                gchar *test_path =
                    secret_service_read_alias_dbus_path_sync(serv, *alias,
                                                             NULL, &error);
                if (error)
                  {
                    g_warning("Error while testing aliases: %s",
                              error->message);
                    g_clear_error(&error);
                  }
                if (test_path)
                  {
                    if (!g_strcmp0(alias_path, test_path))
                      {
                        g_free(test_path);
                        break;
                      }
                    g_free(test_path);
                  }
              }
            printf("%s\t%s\t%s\t%s\t%s\n", label, *alias,
                   secret_collection_get_locked(col) ? "locked" : "open",
                   ctime, mtime);
            g_free(ctime);
            g_free(mtime);
            g_free(label);
          }
      }

    if (options.read)
      {
        GList *format = parse_format(options.read);
        #define BIG_NUMBER 1024
        char buffer[BIG_NUMBER];
        for (char *line = fgets(buffer, sizeof buffer, stdin); line;
             line = fgets(buffer, sizeof buffer, stdin))
          {
            char *end = strchr(line, '\0') - 1;
            while (strchr("\r\n", *end)) *end-- = '\0';
            gchar *id = NULL;
            gchar *label = name;
            SecretValue *r_secret = secret;
            SecretCollection *r_col = collection;
            GHashTable *r_attrs = g_hash_table_new_full(&g_str_hash,
                                               &g_str_equal, &g_free, &g_free);
            g_hash_table_foreach(attributes, &ght_add, r_attrs);
            gchar *attribute = NULL;
            gchar *value = NULL;
            GList *format_A = NULL;
            GList *elem = format;
            do for (elem; elem; elem = elem->next)
              {
                struct format_parsed *parse = elem->data;
                if (parse->option)
                  {
                    char *rest = NULL;
                    if (*parse->delim)
                      {
                        rest = strstr(line, parse->delim);
                        if (!rest)
                            g_warning("Expected \"%s\" in input line,"
                                      " not found.", parse->delim);
                      }
                    gchar *token = rest ? g_strndup(line, rest - line)
                                        : g_strdup(line);
                    line = rest ? rest + strlen(parse->delim) : NULL;
                    switch (parse->option)
                      {
                        case 'i':
                            id = token;
                            break;
                        case 'c':
                            r_col = find_collection(serv, token);
                            break;
                        case 'C':
                            r_col = secret_collection_for_alias_sync(serv,
                                           token, SECRET_COLLECTION_LOAD_ITEMS,
                                                                 NULL, &error);
                            if (error)
                              {
                                g_warning("Couldn't find collection with"
                                          " alias \"%s\": %s", token,
                                          error->message);
                                g_clear_error(&error);
                              }
                            break;
                        case 'l':
                            label = token;
                            break;
                        case 's':
                            r_secret = secret_value_new(token, -1, TEXT_PLAIN);
                            g_free(token);
                            break;
                        case 'A':
                            format_A = elem;
                            //FALLTHROUGH
                        case 'a':
                            attribute = token;
                            if (value)
                              {
                                g_hash_table_insert(r_attrs, attribute, value);
                                attribute = value = NULL;
                              }
                            break;
                        case 'v':
                            value = token;
                            if (attribute)
                              {
                                g_hash_table_insert(r_attrs, attribute, value);
                                attribute = value = NULL;
                              }
                            break;
                        case '*':
                            g_free(token);
                            break;
                        default:
                            g_warning("Unrecognized format specifier: %c",
                                      parse->option);
                            g_free(token);
                            break;
                      }
                  }
                else
                    if (g_str_has_prefix(line, parse->delim))
                        line += strlen(parse->delim);
                    else g_warning("Expected \"%s\" on line start, not found.",
                                   parse->delim);
              }
            while (line && *line && (elem = format_A));
            SecretItem *item = NULL;
            if (id)
              {
                item = secret_item_new_for_dbus_path_sync(serv,
                                           id, SECRET_ITEM_NONE, NULL, &error);
                if (error)
                  {
                    g_warning("Failed to find item with ID \"%s\": %s", id,
                              error->message);
                    g_clear_error(&error);
                  }
              }
            g_free(id);
            process_item(item, r_col, label, r_attrs, r_secret);
            if (item) g_object_unref(item);
            if (label != name) g_free(label);
            if (r_secret != secret) secret_value_unref(r_secret);
            if (r_col != collection) g_object_unref(r_col);
            g_free(attribute);
            g_free(value);
            g_hash_table_unref(r_attrs);
          }
        g_list_free_full(format, &format_parsed_free);
      }
    else if (options.new)
        process_item(NULL, collection, name, attributes, secret);
    else
      {
        GList *item_list;
        if (collection && !options.move)
            item_list = secret_collection_search_sync(collection, NULL,
                                  attributes, SECRET_SEARCH_ALL, NULL, &error);
        else item_list = secret_service_search_sync(serv, NULL, attributes,
                                              SECRET_SEARCH_ALL, NULL, &error);
        if (error)
            g_critical("Failed to get matched items: %s", error->message);
        // basically: if we are supplied with specifiers,
        // but have got nothing to do with them
        if (!options.move && !options.delete && !options.info
            && !options.secret && !options.change_secret
            && (collection && !options.new_keyring && !options.delete_keyring
                && !options.unlock && !options.lock || argc > 1))
            // default action
            options.info = g_strdup("%i");
        for (GList *elem = item_list; elem; elem = elem->next)
          {
            SecretItem *item = elem->data;
            if (name && g_strcmp0(secret_item_get_label(item), name))
                continue;
            process_item(item, collection, NULL, NULL, secret);
          }
        g_list_free_full(item_list, &g_object_unref);
      }
    if (secret) secret_value_unref(secret);
    if (info_parsed) g_list_free_full(info_parsed, &format_parsed_free);

    if (options.delete_keyring)
        if (!secret_collection_delete_sync(collection, NULL, &error))
          {
            g_warning("Failed to delete collection(s): %s", error->message);
            g_clear_error(&error);
          }

    if (options.lock)
      {
        secret_service_lock_sync(serv, collections, NULL, NULL, &error);
        if (error)
          {
            g_warning("Error while locking collection(s): %s", error->message);
            g_clear_error(&error);
          }
      }

    g_list_free_full(collections, &g_object_unref);
    g_free(options.keyring);
    g_free(options.alias);
    g_free(options.read);
    g_free(options.info);
    g_free(options.secret);
    secret_service_disconnect();
}
