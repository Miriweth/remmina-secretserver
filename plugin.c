/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <curl/curl.h>
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <libsecret/secret.h>
#include <remmina/plugin.h>
#include <glib/gstdio.h>
#include <sodium.h>
#include <errno.h>
#include <string.h>
#include "token_store.h"

#define MAX_BODY (1024 * 1024)
#define BROWSER_TOKEN_SECONDS (15 * 60)
#define TOKEN_MAX_SECONDS 86400

static RemminaPluginService *service;
static gchar *browser_token;
static gchar *browser_token_url;
static gint64 browser_token_until;
static guint browser_token_timer;
static gchar *direct_token;
static gchar *direct_refresh_token;
static gchar *direct_token_url;
static gchar *direct_token_user;
static gint64 direct_token_until;
static gchar *cache_passphrase;
static gboolean cache_checked;
static gboolean cache_declined;

static const SecretSchema api_schema = {
    .name = "org.remmina.Delinea.ApiPassword",
    .flags = SECRET_SCHEMA_NONE,
    .attributes = { { "url", SECRET_SCHEMA_ATTRIBUTE_STRING },
                    { "user", SECRET_SCHEMA_ATTRIBUTE_STRING }, { NULL, 0 } }
};

typedef struct {
    gchar *group, *name, *host, *secret_id;
    gchar *username_slug, *password_slug, *domain_slug;
    gchar *profile_path;
} Connection;

static void connection_free(gpointer ptr)
{
    Connection *c = ptr;
    g_free(c->group); g_free(c->name); g_free(c->host); g_free(c->secret_id);
    g_free(c->username_slug); g_free(c->password_slug); g_free(c->domain_slug);
    g_free(c->profile_path);
    g_free(c);
}

static gchar *key_string(GKeyFile *key, const gchar *group, const gchar *field)
{
    gchar *s = g_key_file_get_string(key, group, field, NULL);
    if (s) g_strstrip(s);
    return s;
}

static gboolean required(const gchar *s)
{
    return s && *s;
}

static gboolean valid_secret_id(const gchar *id)
{
    if (!required(id)) return FALSE;
    for (const gchar *p = id; *p; p++)
        if (!g_ascii_isdigit(*p)) return FALSE;
    return TRUE;
}

static gboolean safe_header_value(const gchar *value)
{
    if (!required(value)) return FALSE;
    for (const gchar *p = value; *p; p++)
        if (!g_ascii_isgraph(*p)) return FALSE;
    return TRUE;
}

static gboolean valid_url(const gchar *url)
{
    GError *error = NULL;
    GUri *uri = g_uri_parse(url, G_URI_FLAGS_NONE, &error);
    gboolean ok = uri && g_strcmp0(g_uri_get_scheme(uri), "https") == 0 &&
        required(g_uri_get_host(uri)) && !g_uri_get_userinfo(uri) &&
        !g_uri_get_query(uri) && !g_uri_get_fragment(uri);
    if (uri) g_uri_unref(uri);
    g_clear_error(&error);
    return ok;
}

/* Reads [server] from config.ini. A missing auth key means browser sign-in. */
static gboolean load_config(gchar **out_url, gchar **out_user, gchar **out_version,
                            gchar **out_auth, gchar **out_mfa, GError **error)
{
    gchar *path = g_build_filename(g_get_user_config_dir(), "remmina-delinea", "config.ini", NULL);
    GKeyFile *key = g_key_file_new();
    if (!g_key_file_load_from_file(key, path, G_KEY_FILE_NONE, error)) {
        g_key_file_unref(key); g_free(path); return FALSE;
    }
    g_free(path);
    gchar *url = key_string(key, "server", "url");
    gchar *user = key_string(key, "server", "api_user");
    gchar *version = key_string(key, "server", "api_version");
    gchar *auth_mode = key_string(key, "server", "auth");
    gchar *mfa_mode = key_string(key, "server", "mfa");
    if (!version) version = g_strdup("v2");
    if (!auth_mode) auth_mode = g_strdup("browser-token");
    if (!valid_url(url) ||
        (g_strcmp0(auth_mode, "password") && g_strcmp0(auth_mode, "browser-token")) ||
        (g_strcmp0(auth_mode, "password") == 0 && !required(user)) ||
        (mfa_mode && g_strcmp0(mfa_mode, "none") && g_strcmp0(mfa_mode, "otp")) ||
        (g_strcmp0(auth_mode, "browser-token") == 0 && g_strcmp0(mfa_mode, "otp") == 0) ||
        (g_strcmp0(version, "v1") && g_strcmp0(version, "v2"))) {
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_INVAL,
                    "Check [server]: HTTPS URL, auth=password/browser-token, api_version=v1/v2, and api_user for direct login.");
        g_key_file_unref(key); g_free(url); g_free(user); g_free(version);
        g_free(auth_mode); g_free(mfa_mode); return FALSE;
    }
    g_key_file_unref(key);
    *out_url = url; *out_user = user; *out_version = version;
    *out_auth = auth_mode; *out_mfa = mfa_mode;
    return TRUE;
}

static void load_profiles(GPtrArray *connections, const gchar *dir)
{
    if (!required(dir)) return;
    GDir *files = g_dir_open(dir, 0, NULL);
    if (!files) return;
    const gchar *filename;
    while ((filename = g_dir_read_name(files))) {
        if (!g_str_has_suffix(filename, ".remmina")) continue;
        gchar *path = g_build_filename(dir, filename, NULL);
        GKeyFile *profile = g_key_file_new();
        gboolean loaded = g_key_file_load_from_file(profile, path, G_KEY_FILE_NONE, NULL);
        gchar *protocol = loaded ? key_string(profile, "remmina", "protocol") : NULL;
        if (!loaded || g_strcmp0(protocol, "DelineaRDP")) {
            g_free(protocol);
            g_key_file_unref(profile); g_free(path); continue;
        }
        g_free(protocol);
        Connection *c = g_new0(Connection, 1);
        c->profile_path = path;
        c->group = key_string(profile, "remmina", "group");
        if (!required(c->group)) { g_free(c->group); c->group = g_strdup("RDP"); }
        c->name = key_string(profile, "remmina", "name");
        c->host = key_string(profile, "remmina", "server");
        c->secret_id = key_string(profile, "remmina", "delinea_secret_id");
        c->username_slug = key_string(profile, "remmina", "delinea_username_slug");
        c->password_slug = key_string(profile, "remmina", "delinea_password_slug");
        c->domain_slug = key_string(profile, "remmina", "delinea_domain_slug");
        if (!required(c->username_slug)) { g_free(c->username_slug); c->username_slug = g_strdup("username"); }
        if (!required(c->password_slug)) { g_free(c->password_slug); c->password_slug = g_strdup("password"); }
        if (!required(c->domain_slug)) { g_free(c->domain_slug); c->domain_slug = g_strdup("domain"); }
        if (!required(c->name) || !required(c->host)) connection_free(c);
        else g_ptr_array_add(connections, c);
        g_key_file_unref(profile);
    }
    g_dir_close(files);
}

static gint compare_profiles(gconstpointer a, gconstpointer b)
{
    const Connection *x = *(Connection *const *)a;
    const Connection *y = *(Connection *const *)b;
    gint result = g_utf8_collate(x->group, y->group);
    return result ? result : g_utf8_collate(x->name, y->name);
}

/* Profiles that Check secret can test, sorted by group and name. */
static GPtrArray *checkable_profiles(const gchar *dir)
{
    GPtrArray *profiles = g_ptr_array_new_with_free_func(connection_free);
    load_profiles(profiles, dir);
    for (guint i = profiles->len; i > 0; i--) {
        Connection *c = g_ptr_array_index(profiles, i - 1);
        if (!valid_secret_id(c->secret_id)) g_ptr_array_remove_index(profiles, i - 1);
    }
    g_ptr_array_sort(profiles, compare_profiles);
    return profiles;
}

static size_t write_body(char *data, size_t size, size_t nmemb, void *user)
{
    GString *buffer = user;
    size_t n = size * nmemb;
    if (n > MAX_BODY || buffer->len > MAX_BODY - n) return 0;
    g_string_append_len(buffer, data, n);
    return n;
}

/* HTTP status errors use the status as the error code. */
#define DELINEA_HTTP_ERROR (delinea_http_error_quark())
static G_DEFINE_QUARK(delinea-http-error-quark, delinea_http_error)

static void set_http_error(GError **error, long status)
{
    g_set_error(error, DELINEA_HTTP_ERROR, (gint)status, "Secret Server returned HTTP %ld.", status);
}

static GString *request(const gchar *url, const gchar *post, const gchar *token,
                        const gchar *otp, GError **error)
{
    if ((token && !safe_header_value(token)) || (otp && !safe_header_value(otp))) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                            "Invalid token or MFA code.");
        return NULL;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Could not initialize libcurl.");
        return NULL;
    }
    GString *body = g_string_new(NULL);
    struct curl_slist *headers = NULL;
    gchar *auth = token ? g_strdup_printf("Authorization: Bearer %s", token) : NULL;
    gchar *otp_header = otp ? g_strdup_printf("OTP: %s", otp) : NULL;
    if (auth) headers = curl_slist_append(headers, auth);
    if (otp_header) headers = curl_slist_append(headers, otp_header);
    if (post) headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (post) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
    CURLcode result = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (result != CURLE_OK)
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Secret Server connection: %s", curl_easy_strerror(result));
    else if (status != 200)
        set_http_error(error, status);
    curl_slist_free_all(headers);
    if (auth) {
        volatile gchar *p = (volatile gchar *)auth;
        for (gsize n = strlen(auth); n; n--) *p++ = 0;
    }
    g_free(auth);
    if (otp_header) {
        volatile gchar *p = (volatile gchar *)otp_header;
        for (gsize n = strlen(otp_header); n; n--) *p++ = 0;
    }
    g_free(otp_header);
    curl_easy_cleanup(curl);
    if (*error) { g_string_free(body, TRUE); return NULL; }
    return body;
}

/* Tests replace this to simulate Secret Server. */
static GString *(*http_request)(const gchar *url, const gchar *post, const gchar *token,
                                const gchar *otp, GError **error) = request;

static JsonObject *parse_object(GString *body, JsonParser **out_parser, GError **error)
{
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, body->str, body->len, error)) {
        g_object_unref(parser); return NULL;
    }
    JsonNode *root = json_parser_get_root(parser);
    if (!JSON_NODE_HOLDS_OBJECT(root)) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Secret Server did not return a JSON object.");
        g_object_unref(parser); return NULL;
    }
    *out_parser = parser;
    return json_node_get_object(root);
}

static gchar *item_value(JsonObject *secret, const gchar *slug)
{
    if (!required(slug) || !json_object_has_member(secret, "items")) return NULL;
    if (!JSON_NODE_HOLDS_ARRAY(json_object_get_member(secret, "items"))) return NULL;
    JsonArray *items = json_object_get_array_member(secret, "items");
    if (!items) return NULL;
    for (guint i = 0; i < json_array_get_length(items); i++) {
        JsonObject *item = json_array_get_object_element(items, i);
        if (item && g_strcmp0(json_object_get_string_member_with_default(item, "slug", NULL), slug) == 0)
            return g_strdup(json_object_get_string_member_with_default(item, "itemValue", NULL));
    }
    return NULL;
}

static gchar *item_slug_summary(JsonObject *secret)
{
    if (!json_object_has_member(secret, "items") ||
        !JSON_NODE_HOLDS_ARRAY(json_object_get_member(secret, "items")))
        return g_strdup("no items in API response");
    JsonArray *items = json_object_get_array_member(secret, "items");
    GString *summary = g_string_new(NULL);
    for (guint i = 0; i < json_array_get_length(items) && i < 30; i++) {
        JsonObject *item = json_array_get_object_element(items, i);
        if (!item) continue;
        const gchar *slug = json_object_get_string_member_with_default(item, "slug", NULL);
        if (!required(slug)) continue;
        gchar *safe_slug = g_strndup(slug, 64);
        for (gchar *p = safe_slug; *p; p++)
            if (!g_ascii_isalnum(*p) && *p != '_' && *p != '-' && *p != '.') *p = '?';
        const gchar *value = json_object_get_string_member_with_default(item, "itemValue", NULL);
        if (summary->len) g_string_append(summary, ", ");
        g_string_append_printf(summary, "%s (%s)", safe_slug,
                               required(value) ? "set" : "empty");
        g_free(safe_slug);
    }
    if (!summary->len) g_string_append(summary, "no slugs returned");
    return g_string_free(summary, FALSE);
}

static void wipe(gchar *s)
{
    if (!s) return;
    volatile gchar *p = (volatile gchar *)s;
    for (gsize n = strlen(s); n; n--) *p++ = 0;
    g_free(s);
}

static void clear_browser_token(void)
{
    if (browser_token_timer) {
        g_source_remove(browser_token_timer);
        browser_token_timer = 0;
    }
    wipe(browser_token);
    browser_token = NULL;
    g_clear_pointer(&browser_token_url, g_free);
    browser_token_until = 0;
}

static void clear_direct_token(void)
{
    wipe(direct_token);
    wipe(direct_refresh_token);
    direct_token = direct_refresh_token = NULL;
    g_clear_pointer(&direct_token_url, g_free);
    g_clear_pointer(&direct_token_user, g_free);
    direct_token_until = 0;
}

static gboolean expire_browser_token(gpointer data)
{
    (void)data;
    browser_token_timer = 0;
    clear_browser_token();
    return G_SOURCE_REMOVE;
}

static void wipe_response(GString *s)
{
    if (!s) return;
    volatile gchar *p = (volatile gchar *)s->str;
    for (gsize n = s->len; n; n--) *p++ = 0;
    g_string_free(s, TRUE);
}

static gboolean fetch_credentials(const gchar *url, const gchar *version, const gchar *token,
                                  Connection *c,
                                  gchar **rdp_user, gchar **rdp_password, gchar **rdp_domain,
                                  GError **error)
{
    gchar *base = g_strdup(url);
    while (base[strlen(base) - 1] == '/') base[strlen(base) - 1] = 0;
    gchar *secret_url = g_strdup_printf("%s/api/%s/secrets/%s", base, version, c->secret_id);
    g_free(base);
    GString *response = http_request(secret_url, NULL, token, NULL, error);
    g_free(secret_url);
    if (!response) return FALSE;
    JsonParser *parser = NULL;
    JsonObject *obj = parse_object(response, &parser, error);
    gchar *slugs = obj ? item_slug_summary(obj) : NULL;
    if (obj) {
        *rdp_user = item_value(obj, c->username_slug);
        *rdp_password = item_value(obj, c->password_slug);
        *rdp_domain = item_value(obj, c->domain_slug);
    }
    if (parser) g_object_unref(parser);
    wipe_response(response);
    if (!*error && (!required(*rdp_user) || !required(*rdp_password)))
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "Secret %s: username or password missing. API fields: %s",
                    c->secret_id, slugs ? slugs : "unknown");
    g_free(slugs);
    return !*error;
}

static void message_dialog(GtkWindow *parent, GtkMessageType type, const gchar *text)
{
    GtkWidget *dialog = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL, type, GTK_BUTTONS_CLOSE, "%s", text);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Tests replace the dialog functions with scripted answers. */
static void (*message)(GtkWindow *parent, GtkMessageType type, const gchar *text) = message_dialog;

static gchar *api_password_dialog(GtkWindow *parent, const gchar *url, const gchar *user)
{
    GError *error = NULL;
    gchar *password = secret_password_lookup_sync(&api_schema, NULL, &error,
                                                  "url", url, "user", user, NULL);
    /* A desktop without Secret Service can still connect by prompting each time. */
    g_clear_error(&error);
    if (password) return password;
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Secret Server API login", parent,
                                                     GTK_DIALOG_MODAL, "Cancel", GTK_RESPONSE_CANCEL,
                                                     "Continue", GTK_RESPONSE_OK, NULL);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *label = gtk_label_new("Secret Server API password:");
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *remember = gtk_check_button_new_with_label("Save in the desktop keyring");
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(box), remember, FALSE, FALSE, 8);
    gtk_widget_show_all(dialog);
    gchar *result = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK && required(gtk_entry_get_text(GTK_ENTRY(entry)))) {
        result = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(remember))) {
            GError *save_error = NULL;
            secret_password_store_sync(&api_schema, SECRET_COLLECTION_DEFAULT,
                                       "Remmina Delinea Secret Server API", result, NULL, &save_error,
                                       "url", url, "user", user, NULL);
            if (save_error) { message(parent, GTK_MESSAGE_ERROR, save_error->message); g_error_free(save_error); }
        }
    }
    gtk_widget_destroy(dialog);
    return result;
}

static gchar *otp_dialog(GtkWindow *parent)
{
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Secret Server MFA", parent,
                                                     GTK_DIALOG_MODAL, "Cancel", GTK_RESPONSE_CANCEL,
                                                     "Continue", GTK_RESPONSE_OK, NULL);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *label = gtk_label_new("One-time code from your authenticator:");
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_input_purpose(GTK_ENTRY(entry), GTK_INPUT_PURPOSE_DIGITS);
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 8);
    gtk_widget_show_all(dialog);
    gchar *otp = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK && required(gtk_entry_get_text(GTK_ENTRY(entry))))
        otp = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
    gtk_widget_destroy(dialog);
    return otp;
}

static gchar *(*api_password_prompt)(GtkWindow *parent, const gchar *url,
                                     const gchar *user) = api_password_dialog;
static gchar *(*otp_prompt)(GtkWindow *parent) = otp_dialog;

static gint64 token_lifetime(JsonObject *obj)
{
    JsonNode *node = json_object_get_member(obj, "expires_in");
    gint64 seconds = 900;
    if (node && JSON_NODE_HOLDS_VALUE(node)) {
        GType type = json_node_get_value_type(node);
        if (type == G_TYPE_STRING) {
            const gchar *value = json_node_get_string(node);
            if (required(value)) seconds = g_ascii_strtoll(value, NULL, 10);
        } else if (type == G_TYPE_INT64 || type == G_TYPE_INT || type == G_TYPE_DOUBLE) {
            seconds = json_node_get_int(node);
        }
    }
    return CLAMP(seconds - 60, 1, TOKEN_MAX_SECONDS);
}

static gboolean set_direct_token(GString *response, const gchar *url, const gchar *user, GError **error)
{
    JsonParser *parser = NULL;
    JsonObject *obj = parse_object(response, &parser, error);
    gchar *access = obj ? g_strdup(json_object_get_string_member_with_default(obj, "access_token", NULL)) : NULL;
    gchar *refresh = obj ? g_strdup(json_object_get_string_member_with_default(obj, "refresh_token", NULL)) : NULL;
    gint64 lifetime = obj ? token_lifetime(obj) : 0;
    if (parser) g_object_unref(parser);
    if (!required(access)) {
        if (!*error) g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                         "Secret Server did not return an access_token.");
        wipe(access); wipe(refresh); return FALSE;
    }
    clear_direct_token();
    direct_token = access;
    direct_refresh_token = refresh;
    direct_token_url = g_strdup(url);
    direct_token_user = g_strdup(user);
    direct_token_until = g_get_monotonic_time() + lifetime * G_USEC_PER_SEC;
    return TRUE;
}

/* Converts a monotonic deadline to wall-clock seconds for the cache file. */
static gint64 token_expiry_epoch(gint64 until)
{
    gint64 remaining = MAX((gint64)0, until - g_get_monotonic_time());
    return g_get_real_time() / G_USEC_PER_SEC + remaining / G_USEC_PER_SEC;
}

static gboolean token_cache_store(const gchar *path, const gchar *passphrase,
                                  const gchar *auth_mode, const gchar *url,
                                  const gchar *user, GError **error)
{
    gboolean browser = g_strcmp0(auth_mode, "browser-token") == 0;
    const gchar *access = browser ? browser_token : direct_token;
    if (!required(access)) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                            "There is no API token to save.");
        return FALSE;
    }
    GKeyFile *key = g_key_file_new();
    g_key_file_set_string(key, "token", "auth", browser ? "browser-token" : "password");
    g_key_file_set_string(key, "token", "url", url);
    g_key_file_set_string(key, "token", "user", browser || !user ? "" : user);
    g_key_file_set_string(key, "token", "access", access);
    if (!browser && required(direct_refresh_token))
        g_key_file_set_string(key, "token", "refresh", direct_refresh_token);
    g_key_file_set_int64(key, "token", "expires_at",
                         token_expiry_epoch(browser ? browser_token_until : direct_token_until));
    gsize length = 0;
    gchar *plain = g_key_file_to_data(key, &length, NULL);
    g_key_file_unref(key);
    gchar *dir = g_path_get_dirname(path);
    gboolean ok = FALSE;
    if (g_mkdir_with_parents(dir, 0700) != 0 || g_chmod(dir, 0700) != 0) {
        int saved_errno = errno;
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(saved_errno),
                    "Could not create %s: %s", dir, g_strerror(saved_errno));
    } else {
        ok = token_store_write(path, passphrase, plain, length, error);
    }
    sodium_memzero(plain, length);
    g_free(plain);
    g_free(dir);
    return ok;
}

/* Restores the token saved for these settings. Returns FALSE without an
   error when the file belongs to other settings or the token has expired. */
static gboolean token_cache_restore(const gchar *path, const gchar *passphrase,
                                    const gchar *auth_mode, const gchar *url,
                                    const gchar *user, GError **error)
{
    gboolean browser = g_strcmp0(auth_mode, "browser-token") == 0;
    gsize length = 0;
    gchar *plain = token_store_read(path, passphrase, &length, error);
    if (!plain) return FALSE;
    GKeyFile *key = g_key_file_new();
    gboolean parsed = g_key_file_load_from_data(key, plain, length, G_KEY_FILE_NONE, NULL);
    sodium_memzero(plain, length);
    g_free(plain);
    gchar *saved_mode = g_key_file_get_string(key, "token", "auth", NULL);
    gchar *saved_url = g_key_file_get_string(key, "token", "url", NULL);
    gchar *saved_user = g_key_file_get_string(key, "token", "user", NULL);
    gchar *access = g_key_file_get_string(key, "token", "access", NULL);
    gchar *refresh = g_key_file_get_string(key, "token", "refresh", NULL);
    GError *number_error = NULL;
    gint64 expires_at = g_key_file_get_int64(key, "token", "expires_at", &number_error);
    g_key_file_unref(key);
    /* Clamp before subtracting so a bad value cannot overflow. */
    gint64 now = g_get_real_time() / G_USEC_PER_SEC;
    gint64 remaining = CLAMP(expires_at, now - 1, now + TOKEN_MAX_SECONDS) - now;
    gboolean valid = parsed && saved_mode && saved_url && saved_user &&
                     safe_header_value(access) && !number_error;
    if (!valid)
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                            "The token cache contains invalid data.");
    g_clear_error(&number_error);
    gboolean matches = valid && g_strcmp0(saved_mode, auth_mode) == 0 &&
                       g_strcmp0(saved_url, url) == 0 &&
                       (browser || g_strcmp0(saved_user, user) == 0);
    gboolean restored = FALSE;
    if (matches && browser && remaining > 0) {
        remaining = MIN(remaining, BROWSER_TOKEN_SECONDS);
        clear_browser_token();
        browser_token = access;
        access = NULL;
        browser_token_url = g_strdup(url);
        browser_token_until = g_get_monotonic_time() + remaining * G_USEC_PER_SEC;
        browser_token_timer = g_timeout_add_seconds((guint)remaining, expire_browser_token, NULL);
        restored = TRUE;
    } else if (matches && !browser && (remaining > 0 || required(refresh))) {
        /* An expired access token is refreshed on first use. */
        remaining = MAX(remaining, 0);
        clear_direct_token();
        direct_token = access;
        access = NULL;
        if (required(refresh)) {
            direct_refresh_token = refresh;
            refresh = NULL;
        }
        direct_token_url = g_strdup(url);
        direct_token_user = g_strdup(user);
        direct_token_until = g_get_monotonic_time() + remaining * G_USEC_PER_SEC;
        restored = TRUE;
    }
    g_free(saved_mode);
    g_free(saved_url);
    g_free(saved_user);
    wipe(access);
    wipe(refresh);
    return restored;
}

/* The token file is on unless config.ini sets save_tokens=false. */
static gboolean token_cache_enabled(void)
{
    gchar *path = g_build_filename(g_get_user_config_dir(), "remmina-delinea", "config.ini", NULL);
    GKeyFile *key = g_key_file_new();
    gboolean enabled = TRUE;
    if (g_key_file_load_from_file(key, path, G_KEY_FILE_NONE, NULL)) {
        GError *error = NULL;
        gboolean value = g_key_file_get_boolean(key, "server", "save_tokens", &error);
        if (!error) enabled = value;
        g_clear_error(&error);
    }
    g_key_file_unref(key);
    g_free(path);
    return enabled;
}

static gchar *token_cache_path(void)
{
    return g_build_filename(g_get_user_config_dir(), "remmina-delinea", "tokens.enc", NULL);
}

static void token_cache_delete(void)
{
    gchar *path = token_cache_path();
    g_unlink(path);
    g_free(path);
}

static gchar *cache_passphrase_dialog(GtkWindow *parent, gboolean create)
{
    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        create ? "Save Secret Server token" : "Unlock saved Secret Server token",
        parent, GTK_DIALOG_MODAL, "Cancel", GTK_RESPONSE_CANCEL,
        create ? "Save" : "Unlock", GTK_RESPONSE_OK, NULL);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *label = gtk_label_new(create
        ? "Keep the Secret Server token in an encrypted file?\n"
          "Choose a passphrase of at least 12 characters. It is not written to disk.\n"
          "Cancel keeps the token in memory until Remmina closes. To stop this question,\n"
          "turn off \"Save tokens in an encrypted file\" in Preferences \u2192 Delinea."
        : "Enter the passphrase for the saved token.\n"
          "Cancel keeps tokens in memory until Remmina closes.");
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *confirm = create ? gtk_entry_new() : NULL;
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 8);
    if (confirm) {
        gtk_entry_set_visibility(GTK_ENTRY(confirm), FALSE);
        gtk_entry_set_placeholder_text(GTK_ENTRY(confirm), "Repeat passphrase");
        gtk_entry_set_activates_default(GTK_ENTRY(confirm), TRUE);
        gtk_box_pack_start(GTK_BOX(box), confirm, FALSE, FALSE, 8);
    }
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
    gtk_widget_show_all(dialog);
    gchar *result = NULL;
    while (!result && gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
        const gchar *value = gtk_entry_get_text(GTK_ENTRY(entry));
        if (!create && required(value))
            result = g_strdup(value);
        else if (create && g_utf8_strlen(value, -1) >= 12 &&
                 g_strcmp0(value, gtk_entry_get_text(GTK_ENTRY(confirm))) == 0)
            result = g_strdup(value);
        else if (create)
            message(GTK_WINDOW(dialog), GTK_MESSAGE_ERROR,
                    "Enter the same passphrase twice, at least 12 characters.");
    }
    gtk_widget_destroy(dialog);
    return result;
}

static gchar *(*cache_passphrase_prompt)(GtkWindow *parent, gboolean create) = cache_passphrase_dialog;

/* Cancel on either passphrase prompt keeps tokens in memory for the rest
   of the Remmina session. */
static void save_token_cache(GtkWindow *parent, const gchar *auth_mode,
                             const gchar *url, const gchar *user)
{
    if (cache_declined || !token_cache_enabled()) return;
    if (!cache_passphrase) cache_passphrase = cache_passphrase_prompt(parent, TRUE);
    if (!cache_passphrase) {
        cache_declined = TRUE;
        return;
    }
    gchar *path = token_cache_path();
    GError *error = NULL;
    if (!token_cache_store(path, cache_passphrase, auth_mode, url, user, &error)) {
        message(parent, GTK_MESSAGE_ERROR, error->message);
        g_clear_error(&error);
    }
    g_free(path);
}

/* Runs once per Remmina session, before the first token is needed. After
   three wrong passphrases or a damaged file, the next save asks for a new
   passphrase and replaces the file. */
static void load_token_cache(GtkWindow *parent, const gchar *auth_mode,
                             const gchar *url, const gchar *user)
{
    if (cache_checked) return;
    cache_checked = TRUE;
    if (!token_cache_enabled()) {
        token_cache_delete();
        return;
    }
    gchar *path = token_cache_path();
    for (guint attempt = 0; attempt < 3 && g_file_test(path, G_FILE_TEST_EXISTS); attempt++) {
        if (!cache_passphrase) cache_passphrase = cache_passphrase_prompt(parent, FALSE);
        if (!cache_passphrase) {
            cache_declined = TRUE;
            break;
        }
        GError *error = NULL;
        token_cache_restore(path, cache_passphrase, auth_mode, url, user, &error);
        if (!error) break;
        wipe(cache_passphrase);
        cache_passphrase = NULL;
        message(parent, GTK_MESSAGE_ERROR, error->message);
        gboolean wrong_passphrase = g_error_matches(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED);
        g_clear_error(&error);
        if (!wrong_passphrase) break;
    }
    g_free(path);
}

static const gchar *direct_token_get(GtkWindow *parent, const gchar *url,
                                     const gchar *user, const gchar *mfa)
{
    if (g_strcmp0(url, direct_token_url) || g_strcmp0(user, direct_token_user))
        clear_direct_token();
    if (direct_token && g_get_monotonic_time() < direct_token_until)
        return direct_token;

    gchar *base = g_strdup(url);
    while (base[strlen(base) - 1] == '/') base[strlen(base) - 1] = 0;
    gchar *token_url = g_strdup_printf("%s/oauth2/token", base);
    g_free(base);
    if (required(direct_refresh_token)) {
        CURL *curl = curl_easy_init();
        gchar *escaped = curl ? curl_easy_escape(curl, direct_refresh_token, 0) : NULL;
        gchar *post = escaped ? g_strdup_printf("grant_type=refresh_token&refresh_token=%s", escaped) : NULL;
        if (escaped) curl_free(escaped);
        if (curl) curl_easy_cleanup(curl);
        if (post) {
            /* Without a new refresh token in the answer, the old one stays valid. */
            gchar *old_refresh = g_strdup(direct_refresh_token);
            GError *refresh_error = NULL;
            GString *response = http_request(token_url, post, NULL, NULL, &refresh_error);
            if (response) {
                if (set_direct_token(response, url, user, &refresh_error) &&
                    !required(direct_refresh_token)) {
                    wipe(direct_refresh_token);
                    direct_refresh_token = old_refresh;
                    old_refresh = NULL;
                }
                wipe_response(response);
            }
            wipe(old_refresh);
            wipe(post);
            g_clear_error(&refresh_error);
            if (direct_token && g_get_monotonic_time() < direct_token_until) {
                g_free(token_url);
                save_token_cache(parent, "password", url, user);
                return direct_token;
            }
        }
        clear_direct_token();
    }

    clear_direct_token();
    gchar *password = api_password_prompt(parent, url, user);
    if (!password) { g_free(token_url); return NULL; }
    gchar *otp = g_strcmp0(mfa, "otp") == 0 ? otp_prompt(parent) : NULL;
    if (g_strcmp0(mfa, "otp") == 0 && !otp) {
        wipe(password); g_free(token_url); return NULL;
    }
    CURL *curl = curl_easy_init();
    gchar *eu = curl ? curl_easy_escape(curl, user, 0) : NULL;
    gchar *ep = curl ? curl_easy_escape(curl, password, 0) : NULL;
    gchar *post = eu && ep ? g_strdup_printf("grant_type=password&username=%s&password=%s", eu, ep) : NULL;
    if (eu) curl_free(eu);
    if (ep) curl_free(ep);
    if (curl) curl_easy_cleanup(curl);
    wipe(password);
    if (!post) {
        message(parent, GTK_MESSAGE_ERROR, "Could not initialize libcurl.");
        wipe(otp); g_free(token_url); return NULL;
    }
    GError *error = NULL;
    GString *response = http_request(token_url, post, NULL, otp, &error);
    wipe(post); wipe(otp); g_free(token_url);
    if (response) {
        if (set_direct_token(response, url, user, &error))
            save_token_cache(parent, "password", url, user);
        wipe_response(response);
    }
    if (error) {
        message(parent, GTK_MESSAGE_ERROR, error->message);
        g_clear_error(&error);
    }
    return direct_token;
}

/* Returns the pasted API token, or NULL after Cancel. */
static gchar *browser_token_dialog(GtkWindow *parent, const gchar *url)
{
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Secret Server browser login", parent,
                                                     GTK_DIALOG_MODAL,
                                                     "Cancel", GTK_RESPONSE_CANCEL,
                                                     "Open Secret Server", 101,
                                                     "Use API token", GTK_RESPONSE_OK, NULL);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *label = gtk_label_new("Sign in through ADFS/MFA in your browser. Under User Preferences,\n"
                                      "generate an API token and paste it here:");
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 8);
    gtk_widget_show_all(dialog);
    gint response;
    while ((response = gtk_dialog_run(GTK_DIALOG(dialog))) == 101) {
        GError *error = NULL;
        if (!gtk_show_uri_on_window(parent, url, GDK_CURRENT_TIME, &error)) {
            message(parent, GTK_MESSAGE_ERROR, error->message);
            g_clear_error(&error);
        }
    }
    gchar *token = NULL;
    if (response == GTK_RESPONSE_OK && required(gtk_entry_get_text(GTK_ENTRY(entry))))
        token = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
    gtk_widget_destroy(dialog);
    return token;
}

static gchar *(*browser_token_prompt)(GtkWindow *parent, const gchar *url) = browser_token_dialog;

static const gchar *browser_token_get(GtkWindow *parent, const gchar *url)
{
    if (browser_token && g_strcmp0(url, browser_token_url) == 0 &&
        g_get_monotonic_time() < browser_token_until)
        return browser_token;
    clear_browser_token();
    gchar *token = browser_token_prompt(parent, url);
    if (!token) return NULL;
    g_strstrip(token);
    if (!safe_header_value(token)) {
        wipe(token);
        message(parent, GTK_MESSAGE_ERROR, "The API token contains invalid characters.");
        return NULL;
    }
    browser_token = token;
    browser_token_url = g_strdup(url);
    browser_token_until = g_get_monotonic_time() + BROWSER_TOKEN_SECONDS * G_USEC_PER_SEC;
    browser_token_timer = g_timeout_add_seconds(BROWSER_TOKEN_SECONDS, expire_browser_token, NULL);
    save_token_cache(parent, "browser-token", url, NULL);
    return browser_token;
}

static gboolean retrieve_with_auth(GtkWindow *parent, const gchar *url, const gchar *user,
                                   const gchar *version, const gchar *auth_mode, const gchar *mfa,
                                   Connection *c, gchar **rdp_user, gchar **rdp_password,
                                   gchar **rdp_domain, GError **error)
{
    gboolean browser = g_strcmp0(auth_mode, "browser-token") == 0;
    load_token_cache(parent, auth_mode, url, user);
    for (guint attempt = 0; attempt < 2; attempt++) {
        const gchar *token = browser ? browser_token_get(parent, url)
                                     : direct_token_get(parent, url, user, mfa);
        if (!token) return FALSE;
        if (fetch_credentials(url, version, token, c,
                              rdp_user, rdp_password, rdp_domain, error)) return TRUE;
        if (!g_error_matches(*error, DELINEA_HTTP_ERROR, 401)) return FALSE;
        /* Secret Server rejected the token: drop it from memory and disk.
           A direct login keeps its refresh token for the second attempt. */
        token_cache_delete();
        if (browser) clear_browser_token();
        else if (attempt == 0) direct_token_until = 0;
        else clear_direct_token();
        if (attempt == 1) return FALSE;
        g_clear_error(error);
    }
    return FALSE;
}

static void launch_connection(GtkWindow *parent, const gchar *url, const gchar *user,
                              const gchar *version, const gchar *auth_mode, const gchar *mfa,
                              Connection *c)
{
    gchar *rdp_user = NULL, *rdp_password = NULL, *rdp_domain = NULL;
    GError *error = NULL;
    if (!retrieve_with_auth(parent, url, user, version, auth_mode, mfa, c,
                            &rdp_user, &rdp_password, &rdp_domain, &error)) {
        if (error) { message(parent, GTK_MESSAGE_ERROR, error->message); g_error_free(error); }
    } else {
        RemminaFile *file = service->file_new();
        if (c->profile_path) {
            GKeyFile *profile = g_key_file_new();
            if (g_key_file_load_from_file(profile, c->profile_path, G_KEY_FILE_NONE, NULL)) {
                gsize count = 0;
                gchar **keys = g_key_file_get_keys(profile, "remmina", &count, NULL);
                for (gsize i = 0; i < count; i++) {
                    if (g_str_has_prefix(keys[i], "delinea_") ||
                        strstr(keys[i], "password") || strstr(keys[i], "passphrase")) continue;
                    gchar *value = g_key_file_get_string(profile, "remmina", keys[i], NULL);
                    if (value) service->file_set_string(file, keys[i], value);
                    g_free(value);
                }
                g_strfreev(keys);
            }
            g_key_file_unref(profile);
        }
        service->file_set_string(file, "name", c->name);
        service->file_set_string(file, "group", "Delinea Jump Hosts");
        service->file_set_string(file, "protocol", "RDP");
        service->file_set_string(file, "server", c->host);
        service->file_set_string(file, "username", rdp_user);
        service->file_set_string(file, "password", rdp_password);
        if (required(rdp_domain)) service->file_set_string(file, "domain", rdp_domain);
        service->open_connection(file, NULL, NULL, NULL);
    }
    wipe(rdp_password); g_free(rdp_user); g_free(rdp_domain);
}

static void check_secret(GtkWindow *parent, const gchar *url, const gchar *user,
                         const gchar *version, const gchar *auth_mode,
                         const gchar *mfa, Connection *c)
{
    gchar *rdp_user = NULL, *rdp_password = NULL, *rdp_domain = NULL;
    GError *error = NULL;
    gboolean fetched = retrieve_with_auth(parent, url, user, version, auth_mode, mfa, c,
                                           &rdp_user, &rdp_password, &rdp_domain, &error);
    if (!fetched && !error) return;
    if (error && !g_error_matches(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA) &&
        !rdp_user && !rdp_password) {
        message(parent, GTK_MESSAGE_ERROR, error->message);
    } else {
        gchar *status = g_strdup_printf("Secret %s\nUsername: %s\nPassword: %s\nDomain: %s%s%s",
                                        c->secret_id,
                                        required(rdp_user) ? rdp_user : "missing",
                                        required(rdp_password) ? "present" : "missing",
                                        required(rdp_domain) ? rdp_domain : "not set",
                                        error ? "\nError: " : "",
                                        error ? error->message : "");
        message(parent, error ? GTK_MESSAGE_WARNING : GTK_MESSAGE_INFO, status);
        g_free(status);
    }
    g_clear_error(&error);
    g_free(rdp_user); wipe(rdp_password); g_free(rdp_domain);
}

static gboolean save_key_file_private(GKeyFile *key, const gchar *path, GError **error)
{
    if (g_file_test(path, G_FILE_TEST_EXISTS) && g_chmod(path, 0600) != 0) {
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                    "Could not set private permissions on %s: %s", path, g_strerror(errno));
        return FALSE;
    }
    gsize length = 0;
    gchar *data = g_key_file_to_data(key, &length, error);
    if (!data) return FALSE;
    gboolean saved = g_file_set_contents_full(path, data, length,
                                               G_FILE_SET_CONTENTS_CONSISTENT,
                                               0600, error);
    g_free(data);
    if (saved && g_chmod(path, 0600) != 0) {
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                    "Could not set private permissions on %s: %s", path, g_strerror(errno));
        return FALSE;
    }
    return saved;
}

/* A saved token belongs to one server URL, login mode and API user. */
static gboolean login_settings_changed(GKeyFile *key, const gchar *url,
                                       gboolean direct, const gchar *user)
{
    gchar *old_url = key_string(key, "server", "url");
    gchar *old_auth = key_string(key, "server", "auth");
    gchar *old_user = key_string(key, "server", "api_user");
    gboolean was_direct = g_strcmp0(old_auth, "password") == 0;
    gboolean changed = g_strcmp0(old_url, url) != 0 || was_direct != direct ||
                       (direct && g_strcmp0(old_user, user) != 0);
    g_free(old_url);
    g_free(old_auth);
    g_free(old_user);
    return changed;
}

/* Writes the Delinea settings. Saving a different login, or turning the
   token file off, removes the saved tokens. */
static gboolean save_settings(const gchar *url, gboolean direct, const gchar *user,
                              gboolean otp, gboolean save_tokens, GError **error)
{
    if (!valid_url(url) || (direct && !required(user))) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                            "Enter an HTTPS Secret Server URL and, for direct API login, an API username.");
        return FALSE;
    }
    gchar *dir = g_build_filename(g_get_user_config_dir(), "remmina-delinea", NULL);
    gchar *path = g_build_filename(dir, "config.ini", NULL);
    GKeyFile *key = g_key_file_new();
    gboolean saved = FALSE;
    if (g_file_test(path, G_FILE_TEST_EXISTS) &&
        !g_key_file_load_from_file(key, path, G_KEY_FILE_NONE, error)) {
        /* error is set */
    } else if (g_mkdir_with_parents(dir, 0700) != 0) {
        int saved_errno = errno;
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(saved_errno),
                    "Could not create %s: %s", dir, g_strerror(saved_errno));
    } else {
        gboolean changed = login_settings_changed(key, url, direct, user);
        g_key_file_set_string(key, "server", "url", url);
        g_key_file_set_string(key, "server", "api_version", "v2");
        g_key_file_set_string(key, "server", "auth", direct ? "password" : "browser-token");
        g_key_file_set_string(key, "server", "mfa", direct && otp ? "otp" : "none");
        if (required(user)) g_key_file_set_string(key, "server", "api_user", user);
        else g_key_file_remove_key(key, "server", "api_user", NULL);
        g_key_file_set_boolean(key, "server", "save_tokens", save_tokens);
        saved = save_key_file_private(key, path, error);
        if (saved && changed) {
            clear_browser_token();
            clear_direct_token();
        }
        if (saved && (changed || !save_tokens)) token_cache_delete();
        if (saved && !save_tokens) {
            wipe(cache_passphrase);
            cache_passphrase = NULL;
        }
    }
    g_key_file_unref(key);
    g_free(path);
    g_free(dir);
    return saved;
}

typedef struct {
    GtkWidget *url, *auth, *user, *otp, *save_tokens, *profile;
    GPtrArray *profiles;
} DelineaPreferences;

static void preferences_free(gpointer data)
{
    DelineaPreferences *preferences = data;
    g_ptr_array_unref(preferences->profiles);
    g_free(preferences);
}

/* Reads the selected profile's Secret with the saved settings, without RDP. */
static void preferences_check(GtkButton *button, gpointer data)
{
    DelineaPreferences *preferences = data;
    GtkWidget *toplevel = gtk_widget_get_toplevel(GTK_WIDGET(button));
    GtkWindow *parent = gtk_widget_is_toplevel(toplevel) ? GTK_WINDOW(toplevel) : NULL;
    gint index = gtk_combo_box_get_active(GTK_COMBO_BOX(preferences->profile));
    if (index < 0 || (guint)index >= preferences->profiles->len) return;
    GError *error = NULL;
    gchar *url = NULL, *user = NULL, *version = NULL, *auth_mode = NULL, *mfa = NULL;
    if (!load_config(&url, &user, &version, &auth_mode, &mfa, &error)) {
        message(parent, GTK_MESSAGE_ERROR, error->message);
        g_error_free(error);
        return;
    }
    check_secret(parent, url, user, version, auth_mode, mfa,
                 g_ptr_array_index(preferences->profiles, index));
    g_free(url); g_free(user); g_free(version); g_free(auth_mode); g_free(mfa);
}

static void preferences_auth_changed(GtkComboBox *box, gpointer data)
{
    DelineaPreferences *preferences = data;
    gboolean direct = gtk_combo_box_get_active(box) == 1;
    gtk_widget_set_sensitive(preferences->user, direct);
    gtk_widget_set_sensitive(preferences->otp, direct);
}

static void preferences_save(GtkButton *button, gpointer data)
{
    (void)button;
    DelineaPreferences *preferences = data;
    gchar *url = g_strdup(gtk_entry_get_text(GTK_ENTRY(preferences->url)));
    gchar *user = g_strdup(gtk_entry_get_text(GTK_ENTRY(preferences->user)));
    g_strstrip(url); g_strstrip(user);
    GError *error = NULL;
    if (save_settings(url, gtk_combo_box_get_active(GTK_COMBO_BOX(preferences->auth)) == 1, user,
                      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(preferences->otp)),
                      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(preferences->save_tokens)),
                      &error)) {
        message(NULL, GTK_MESSAGE_INFO, "Delinea settings saved.");
    } else {
        message(NULL, GTK_MESSAGE_ERROR, error->message);
        g_clear_error(&error);
    }
    g_free(url); g_free(user);
}

static GtkWidget *preferences_body(RemminaPrefPlugin *plugin)
{
    (void)plugin;
    GKeyFile *key = g_key_file_new();
    gchar *path = g_build_filename(g_get_user_config_dir(), "remmina-delinea", "config.ini", NULL);
    g_key_file_load_from_file(key, path, G_KEY_FILE_NONE, NULL);
    g_free(path);
    gchar *url = key_string(key, "server", "url");
    gchar *auth = key_string(key, "server", "auth");
    gchar *user = key_string(key, "server", "api_user");
    gchar *mfa = key_string(key, "server", "mfa");
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 16);
    DelineaPreferences *preferences = g_new0(DelineaPreferences, 1);
    gchar *profiles_dir = service->file_get_user_datadir();
    preferences->profiles = checkable_profiles(profiles_dir);
    g_free(profiles_dir);
    g_object_set_data_full(G_OBJECT(grid), "delinea-preferences", preferences, preferences_free);
    GtkWidget *label = gtk_label_new("Secret Server URL");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 1, 1);
    preferences->url = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(preferences->url), "https://secretserver.example.org");
    gtk_entry_set_text(GTK_ENTRY(preferences->url), url ? url : "");
    gtk_widget_set_hexpand(preferences->url, TRUE);
    gtk_grid_attach(GTK_GRID(grid), preferences->url, 1, 0, 1, 1);
    label = gtk_label_new("Authentication");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 0, 1, 1, 1);
    preferences->auth = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(preferences->auth), "Browser sign-in + API token");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(preferences->auth), "Direct API login");
    gtk_combo_box_set_active(GTK_COMBO_BOX(preferences->auth), g_strcmp0(auth, "password") == 0 ? 1 : 0);
    gtk_grid_attach(GTK_GRID(grid), preferences->auth, 1, 1, 1, 1);
    label = gtk_label_new("API username");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 0, 2, 1, 1);
    preferences->user = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(preferences->user), user ? user : "");
    gtk_grid_attach(GTK_GRID(grid), preferences->user, 1, 2, 1, 1);
    preferences->otp = gtk_check_button_new_with_label("Ask for an OTP on direct login");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(preferences->otp), g_strcmp0(mfa, "otp") == 0);
    gtk_grid_attach(GTK_GRID(grid), preferences->otp, 1, 3, 1, 1);
    preferences->save_tokens = gtk_check_button_new_with_label("Save tokens in an encrypted file");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(preferences->save_tokens), token_cache_enabled());
    gtk_widget_set_tooltip_text(preferences->save_tokens,
                                "Keeps the Secret Server token in ~/.config/remmina-delinea/tokens.enc, "
                                "encrypted with a passphrase. Turning this off deletes the file.");
    gtk_grid_attach(GTK_GRID(grid), preferences->save_tokens, 1, 4, 1, 1);
    GtkWidget *save = gtk_button_new_with_label("Save Delinea settings");
    gtk_widget_set_halign(save, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), save, 1, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), 0, 6, 2, 1);
    label = gtk_label_new("Test profile");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 0, 7, 1, 1);
    preferences->profile = gtk_combo_box_text_new();
    for (guint i = 0; i < preferences->profiles->len; i++) {
        Connection *c = g_ptr_array_index(preferences->profiles, i);
        gchar *text = g_strdup_printf("%s / %s (%s)", c->group, c->name, c->host);
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(preferences->profile), text);
        g_free(text);
    }
    gtk_grid_attach(GTK_GRID(grid), preferences->profile, 1, 7, 1, 1);
    GtkWidget *check = gtk_button_new_with_label("Check secret");
    gtk_widget_set_halign(check, GTK_ALIGN_START);
    gtk_widget_set_tooltip_text(check, "Reads the Secret with the saved settings. RDP is not started.");
    gtk_grid_attach(GTK_GRID(grid), check, 1, 8, 1, 1);
    if (preferences->profiles->len) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(preferences->profile), 0);
    } else {
        gtk_widget_set_sensitive(preferences->profile, FALSE);
        gtk_widget_set_sensitive(check, FALSE);
        gtk_widget_set_tooltip_text(preferences->profile,
                                    "Create a Delinea RDP profile with a Secret Server ID first.");
    }
    g_signal_connect(preferences->auth, "changed", G_CALLBACK(preferences_auth_changed), preferences);
    g_signal_connect(save, "clicked", G_CALLBACK(preferences_save), preferences);
    g_signal_connect(check, "clicked", G_CALLBACK(preferences_check), preferences);
    preferences_auth_changed(GTK_COMBO_BOX(preferences->auth), preferences);
    g_free(url); g_free(auth); g_free(user); g_free(mfa); g_key_file_unref(key);
    gtk_widget_show_all(grid);
    return grid;
}

static RemminaPrefPlugin delinea_preferences = {
    REMMINA_PLUGIN_TYPE_PREF, "DelineaSettings", "Secret Server settings",
    NULL, "0.4.0", "Delinea", preferences_body
};

static const RemminaProtocolSetting delinea_basic_settings[] = {
    { REMMINA_PROTOCOL_SETTING_TYPE_SERVER, "server", NULL, FALSE, NULL, NULL, NULL, NULL },
    { REMMINA_PROTOCOL_SETTING_TYPE_TEXT, "delinea_secret_id", "Secret Server ID", FALSE, NULL, NULL, NULL, NULL },
    { REMMINA_PROTOCOL_SETTING_TYPE_END, NULL, NULL, FALSE, NULL, NULL, NULL, NULL }
};

static const RemminaProtocolSetting delinea_advanced_settings[] = {
    { REMMINA_PROTOCOL_SETTING_TYPE_TEXT, "delinea_username_slug", "Username field (slug)", FALSE, NULL, NULL, NULL, NULL },
    { REMMINA_PROTOCOL_SETTING_TYPE_TEXT, "delinea_password_slug", "Password field (slug)", FALSE, NULL, NULL, NULL, NULL },
    { REMMINA_PROTOCOL_SETTING_TYPE_TEXT, "delinea_domain_slug", "Domain field (slug)", FALSE, NULL, NULL, NULL, NULL },
    { REMMINA_PROTOCOL_SETTING_TYPE_END, NULL, NULL, FALSE, NULL, NULL, NULL, NULL }
};

static void delinea_protocol_init(RemminaProtocolWidget *gp)
{
    (void)gp;
}

static gboolean delinea_protocol_close(RemminaProtocolWidget *gp)
{
    service->protocol_plugin_signal_connection_closed(gp);
    return TRUE;
}

static gboolean delinea_protocol_open(RemminaProtocolWidget *gp)
{
    RemminaFile *source = service->protocol_plugin_get_file(gp);
    Connection c = { 0 };
    c.name = (gchar *)service->file_get_string(source, "name");
    c.group = (gchar *)service->file_get_string(source, "group");
    c.host = (gchar *)service->file_get_string(source, "server");
    c.secret_id = (gchar *)service->file_get_string(source, "delinea_secret_id");
    c.username_slug = (gchar *)service->file_get_string(source, "delinea_username_slug");
    c.password_slug = (gchar *)service->file_get_string(source, "delinea_password_slug");
    c.domain_slug = (gchar *)service->file_get_string(source, "delinea_domain_slug");
    c.profile_path = (gchar *)service->file_get_path(source);
    if (!required(c.name)) c.name = c.host;
    if (!required(c.username_slug)) c.username_slug = "username";
    if (!required(c.password_slug)) c.password_slug = "password";
    if (!required(c.domain_slug)) c.domain_slug = "domain";
    if (!required(c.host) || g_str_has_suffix(c.host, ".invalid") ||
        !valid_secret_id(c.secret_id)) {
        message(NULL, GTK_MESSAGE_ERROR,
                "Set the jump host and a numeric Secret Server ID in this profile.");
        service->protocol_plugin_signal_connection_closed(gp);
        return TRUE;
    }

    GError *error = NULL;
    gchar *url = NULL, *user = NULL, *version = NULL, *auth_mode = NULL, *mfa = NULL;
    if (!load_config(&url, &user, &version, &auth_mode, &mfa, &error)) {
        message(NULL, GTK_MESSAGE_ERROR, error->message);
        g_error_free(error);
        service->protocol_plugin_signal_connection_closed(gp);
        return TRUE;
    }
    launch_connection(NULL, url, user, version, auth_mode, mfa, &c);
    g_free(url); g_free(user); g_free(version); g_free(auth_mode); g_free(mfa);
    service->protocol_plugin_signal_connection_closed(gp);
    return TRUE;
}

static RemminaProtocolPlugin delinea_protocol = {
    .type = REMMINA_PLUGIN_TYPE_PROTOCOL,
    .name = "DelineaRDP",
    .description = "Delinea RDP - Secret Server",
    .version = "0.4.0",
    .icon_name = "org.remmina.Remmina-rdp-symbolic",
    .icon_name_ssh = "org.remmina.Remmina-rdp-ssh-symbolic",
    .basic_settings = delinea_basic_settings,
    .advanced_settings = delinea_advanced_settings,
    .ssh_setting = REMMINA_PROTOCOL_SSH_SETTING_NONE,
    .init = delinea_protocol_init,
    .open_connection = delinea_protocol_open,
    .close_connection = delinea_protocol_close
};

G_MODULE_EXPORT gboolean remmina_plugin_entry(RemminaPluginService *api)
{
    service = api;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return FALSE;
    return api->register_plugin((RemminaPlugin *)&delinea_preferences) &&
           api->register_plugin((RemminaPlugin *)&delinea_protocol);
}
