#include <glib/gstdio.h>
#include "../plugin.c"

/* main() points XDG_CONFIG_HOME at a temporary directory. */
static void test_configuration(void)
{
    GError *error = NULL;
    gchar *dir = g_build_filename(g_get_user_config_dir(), "remmina-delinea", NULL);
    gchar *path = g_build_filename(dir, "config.ini", NULL);
    g_assert_cmpint(g_mkdir_with_parents(dir, 0700), ==, 0);
    gchar *sample = NULL;
    g_assert_true(g_file_get_contents("config.ini.example", &sample, NULL, &error));
    g_assert_no_error(error);
    g_assert_true(g_file_set_contents(path, sample, -1, &error));
    g_assert_no_error(error);
    gchar *url = NULL, *user = NULL, *version = NULL, *auth = NULL, *mfa = NULL;
    g_assert_true(load_config(&url, &user, &version, &auth, &mfa, &error));
    g_assert_no_error(error);
    g_assert_null(user);
    g_assert_cmpstr(version, ==, "v2");
    g_assert_cmpstr(auth, ==, "browser-token");
    g_assert_true(valid_url(url));
    g_assert_false(valid_url("http://example.org"));
    g_assert_true(valid_secret_id("1001"));
    g_assert_false(valid_secret_id("1001x"));
    g_assert_true(safe_header_value("ey.a-b_c.123"));
    g_assert_false(safe_header_value("abc\r\nInjected: bad"));
    g_free(url); g_free(user); g_free(version); g_free(auth); g_free(mfa); g_free(sample);
    const gchar *direct = "[server]\nurl=https://secretserver.example.org\n"
                          "auth=password\napi_user=remmina-api\nmfa=otp\napi_version=v2\n";
    g_assert_true(g_file_set_contents(path, direct, -1, &error));
    g_assert_no_error(error);
    g_assert_true(load_config(&url, &user, &version, &auth, &mfa, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(user, ==, "remmina-api");
    g_assert_cmpstr(version, ==, "v2");
    g_assert_cmpstr(auth, ==, "password");
    g_assert_cmpstr(mfa, ==, "otp");
    g_free(url); g_free(user); g_free(version); g_free(auth); g_free(mfa);
    g_unlink(path);
    GKeyFile *key = g_key_file_new();
    g_key_file_set_string(key, "server", "url", "https://secretserver.example.org");
    g_key_file_set_string(key, "server", "auth", "browser-token");
    g_assert_true(save_key_file_private(key, path, &error));
    g_assert_no_error(error);
    GStatBuf statbuf;
    g_assert_cmpint(g_stat(path, &statbuf), ==, 0);
    g_assert_cmpint(statbuf.st_mode & 0777, ==, 0600);
    g_assert_cmpstr(delinea_preferences.pref_label, ==, "Delinea");
    g_key_file_unref(key);
    g_unlink(path); g_rmdir(dir);
    g_free(path); g_free(dir);
}

/* Sections left by the removed Jump Hosts dialog must not block connections. */
static void test_configuration_ignores_old_connections(void)
{
    GError *error = NULL;
    gchar *dir = g_build_filename(g_get_user_config_dir(), "remmina-delinea", NULL);
    gchar *path = g_build_filename(dir, "config.ini", NULL);
    g_assert_cmpint(g_mkdir_with_parents(dir, 0700), ==, 0);
    g_assert_true(g_file_set_contents(path, "[server]\nurl=https://secretserver.example.org\n"
                                            "[connection old]\ntier=Tier 0\nsecret_id=12x\n",
                                      -1, &error));
    g_assert_no_error(error);
    gchar *url = NULL, *user = NULL, *version = NULL, *auth = NULL, *mfa = NULL;
    g_assert_true(load_config(&url, &user, &version, &auth, &mfa, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(auth, ==, "browser-token");
    g_free(url); g_free(user); g_free(version); g_free(auth); g_free(mfa);
    g_unlink(path); g_rmdir(dir);
    g_free(path); g_free(dir);
}

static void test_profiles(void)
{
    GError *error = NULL;
    gchar *dir = g_dir_make_tmp("remmina-profiles-test-XXXXXX", &error);
    g_assert_no_error(error);
    gchar *path = g_build_filename(dir, "tier0.remmina", NULL);
    const gchar *contents = "[remmina]\nprotocol=DelineaRDP\nname=Tier 0 Jump\n"
                            "group=Tier 0\nserver=jump-t0.example.org\n"
                            "delinea_username_slug=\ndelinea_password_slug=\ndelinea_domain_slug=\n";
    g_assert_true(g_file_set_contents(path, contents, -1, &error));
    g_assert_no_error(error);
    GPtrArray *connections = g_ptr_array_new_with_free_func(connection_free);
    load_profiles(connections, dir);
    g_assert_cmpuint(connections->len, ==, 1);
    Connection *c = g_ptr_array_index(connections, 0);
    g_assert_cmpstr(c->group, ==, "Tier 0");
    g_assert_cmpstr(c->host, ==, "jump-t0.example.org");
    g_assert_null(c->secret_id);
    g_assert_cmpstr(c->username_slug, ==, "username");
    g_assert_cmpstr(c->password_slug, ==, "password");
    g_assert_cmpstr(c->domain_slug, ==, "domain");
    g_assert_cmpstr(delinea_protocol.name, ==, "DelineaRDP");
    g_assert_cmpstr(delinea_protocol.basic_settings[1].name, ==, "delinea_secret_id");
    GKeyFile *profile = g_key_file_new();
    g_assert_true(g_key_file_load_from_file(profile, path, G_KEY_FILE_NONE, &error));
    g_assert_no_error(error);
    g_key_file_set_string(profile, "remmina", "delinea_secret_id", "1001");
    g_assert_true(save_key_file_private(profile, path, &error));
    g_assert_no_error(error);
    GStatBuf statbuf;
    g_assert_cmpint(g_stat(path, &statbuf), ==, 0);
    g_assert_cmpint(statbuf.st_mode & 0777, ==, 0600);
    g_key_file_unref(profile);
    g_ptr_array_set_size(connections, 0);
    load_profiles(connections, dir);
    g_assert_cmpuint(connections->len, ==, 1);
    c = g_ptr_array_index(connections, 0);
    g_assert_cmpstr(c->secret_id, ==, "1001");
    g_ptr_array_unref(connections);
    g_unlink(path); g_rmdir(dir); g_free(path); g_free(dir);
}

static void test_secret_fields(void)
{
    const gchar *json = "{\"items\":[{\"slug\":\"username\",\"itemValue\":\"Admin\\\\T0\"},"
                        "{\"slug\":\"password\",\"itemValue\":\"secret\"}]}";
    GString *data = g_string_new(json);
    GError *error = NULL;
    JsonParser *parser = NULL;
    JsonObject *object = parse_object(data, &parser, &error);
    g_assert_no_error(error);
    g_assert_nonnull(object);
    gchar *user = item_value(object, "username");
    gchar *password = item_value(object, "password");
    g_assert_cmpstr(user, ==, "Admin\\T0");
    g_assert_cmpstr(password, ==, "secret");
    g_assert_null(item_value(object, "missing"));
    gchar *summary = item_slug_summary(object);
    g_assert_nonnull(strstr(summary, "username (set)"));
    g_assert_nonnull(strstr(summary, "password (set)"));
    g_assert_null(strstr(summary, "secret"));
    g_free(summary);
    g_free(user); wipe(password);
    g_object_unref(parser); g_string_free(data, TRUE);
}

static void test_token_lifetime(void)
{
    JsonParser *parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, "{\"expires_in\":\"1200\"}", -1, NULL));
    g_assert_cmpint(token_lifetime(json_node_get_object(json_parser_get_root(parser))), ==, 1140);
    g_assert_true(json_parser_load_from_data(parser, "{\"expires_in\":30}", -1, NULL));
    g_assert_cmpint(token_lifetime(json_node_get_object(json_parser_get_root(parser))), ==, 1);
    g_object_unref(parser);
}

static void test_token_rotation(void)
{
    GError *error = NULL;
    GString *response = g_string_new("{\"access_token\":\"first\",\"refresh_token\":\"rotate-me\",\"expires_in\":1200}");
    g_assert_true(set_direct_token(response, "https://secretserver.example.org", "api-user", &error));
    g_assert_no_error(error);
    g_assert_cmpstr(direct_token, ==, "first");
    g_assert_cmpstr(direct_refresh_token, ==, "rotate-me");
    wipe_response(response);
    response = g_string_new("{\"access_token\":\"second\",\"refresh_token\":\"new-refresh\",\"expires_in\":1200}");
    g_assert_true(set_direct_token(response, "https://secretserver.example.org", "api-user", &error));
    g_assert_no_error(error);
    g_assert_cmpstr(direct_token, ==, "second");
    g_assert_cmpstr(direct_refresh_token, ==, "new-refresh");
    wipe_response(response);
    clear_direct_token();
    g_assert_null(direct_token);
    g_assert_null(direct_refresh_token);
}

#define TEST_URL "https://secretserver.example.org/SecretServer"
#define TEST_PASSPHRASE "correct horse battery"

static gchar *cache_file(void)
{
    return g_build_filename(g_get_user_config_dir(), "remmina-delinea", "tokens.enc", NULL);
}

static void reset_tokens(void)
{
    clear_browser_token();
    clear_direct_token();
    gchar *path = cache_file();
    g_unlink(path);
    g_free(path);
}

static void use_browser_token(const gchar *token, gint64 seconds)
{
    clear_browser_token();
    browser_token = g_strdup(token);
    browser_token_url = g_strdup(TEST_URL);
    browser_token_until = g_get_monotonic_time() + seconds * G_USEC_PER_SEC;
}

static gint64 seconds_left(gint64 until)
{
    return (until - g_get_monotonic_time()) / G_USEC_PER_SEC;
}

static void test_cache_browser_round_trip(void)
{
    reset_tokens();
    gchar *path = cache_file();
    GError *error = NULL;
    use_browser_token("browser-token-1", 600);
    g_assert_true(token_cache_store(path, TEST_PASSPHRASE, "browser-token", TEST_URL, NULL, &error));
    g_assert_no_error(error);
    clear_browser_token();
    g_assert_true(token_cache_restore(path, TEST_PASSPHRASE, "browser-token", TEST_URL, NULL, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(browser_token, ==, "browser-token-1");
    g_assert_cmpstr(browser_token_url, ==, TEST_URL);
    g_assert_cmpint(seconds_left(browser_token_until), >=, 590);
    g_assert_cmpint(seconds_left(browser_token_until), <=, 600);
    g_assert_cmpuint(browser_token_timer, !=, 0);
    reset_tokens();
    g_free(path);
}

/* Writes a cache file with hand-written contents, as another version or a
   clock change could leave it. */
static void write_cache_payload(const gchar *payload)
{
    gchar *path = cache_file();
    gchar *dir = g_path_get_dirname(path);
    GError *error = NULL;
    g_assert_cmpint(g_mkdir_with_parents(dir, 0700), ==, 0);
    g_assert_true(token_store_write(path, TEST_PASSPHRASE, payload, strlen(payload), &error));
    g_assert_no_error(error);
    g_free(dir);
    g_free(path);
}

static void write_browser_payload(gint64 expires_in)
{
    gchar *payload = g_strdup_printf("[token]\nauth=browser-token\nurl=" TEST_URL "\nuser=\n"
                                     "access=browser-token-2\nexpires_at=%" G_GINT64_FORMAT "\n",
                                     g_get_real_time() / G_USEC_PER_SEC + expires_in);
    write_cache_payload(payload);
    g_free(payload);
}

static void test_cache_browser_at_most_15_minutes(void)
{
    reset_tokens();
    write_browser_payload(86400);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_true(token_cache_restore(path, TEST_PASSPHRASE, "browser-token", TEST_URL, NULL, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(browser_token, ==, "browser-token-2");
    g_assert_cmpint(seconds_left(browser_token_until), <=, 900);
    g_assert_cmpint(seconds_left(browser_token_until), >=, 890);
    reset_tokens();
    g_free(path);
}

static void test_cache_browser_expired(void)
{
    reset_tokens();
    write_browser_payload(-5);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_false(token_cache_restore(path, TEST_PASSPHRASE, "browser-token", TEST_URL, NULL, &error));
    g_assert_no_error(error);
    g_assert_null(browser_token);
    g_assert_cmpuint(browser_token_timer, ==, 0);
    /* expires_at - now must not overflow into a valid-looking time. */
    write_cache_payload("[token]\nauth=browser-token\nurl=" TEST_URL "\nuser=\n"
                        "access=browser-token-2\nexpires_at=-9223372036854775808\n");
    g_assert_false(token_cache_restore(path, TEST_PASSPHRASE, "browser-token", TEST_URL, NULL, &error));
    g_assert_no_error(error);
    g_assert_null(browser_token);
    reset_tokens();
    g_free(path);
}

/* A token saved for one server or login mode must never reach another. */
static void test_cache_other_settings(void)
{
    reset_tokens();
    write_browser_payload(600);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_false(token_cache_restore(path, TEST_PASSPHRASE, "browser-token",
                                       "https://other.example.org/SecretServer", NULL, &error));
    g_assert_no_error(error);
    g_assert_null(browser_token);
    g_assert_false(token_cache_restore(path, TEST_PASSPHRASE, "password", TEST_URL,
                                       "remmina-api", &error));
    g_assert_no_error(error);
    g_assert_null(browser_token);
    g_assert_null(direct_token);
    reset_tokens();
    g_free(path);
}

/* Preferences keep api_user when switching to browser sign-in. */
static void test_cache_browser_ignores_api_user(void)
{
    reset_tokens();
    write_browser_payload(600);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_true(token_cache_restore(path, TEST_PASSPHRASE, "browser-token", TEST_URL,
                                      "remmina-api", &error));
    g_assert_no_error(error);
    g_assert_cmpstr(browser_token, ==, "browser-token-2");
    reset_tokens();
    g_free(path);
}

static void use_direct_token(const gchar *access, const gchar *refresh, gint64 seconds)
{
    clear_direct_token();
    direct_token = g_strdup(access);
    direct_refresh_token = g_strdup(refresh);
    direct_token_url = g_strdup(TEST_URL);
    direct_token_user = g_strdup("remmina-api");
    direct_token_until = g_get_monotonic_time() + seconds * G_USEC_PER_SEC;
}

static void write_direct_payload(const gchar *refresh_line, gint64 expires_in)
{
    gchar *payload = g_strdup_printf("[token]\nauth=password\nurl=" TEST_URL "\nuser=remmina-api\n"
                                     "access=direct-access-2\n%sexpires_at=%" G_GINT64_FORMAT "\n",
                                     refresh_line, g_get_real_time() / G_USEC_PER_SEC + expires_in);
    write_cache_payload(payload);
    g_free(payload);
}

static void test_cache_direct_round_trip(void)
{
    reset_tokens();
    gchar *path = cache_file();
    GError *error = NULL;
    use_direct_token("direct-access-1", "direct-refresh-1", 3600);
    g_assert_true(token_cache_store(path, TEST_PASSPHRASE, "password", TEST_URL, "remmina-api", &error));
    g_assert_no_error(error);
    clear_direct_token();
    g_assert_true(token_cache_restore(path, TEST_PASSPHRASE, "password", TEST_URL, "remmina-api", &error));
    g_assert_no_error(error);
    g_assert_cmpstr(direct_token, ==, "direct-access-1");
    g_assert_cmpstr(direct_refresh_token, ==, "direct-refresh-1");
    g_assert_cmpstr(direct_token_url, ==, TEST_URL);
    g_assert_cmpstr(direct_token_user, ==, "remmina-api");
    g_assert_cmpint(seconds_left(direct_token_until), >=, 3590);
    g_assert_cmpint(seconds_left(direct_token_until), <=, 3600);
    g_assert_null(browser_token);
    reset_tokens();
    g_free(path);
}

/* An expired access token is still worth restoring for its refresh token. */
static void test_cache_direct_expired(void)
{
    reset_tokens();
    write_direct_payload("refresh=direct-refresh-2\n", -60);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_true(token_cache_restore(path, TEST_PASSPHRASE, "password", TEST_URL, "remmina-api", &error));
    g_assert_no_error(error);
    g_assert_cmpstr(direct_refresh_token, ==, "direct-refresh-2");
    g_assert_cmpint(seconds_left(direct_token_until), <=, 0);
    reset_tokens();
    write_direct_payload("", -60);
    g_assert_false(token_cache_restore(path, TEST_PASSPHRASE, "password", TEST_URL, "remmina-api", &error));
    g_assert_no_error(error);
    g_assert_null(direct_token);
    reset_tokens();
    g_free(path);
}

static void test_cache_direct_at_most_one_day(void)
{
    reset_tokens();
    write_direct_payload("refresh=direct-refresh-2\n", 30 * 86400);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_true(token_cache_restore(path, TEST_PASSPHRASE, "password", TEST_URL, "remmina-api", &error));
    g_assert_no_error(error);
    g_assert_cmpint(seconds_left(direct_token_until), <=, 86400);
    g_assert_cmpint(seconds_left(direct_token_until), >=, 86390);
    reset_tokens();
    g_free(path);
}

static void test_cache_direct_other_user(void)
{
    reset_tokens();
    write_direct_payload("refresh=direct-refresh-2\n", 600);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_false(token_cache_restore(path, TEST_PASSPHRASE, "password", TEST_URL, "other-api", &error));
    g_assert_no_error(error);
    g_assert_null(direct_token);
    g_assert_null(direct_refresh_token);
    reset_tokens();
    g_free(path);
}

static void test_cache_wrong_passphrase(void)
{
    reset_tokens();
    write_browser_payload(600);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_false(token_cache_restore(path, "not the passphrase", "browser-token", TEST_URL, NULL, &error));
    g_assert_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED);
    g_clear_error(&error);
    g_assert_null(browser_token);
    g_assert_true(g_file_test(path, G_FILE_TEST_EXISTS));
    reset_tokens();
    g_free(path);
}

static void check_invalid_payload(const gchar *payload)
{
    reset_tokens();
    write_cache_payload(payload);
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_false(token_cache_restore(path, TEST_PASSPHRASE, "browser-token", TEST_URL, NULL, &error));
    g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
    g_clear_error(&error);
    g_assert_null(browser_token);
    reset_tokens();
    g_free(path);
}

static void test_cache_invalid_payload(void)
{
    gint64 later = g_get_real_time() / G_USEC_PER_SEC + 600;
    check_invalid_payload("not a key file");
    const gchar *bad_tokens[] = { "has space", "line\\r\\nX-Injected: 1", "" };
    for (guint i = 0; i < G_N_ELEMENTS(bad_tokens); i++) {
        gchar *payload = g_strdup_printf("[token]\nauth=browser-token\nurl=" TEST_URL "\nuser=\n"
                                         "access=%s\nexpires_at=%" G_GINT64_FORMAT "\n",
                                         bad_tokens[i], later);
        check_invalid_payload(payload);
        g_free(payload);
    }
    check_invalid_payload("[token]\nauth=browser-token\nurl=" TEST_URL "\nuser=\naccess=browser-token-2\n");
    check_invalid_payload("[token]\nauth=browser-token\nurl=" TEST_URL "\nuser=\naccess=browser-token-2\n"
                          "expires_at=soon\n");
}

static void test_cache_private_directory(void)
{
    reset_tokens();
    gchar *path = cache_file();
    gchar *dir = g_path_get_dirname(path);
    GError *error = NULL;
    g_assert_cmpint(g_mkdir_with_parents(dir, 0755), ==, 0);
    g_assert_cmpint(g_chmod(dir, 0755), ==, 0);
    use_browser_token("browser-token-1", 600);
    g_assert_true(token_cache_store(path, TEST_PASSPHRASE, "browser-token", TEST_URL, NULL, &error));
    g_assert_no_error(error);
    GStatBuf statbuf;
    g_assert_cmpint(g_stat(dir, &statbuf), ==, 0);
    g_assert_cmpint(statbuf.st_mode & 0777, ==, 0700);
    g_assert_cmpint(g_stat(path, &statbuf), ==, 0);
    g_assert_cmpint(statbuf.st_mode & 0777, ==, 0600);
    reset_tokens();
    g_free(dir);
    g_free(path);
}

static void test_cache_needs_token(void)
{
    reset_tokens();
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_false(token_cache_store(path, TEST_PASSPHRASE, "password", TEST_URL, "remmina-api", &error));
    g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
    g_clear_error(&error);
    g_assert_false(g_file_test(path, G_FILE_TEST_EXISTS));
    g_free(path);
}

#define TOKEN_URL TEST_URL "/oauth2/token"
#define SECRET_URL TEST_URL "/api/v2/secrets/1001"
#define REFRESH_1 "grant_type=refresh_token&refresh_token=direct-refresh-1"
#define TOKEN_RESPONSE(access, refresh) \
    "{\"access_token\":\"" access "\",\"token_type\":\"bearer\"," \
    "\"expires_in\":1199,\"refresh_token\":\"" refresh "\"}"
#define SECRET_RESPONSE \
    "{\"id\":1001,\"name\":\"Tier 0 Jump\",\"secretTemplateId\":6001,\"folderId\":12," \
    "\"active\":true,\"items\":[" \
    "{\"itemId\":1,\"fieldId\":108,\"fieldName\":\"Domain\",\"slug\":\"domain\"," \
    "\"itemValue\":\"EXAMPLE\",\"isPassword\":false,\"isFile\":false,\"isNotes\":false}," \
    "{\"itemId\":2,\"fieldId\":111,\"fieldName\":\"Username\",\"slug\":\"username\"," \
    "\"itemValue\":\"t0-admin\",\"isPassword\":false,\"isFile\":false,\"isNotes\":false}," \
    "{\"itemId\":3,\"fieldId\":110,\"fieldName\":\"Password\",\"slug\":\"password\"," \
    "\"itemValue\":\"example-password\",\"isPassword\":true,\"isFile\":false,\"isNotes\":false}]}"

typedef struct {
    const gchar *url;         /* expected request URL */
    const gchar *post;        /* expected form body, NULL for GET */
    const gchar *token;       /* expected bearer token, NULL for none */
    long status;              /* HTTP status the fake server answers */
    const gchar *body;        /* response body for HTTP 200 */
    gboolean no_cache_file;   /* the token file must be gone by now */
} Exchange;

static const Exchange *exchanges;
static guint exchange_count, exchange_next;
static const gchar *expected_otp;

static GString *fake_request(const gchar *url, const gchar *post, const gchar *token,
                             const gchar *otp, GError **error)
{
    g_assert_cmpuint(exchange_next, <, exchange_count);
    const Exchange *x = &exchanges[exchange_next++];
    g_assert_cmpstr(url, ==, x->url);
    g_assert_cmpstr(post, ==, x->post);
    g_assert_cmpstr(token, ==, x->token);
    /* The OTP header belongs to the password grant only. */
    g_assert_cmpstr(otp, ==, post && g_str_has_prefix(post, "grant_type=password&") ? expected_otp : NULL);
    if (x->no_cache_file) {
        gchar *path = cache_file();
        g_assert_false(g_file_test(path, G_FILE_TEST_EXISTS));
        g_free(path);
    }
    if (x->status != 200) {
        set_http_error(error, x->status);
        return NULL;
    }
    return g_string_new(x->body);
}

/* One scripted dialog: the prompt that must appear next and what the user
   enters. A NULL answer means Cancel. */
typedef struct {
    const gchar *kind;   /* "unlock", "create", "paste", "password" or "otp" */
    const gchar *answer;
} Answer;

static const Answer *answers;
static guint answer_count, answer_next;
static GString *messages;

static gchar *next_answer(const gchar *kind)
{
    if (answer_next >= answer_count) g_error("Unexpected %s dialog", kind);
    const Answer *a = &answers[answer_next++];
    g_assert_cmpstr(kind, ==, a->kind);
    return g_strdup(a->answer);
}

static gchar *fake_passphrase(GtkWindow *parent, gboolean create)
{
    (void)parent;
    return next_answer(create ? "create" : "unlock");
}

static gchar *fake_paste(GtkWindow *parent, const gchar *url)
{
    (void)parent; (void)url;
    return next_answer("paste");
}

static gchar *fake_password(GtkWindow *parent, const gchar *url, const gchar *user)
{
    (void)parent; (void)url; (void)user;
    return next_answer("password");
}

static gchar *fake_otp(GtkWindow *parent)
{
    (void)parent;
    return next_answer("otp");
}

static void fake_message(GtkWindow *parent, GtkMessageType type, const gchar *text)
{
    (void)parent; (void)type;
    g_string_append_printf(messages, "%s\n", text);
}

static void script_session(const Exchange *list, guint count,
                           const Answer *dialogs, guint dialog_count)
{
    reset_tokens();
    exchanges = list;
    exchange_count = count;
    exchange_next = 0;
    http_request = fake_request;
    answers = dialogs;
    answer_count = dialog_count;
    answer_next = 0;
    if (messages) g_string_truncate(messages, 0);
    else messages = g_string_new(NULL);
    cache_passphrase_prompt = fake_passphrase;
    browser_token_prompt = fake_paste;
    api_password_prompt = fake_password;
    otp_prompt = fake_otp;
    message = fake_message;
    wipe(cache_passphrase);
    cache_passphrase = NULL;
    cache_checked = FALSE;
    cache_declined = FALSE;
}

/* A direct API login later in a Remmina session: the cache passphrase is
   known, the file was already checked, and no dialog may appear. */
static void start_session(const Exchange *list, guint count)
{
    script_session(list, count, NULL, 0);
    cache_passphrase = g_strdup(TEST_PASSPHRASE);
    cache_checked = TRUE;
}

static void end_session(void)
{
    g_assert_cmpuint(exchange_next, ==, exchange_count);
    g_assert_cmpuint(answer_next, ==, answer_count);
    http_request = request;
    cache_passphrase_prompt = cache_passphrase_dialog;
    browser_token_prompt = browser_token_dialog;
    api_password_prompt = api_password_dialog;
    otp_prompt = otp_dialog;
    message = message_dialog;
    expected_otp = NULL;
    wipe(cache_passphrase);
    cache_passphrase = NULL;
    cache_checked = FALSE;
    cache_declined = FALSE;
    reset_tokens();
}

static gboolean fetch_secret_with(const gchar *auth_mode, const gchar *mfa, GError **error)
{
    Connection c = { .secret_id = "1001", .username_slug = "username",
                     .password_slug = "password", .domain_slug = "domain" };
    gchar *user = NULL, *password = NULL, *domain = NULL;
    gboolean ok = retrieve_with_auth(NULL, TEST_URL, "remmina-api", "v2", auth_mode, mfa,
                                     &c, &user, &password, &domain, error);
    if (ok) {
        g_assert_cmpstr(user, ==, "t0-admin");
        g_assert_cmpstr(password, ==, "example-password");
        g_assert_cmpstr(domain, ==, "EXAMPLE");
    }
    g_free(user);
    wipe(password);
    g_free(domain);
    return ok;
}

static gboolean fetch_test_secret(GError **error)
{
    return fetch_secret_with("password", "none", error);
}

/* Reads the token file the way a restarted Remmina would. */
static void assert_saved_direct_tokens(const gchar *access, const gchar *refresh)
{
    clear_direct_token();
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_true(token_cache_restore(path, TEST_PASSPHRASE, "password", TEST_URL, "remmina-api", &error));
    g_assert_no_error(error);
    g_assert_cmpstr(direct_token, ==, access);
    g_assert_cmpstr(direct_refresh_token, ==, refresh);
    g_free(path);
}

/* Secret Server can rotate refresh tokens, so a restart needs the new one. */
static void test_refresh_saves_new_tokens(void)
{
    const Exchange list[] = {
        { TOKEN_URL, REFRESH_1, NULL, 200, TOKEN_RESPONSE("direct-access-2", "direct-refresh-2"), FALSE },
        { SECRET_URL, NULL, "direct-access-2", 200, SECRET_RESPONSE, FALSE },
    };
    start_session(list, G_N_ELEMENTS(list));
    use_direct_token("direct-access-1", "direct-refresh-1", -60);
    GError *error = NULL;
    g_assert_true(fetch_test_secret(&error));
    g_assert_no_error(error);
    assert_saved_direct_tokens("direct-access-2", "direct-refresh-2");
    end_session();
}

/* First connection after a restart: nothing in memory, the passphrase was
   just entered, and the saved access token has expired. */
static void test_restart_uses_saved_refresh_token(void)
{
    const Exchange list[] = {
        { TOKEN_URL, "grant_type=refresh_token&refresh_token=direct-refresh-2", NULL, 200,
          TOKEN_RESPONSE("direct-access-3", "direct-refresh-3"), FALSE },
        { SECRET_URL, NULL, "direct-access-3", 200, SECRET_RESPONSE, FALSE },
    };
    start_session(list, G_N_ELEMENTS(list));
    write_direct_payload("refresh=direct-refresh-2\n", -60);
    cache_checked = FALSE;
    GError *error = NULL;
    g_assert_true(fetch_test_secret(&error));
    g_assert_no_error(error);
    g_assert_true(cache_checked);
    assert_saved_direct_tokens("direct-access-3", "direct-refresh-3");
    end_session();
}

/* RFC 6749: without a new refresh token, the client keeps the old one. */
static void test_refresh_keeps_old_refresh_token(void)
{
    const Exchange list[] = {
        { TOKEN_URL, REFRESH_1, NULL, 200,
          "{\"access_token\":\"direct-access-2\",\"token_type\":\"bearer\",\"expires_in\":1199}", FALSE },
        { SECRET_URL, NULL, "direct-access-2", 200, SECRET_RESPONSE, FALSE },
    };
    start_session(list, G_N_ELEMENTS(list));
    use_direct_token("direct-access-1", "direct-refresh-1", -60);
    GError *error = NULL;
    g_assert_true(fetch_test_secret(&error));
    g_assert_no_error(error);
    assert_saved_direct_tokens("direct-access-2", "direct-refresh-1");
    end_session();
}

static void test_rejected_token_is_replaced(void)
{
    const Exchange list[] = {
        { SECRET_URL, NULL, "direct-access-1", 401, NULL, FALSE },
        { TOKEN_URL, REFRESH_1, NULL, 200, TOKEN_RESPONSE("direct-access-2", "direct-refresh-2"), TRUE },
        { SECRET_URL, NULL, "direct-access-2", 200, SECRET_RESPONSE, FALSE },
    };
    start_session(list, G_N_ELEMENTS(list));
    write_direct_payload("refresh=direct-refresh-1\n", 600);
    use_direct_token("direct-access-1", "direct-refresh-1", 600);
    GError *error = NULL;
    g_assert_true(fetch_test_secret(&error));
    g_assert_no_error(error);
    assert_saved_direct_tokens("direct-access-2", "direct-refresh-2");
    end_session();
}

static void test_twice_rejected_token_is_deleted(void)
{
    const Exchange list[] = {
        { SECRET_URL, NULL, "direct-access-1", 401, NULL, FALSE },
        { TOKEN_URL, REFRESH_1, NULL, 200, TOKEN_RESPONSE("direct-access-2", "direct-refresh-2"), TRUE },
        { SECRET_URL, NULL, "direct-access-2", 401, NULL, FALSE },
    };
    start_session(list, G_N_ELEMENTS(list));
    write_direct_payload("refresh=direct-refresh-1\n", 600);
    use_direct_token("direct-access-1", "direct-refresh-1", 600);
    GError *error = NULL;
    g_assert_false(fetch_test_secret(&error));
    g_assert_error(error, DELINEA_HTTP_ERROR, 401);
    g_clear_error(&error);
    g_assert_null(direct_token);
    g_assert_null(direct_refresh_token);
    gchar *path = cache_file();
    g_assert_false(g_file_test(path, G_FILE_TEST_EXISTS));
    g_free(path);
    end_session();
}

static gboolean cache_file_exists(void)
{
    gchar *path = cache_file();
    gboolean exists = g_file_test(path, G_FILE_TEST_EXISTS);
    g_free(path);
    return exists;
}

static guint message_count(void)
{
    guint count = 0;
    for (const gchar *p = messages->str; *p; p++)
        if (*p == '\n') count++;
    return count;
}

/* Restores the browser token from the file with the given passphrase. */
static void assert_saved_browser_token(const gchar *passphrase, const gchar *token)
{
    clear_browser_token();
    gchar *path = cache_file();
    GError *error = NULL;
    g_assert_true(token_cache_restore(path, passphrase, "browser-token", TEST_URL, NULL, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(browser_token, ==, token);
    g_free(path);
}

static void fetch_browser_secret(void)
{
    GError *error = NULL;
    g_assert_true(fetch_secret_with("browser-token", "none", &error));
    g_assert_no_error(error);
}

/* Cancel on the save prompt keeps tokens in memory for the whole session. */
static void test_cancel_save_prompt(void)
{
    const Exchange list[] = {
        { SECRET_URL, NULL, "browser-token-1", 200, SECRET_RESPONSE, FALSE },
        { SECRET_URL, NULL, "browser-token-2", 200, SECRET_RESPONSE, FALSE },
    };
    const Answer dialogs[] = {
        { "paste", "browser-token-1" }, { "create", NULL }, { "paste", "browser-token-2" },
    };
    script_session(list, G_N_ELEMENTS(list), dialogs, G_N_ELEMENTS(dialogs));
    fetch_browser_secret();
    clear_browser_token();
    fetch_browser_secret();
    g_assert_false(cache_file_exists());
    end_session();
}

static void test_browser_token_is_saved(void)
{
    const Exchange list[] = { { SECRET_URL, NULL, "browser-token-5", 200, SECRET_RESPONSE, FALSE } };
    const Answer dialogs[] = { { "paste", "browser-token-5" }, { "create", TEST_PASSPHRASE } };
    script_session(list, G_N_ELEMENTS(list), dialogs, G_N_ELEMENTS(dialogs));
    fetch_browser_secret();
    assert_saved_browser_token(TEST_PASSPHRASE, "browser-token-5");
    end_session();
}

static void test_unlock_allows_three_attempts(void)
{
    const Exchange list[] = { { SECRET_URL, NULL, "browser-token-2", 200, SECRET_RESPONSE, FALSE } };
    const Answer dialogs[] = {
        { "unlock", "wrong one" }, { "unlock", "wrong two" }, { "unlock", TEST_PASSPHRASE },
    };
    script_session(list, G_N_ELEMENTS(list), dialogs, G_N_ELEMENTS(dialogs));
    write_browser_payload(600);
    fetch_browser_secret();
    g_assert_cmpuint(message_count(), ==, 2);
    end_session();
}

/* A mistyped passphrase must never be used to write the file. */
static void test_three_wrong_passphrases(void)
{
    const Exchange list[] = { { SECRET_URL, NULL, "browser-token-3", 200, SECRET_RESPONSE, FALSE } };
    const Answer dialogs[] = {
        { "unlock", "wrong one" }, { "unlock", "wrong two" }, { "unlock", "wrong three" },
        { "paste", "browser-token-3" }, { "create", "a new passphrase" },
    };
    script_session(list, G_N_ELEMENTS(list), dialogs, G_N_ELEMENTS(dialogs));
    write_browser_payload(600);
    fetch_browser_secret();
    assert_saved_browser_token("a new passphrase", "browser-token-3");
    end_session();
}

static void test_cancel_unlock_keeps_file(void)
{
    const Exchange list[] = { { SECRET_URL, NULL, "browser-token-4", 200, SECRET_RESPONSE, FALSE } };
    const Answer dialogs[] = { { "unlock", NULL }, { "paste", "browser-token-4" } };
    script_session(list, G_N_ELEMENTS(list), dialogs, G_N_ELEMENTS(dialogs));
    write_browser_payload(600);
    fetch_browser_secret();
    assert_saved_browser_token(TEST_PASSPHRASE, "browser-token-2");
    end_session();
}

/* The file is gone before the user is asked for a new token. */
static void test_browser_401_deletes_file(void)
{
    const Exchange list[] = { { SECRET_URL, NULL, "browser-token-2", 401, NULL, FALSE } };
    const Answer dialogs[] = { { "unlock", TEST_PASSPHRASE }, { "paste", NULL } };
    script_session(list, G_N_ELEMENTS(list), dialogs, G_N_ELEMENTS(dialogs));
    write_browser_payload(600);
    GError *error = NULL;
    g_assert_false(fetch_secret_with("browser-token", "none", &error));
    g_assert_no_error(error);
    g_assert_false(cache_file_exists());
    end_session();
}

static void test_password_login_is_saved(void)
{
    const Exchange list[] = {
        { TOKEN_URL, "grant_type=password&username=remmina-api&password=api-password", NULL, 200,
          TOKEN_RESPONSE("direct-access-1", "direct-refresh-1"), FALSE },
        { SECRET_URL, NULL, "direct-access-1", 200, SECRET_RESPONSE, FALSE },
    };
    const Answer dialogs[] = {
        { "password", "api-password" }, { "otp", "123456" }, { "create", TEST_PASSPHRASE },
    };
    script_session(list, G_N_ELEMENTS(list), dialogs, G_N_ELEMENTS(dialogs));
    expected_otp = "123456";
    GError *error = NULL;
    g_assert_true(fetch_secret_with("password", "otp", &error));
    g_assert_no_error(error);
    assert_saved_direct_tokens("direct-access-1", "direct-refresh-1");
    end_session();
}

static gchar *config_file(void)
{
    return g_build_filename(g_get_user_config_dir(), "remmina-delinea", "config.ini", NULL);
}

static void write_config(const gchar *contents)
{
    gchar *path = config_file();
    gchar *dir = g_path_get_dirname(path);
    GError *error = NULL;
    g_assert_cmpint(g_mkdir_with_parents(dir, 0700), ==, 0);
    g_assert_true(g_file_set_contents(path, contents, -1, &error));
    g_assert_no_error(error);
    g_free(dir);
    g_free(path);
}

static void remove_config(void)
{
    gchar *path = config_file();
    g_unlink(path);
    g_free(path);
}

/* Turned off: no passphrase prompt, and an old file is removed. */
static void test_token_file_turned_off(void)
{
    const Exchange list[] = { { SECRET_URL, NULL, "browser-token-6", 200, SECRET_RESPONSE, FALSE } };
    const Answer dialogs[] = { { "paste", "browser-token-6" } };
    script_session(list, G_N_ELEMENTS(list), dialogs, G_N_ELEMENTS(dialogs));
    write_config("[server]\nurl=" TEST_URL "\nsave_tokens=false\n");
    write_browser_payload(600);
    fetch_browser_secret();
    g_assert_false(cache_file_exists());
    remove_config();
    end_session();
}

static void test_save_settings(void)
{
    reset_tokens();
    GError *error = NULL;
    g_assert_true(save_settings(TEST_URL, TRUE, "remmina-api", TRUE, TRUE, &error));
    g_assert_no_error(error);
    gchar *url = NULL, *user = NULL, *version = NULL, *auth = NULL, *mfa = NULL;
    g_assert_true(load_config(&url, &user, &version, &auth, &mfa, &error));
    g_assert_cmpstr(auth, ==, "password");
    g_assert_cmpstr(user, ==, "remmina-api");
    g_assert_cmpstr(mfa, ==, "otp");
    g_free(url); g_free(user); g_free(version); g_free(auth); g_free(mfa);
    g_assert_true(token_cache_enabled());
    /* Saving the same login again keeps the token file. */
    write_direct_payload("refresh=direct-refresh-2\n", 600);
    g_assert_true(save_settings(TEST_URL, TRUE, "remmina-api", TRUE, TRUE, &error));
    g_assert_true(cache_file_exists());
    /* Another server clears the tokens and deletes the file. */
    use_direct_token("direct-access-1", "direct-refresh-1", 600);
    g_assert_true(save_settings("https://other.example.org/SecretServer", TRUE, "remmina-api",
                                TRUE, TRUE, &error));
    g_assert_false(cache_file_exists());
    g_assert_null(direct_token);
    /* Turning the token file off deletes it and forgets the passphrase. */
    write_direct_payload("refresh=direct-refresh-2\n", 600);
    cache_passphrase = g_strdup(TEST_PASSPHRASE);
    g_assert_true(save_settings("https://other.example.org/SecretServer", TRUE, "remmina-api",
                                TRUE, FALSE, &error));
    g_assert_false(cache_file_exists());
    g_assert_null(cache_passphrase);
    g_assert_false(token_cache_enabled());
    /* Invalid settings are rejected and nothing is written. */
    g_assert_false(save_settings("http://insecure.example.org", FALSE, "", FALSE, TRUE, &error));
    g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
    g_clear_error(&error);
    g_assert_false(token_cache_enabled());
    remove_config();
    reset_tokens();
}

static void write_profile(const gchar *dir, const gchar *name, const gchar *contents)
{
    GError *error = NULL;
    gchar *path = g_build_filename(dir, name, NULL);
    g_assert_true(g_file_set_contents(path, contents, -1, &error));
    g_assert_no_error(error);
    g_free(path);
}

static void test_checkable_profiles(void)
{
    GError *error = NULL;
    gchar *dir = g_dir_make_tmp("remmina-profiles-test-XXXXXX", &error);
    g_assert_no_error(error);
    /* Neither creation order nor file names match the expected order, in
       either direction, so the test cannot pass by directory order. */
    const gchar *files[] = { "p1.remmina", "p2.remmina", "p3.remmina", "no-id.remmina",
                             "bad-id.remmina", "rdp.remmina", "vnc.remmina" };
    write_profile(dir, files[0], "[remmina]\nprotocol=DelineaRDP\nname=Jump C\ngroup=Tier 0\n"
                                 "server=c.example.org\ndelinea_secret_id=1003\n");
    write_profile(dir, files[1], "[remmina]\nprotocol=DelineaRDP\nname=Jump A\ngroup=Tier 1\n"
                                 "server=a.example.org\ndelinea_secret_id=1001\n");
    write_profile(dir, files[2], "[remmina]\nprotocol=DelineaRDP\nname=Jump B\ngroup=Tier 0\n"
                                 "server=b.example.org\ndelinea_secret_id=1002\n");
    write_profile(dir, files[3], "[remmina]\nprotocol=DelineaRDP\nname=No ID\ngroup=Tier 2\n"
                                 "server=d.example.org\n");
    write_profile(dir, files[4], "[remmina]\nprotocol=DelineaRDP\nname=Bad ID\ngroup=Tier 2\n"
                                 "server=e.example.org\ndelinea_secret_id=12x\n");
    write_profile(dir, files[5], "[remmina]\nprotocol=RDP\nname=Plain RDP\ngroup=Tier 0\n"
                                 "server=f.example.org\ndelinea_secret_id=1004\n");
    write_profile(dir, files[6], "[remmina]\nprotocol=VNC\nname=VNC\ngroup=Tier 0\n"
                                 "server=g.example.org\ndelinea_secret_id=1005\n");
    GPtrArray *profiles = checkable_profiles(dir);
    g_assert_cmpuint(profiles->len, ==, 3);
    /* Group first, then name: Tier 0 comes before the alphabetically first name. */
    const gchar *expected[] = { "Jump B", "Jump C", "Jump A" };
    for (guint i = 0; i < G_N_ELEMENTS(expected); i++) {
        Connection *c = g_ptr_array_index(profiles, i);
        g_assert_cmpstr(c->name, ==, expected[i]);
    }
    g_assert_cmpstr(((Connection *)g_ptr_array_index(profiles, 0))->secret_id, ==, "1002");
    g_ptr_array_unref(profiles);
    for (guint i = 0; i < G_N_ELEMENTS(files); i++) {
        gchar *path = g_build_filename(dir, files[i], NULL);
        g_unlink(path);
        g_free(path);
    }
    g_rmdir(dir);
    g_free(dir);
}

static GPtrArray *registered_names;

static gboolean record_plugin(RemminaPlugin *plugin)
{
    g_ptr_array_add(registered_names, g_strdup(plugin->name));
    return TRUE;
}

/* Settings and Check secret live in Preferences, so no Tools menu entry. */
static void test_registered_plugins(void)
{
    RemminaPluginService fake = { .register_plugin = record_plugin };
    RemminaPluginService *real = service;
    registered_names = g_ptr_array_new_with_free_func(g_free);
    g_assert_true(remmina_plugin_entry(&fake));
    service = real;
    g_assert_cmpuint(registered_names->len, ==, 2);
    g_assert_true(g_ptr_array_find_with_equal_func(registered_names, "DelineaRDP", g_str_equal, NULL));
    g_assert_true(g_ptr_array_find_with_equal_func(registered_names, "DelineaSettings", g_str_equal, NULL));
    g_ptr_array_unref(registered_names);
}

static void test_login_settings_changed(void)
{
    GKeyFile *key = g_key_file_new();
    g_key_file_set_string(key, "server", "url", TEST_URL);
    /* Without an auth key, browser sign-in is the default. */
    g_assert_false(login_settings_changed(key, TEST_URL, FALSE, ""));
    g_assert_true(login_settings_changed(key, "https://other.example.org/SecretServer", FALSE, ""));
    g_assert_true(login_settings_changed(key, TEST_URL, TRUE, "remmina-api"));
    g_key_file_set_string(key, "server", "auth", "browser-token");
    g_key_file_set_string(key, "server", "api_user", "remmina-api");
    g_assert_false(login_settings_changed(key, TEST_URL, FALSE, "someone-else"));
    g_key_file_set_string(key, "server", "auth", "password");
    g_assert_false(login_settings_changed(key, TEST_URL, TRUE, "remmina-api"));
    g_assert_true(login_settings_changed(key, TEST_URL, TRUE, "someone-else"));
    g_assert_true(login_settings_changed(key, TEST_URL, FALSE, "remmina-api"));
    g_key_file_unref(key);
}

static void remove_tree(const gchar *path)
{
    GDir *dir = g_dir_open(path, 0, NULL);
    if (dir) {
        const gchar *name;
        while ((name = g_dir_read_name(dir))) {
            gchar *child = g_build_filename(path, name, NULL);
            remove_tree(child);
            g_free(child);
        }
        g_dir_close(dir);
    }
    g_remove(path);
}

int main(int argc, char **argv)
{
    /* No session bus, so a failing test can never reach the desktop keyring. */
    g_setenv("DBUS_SESSION_BUS_ADDRESS", "disabled:", TRUE);
    /* Must run before anything calls g_get_user_config_dir(), which caches. */
    gchar *config_home = g_dir_make_tmp("remmina-delinea-test-XXXXXX", NULL);
    g_assert_nonnull(config_home);
    g_setenv("XDG_CONFIG_HOME", config_home, TRUE);
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/delinea/configuration", test_configuration);
    g_test_add_func("/delinea/profiles", test_profiles);
    g_test_add_func("/delinea/secret-fields", test_secret_fields);
    g_test_add_func("/delinea/token-lifetime", test_token_lifetime);
    g_test_add_func("/delinea/token-rotation", test_token_rotation);
    g_test_add_func("/delinea/token-cache/browser-round-trip", test_cache_browser_round_trip);
    g_test_add_func("/delinea/token-cache/browser-at-most-15-minutes", test_cache_browser_at_most_15_minutes);
    g_test_add_func("/delinea/token-cache/browser-expired", test_cache_browser_expired);
    g_test_add_func("/delinea/token-cache/other-settings", test_cache_other_settings);
    g_test_add_func("/delinea/token-cache/browser-ignores-api-user", test_cache_browser_ignores_api_user);
    g_test_add_func("/delinea/token-cache/direct-round-trip", test_cache_direct_round_trip);
    g_test_add_func("/delinea/token-cache/direct-expired", test_cache_direct_expired);
    g_test_add_func("/delinea/token-cache/direct-at-most-one-day", test_cache_direct_at_most_one_day);
    g_test_add_func("/delinea/token-cache/direct-other-user", test_cache_direct_other_user);
    g_test_add_func("/delinea/token-cache/wrong-passphrase", test_cache_wrong_passphrase);
    g_test_add_func("/delinea/token-cache/invalid-payload", test_cache_invalid_payload);
    g_test_add_func("/delinea/token-cache/private-directory", test_cache_private_directory);
    g_test_add_func("/delinea/token-cache/needs-token", test_cache_needs_token);
    g_test_add_func("/delinea/login/refresh-saves-new-tokens", test_refresh_saves_new_tokens);
    g_test_add_func("/delinea/login/restart-uses-saved-refresh-token", test_restart_uses_saved_refresh_token);
    g_test_add_func("/delinea/login/refresh-keeps-old-refresh-token", test_refresh_keeps_old_refresh_token);
    g_test_add_func("/delinea/login/rejected-token-is-replaced", test_rejected_token_is_replaced);
    g_test_add_func("/delinea/login/twice-rejected-token-is-deleted", test_twice_rejected_token_is_deleted);
    g_test_add_func("/delinea/login/settings-changed", test_login_settings_changed);
    g_test_add_func("/delinea/dialogs/cancel-save-prompt", test_cancel_save_prompt);
    g_test_add_func("/delinea/dialogs/browser-token-is-saved", test_browser_token_is_saved);
    g_test_add_func("/delinea/dialogs/unlock-allows-three-attempts", test_unlock_allows_three_attempts);
    g_test_add_func("/delinea/dialogs/three-wrong-passphrases", test_three_wrong_passphrases);
    g_test_add_func("/delinea/dialogs/cancel-unlock-keeps-file", test_cancel_unlock_keeps_file);
    g_test_add_func("/delinea/dialogs/browser-401-deletes-file", test_browser_401_deletes_file);
    g_test_add_func("/delinea/dialogs/password-login-is-saved", test_password_login_is_saved);
    g_test_add_func("/delinea/dialogs/token-file-turned-off", test_token_file_turned_off);
    g_test_add_func("/delinea/settings/save", test_save_settings);
    g_test_add_func("/delinea/registered-plugins", test_registered_plugins);
    g_test_add_func("/delinea/checkable-profiles", test_checkable_profiles);
    g_test_add_func("/delinea/configuration-ignores-old-connections", test_configuration_ignores_old_connections);
    int result = g_test_run();
    remove_tree(config_home);
    g_free(config_home);
    return result;
}
