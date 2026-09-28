#include <glib/gstdio.h>
#include <sodium.h>
#include <string.h>
#include "../token_store.h"

static void test_encrypted_file(void)
{
    GError *error = NULL;
    gchar *dir = g_dir_make_tmp("remmina-token-test-XXXXXX", &error);
    g_assert_no_error(error);
    gchar *path = g_build_filename(dir, "tokens.enc", NULL);
    const gchar *plain = "[token]\naccess=example-access\nrefresh=example-refresh\n";
    g_assert_true(token_store_write(path, "a long test passphrase", plain, strlen(plain), &error));
    g_assert_no_error(error);
    GStatBuf statbuf;
    g_assert_cmpint(g_stat(path, &statbuf), ==, 0);
    g_assert_cmpint(statbuf.st_mode & 0777, ==, 0600);
    gchar *blob = NULL;
    gsize blob_len = 0;
    g_assert_true(g_file_get_contents(path, &blob, &blob_len, &error));
    g_assert_no_error(error);
    g_assert_null(g_strstr_len(blob, blob_len, "example-access"));
    g_free(blob);
    gsize length = 0;
    gchar *restored = token_store_read(path, "a long test passphrase", &length, &error);
    g_assert_no_error(error);
    g_assert_cmpuint(length, ==, strlen(plain));
    g_assert_cmpstr(restored, ==, plain);
    sodium_memzero(restored, length); g_free(restored);
    g_assert_null(token_store_read(path, "wrong passphrase", NULL, &error));
    g_assert_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED);
    g_clear_error(&error);
    g_unlink(path); g_rmdir(dir); g_free(path); g_free(dir);
}

/* Writes a valid cache file, lets the caller change its bytes, and checks
   that reading it fails with the expected error and no plaintext. */
static void check_damaged_file(void (*damage)(gchar *blob, gsize *length), gint expected)
{
    GError *error = NULL;
    gchar *dir = g_dir_make_tmp("remmina-token-test-XXXXXX", &error);
    g_assert_no_error(error);
    gchar *path = g_build_filename(dir, "tokens.enc", NULL);
    const gchar *plain = "[token]\naccess=example-access\n";
    g_assert_true(token_store_write(path, "a long test passphrase", plain, strlen(plain), &error));
    g_assert_no_error(error);
    gchar *blob = NULL;
    gsize length = 0;
    g_assert_true(g_file_get_contents(path, &blob, &length, &error));
    g_assert_no_error(error);
    damage(blob, &length);
    g_assert_true(g_file_set_contents(path, blob, length, &error));
    g_assert_no_error(error);
    g_free(blob);
    gsize plain_len = 99;
    g_assert_null(token_store_read(path, "a long test passphrase", &plain_len, &error));
    g_assert_error(error, G_IO_ERROR, expected);
    g_assert_cmpuint(plain_len, ==, 99);
    g_clear_error(&error);
    g_unlink(path); g_rmdir(dir); g_free(path); g_free(dir);
}

static void damage_magic(gchar *blob, gsize *length) { (void)length; blob[0] = 'X'; }
/* 6 magic + 16 salt + 24 nonce + 16 MAC bytes is the smallest valid file. */
static void damage_truncate(gchar *blob, gsize *length) { (void)blob; *length = 6 + 16 + 24 + 15; }
static void damage_ciphertext(gchar *blob, gsize *length) { blob[*length - 1] ^= 0x01; }
static void damage_salt(gchar *blob, gsize *length) { (void)length; blob[6] ^= 0x01; }

static void test_damaged_file(void)
{
    check_damaged_file(damage_magic, G_IO_ERROR_INVALID_DATA);
    check_damaged_file(damage_truncate, G_IO_ERROR_INVALID_DATA);
    check_damaged_file(damage_ciphertext, G_IO_ERROR_PERMISSION_DENIED);
    check_damaged_file(damage_salt, G_IO_ERROR_PERMISSION_DENIED);
}

static void test_tightens_permissions(void)
{
    GError *error = NULL;
    gchar *dir = g_dir_make_tmp("remmina-token-test-XXXXXX", &error);
    g_assert_no_error(error);
    gchar *path = g_build_filename(dir, "tokens.enc", NULL);
    g_assert_true(g_file_set_contents(path, "old", -1, &error));
    g_assert_no_error(error);
    g_assert_cmpint(g_chmod(path, 0644), ==, 0);
    g_assert_true(token_store_write(path, "a long test passphrase", "new", 3, &error));
    g_assert_no_error(error);
    GStatBuf statbuf;
    g_assert_cmpint(g_stat(path, &statbuf), ==, 0);
    g_assert_cmpint(statbuf.st_mode & 0777, ==, 0600);
    g_unlink(path); g_rmdir(dir); g_free(path); g_free(dir);
}

static void test_requires_passphrase(void)
{
    GError *error = NULL;
    gchar *dir = g_dir_make_tmp("remmina-token-test-XXXXXX", &error);
    g_assert_no_error(error);
    gchar *path = g_build_filename(dir, "tokens.enc", NULL);
    g_assert_false(token_store_write(path, "", "token", 5, &error));
    g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
    g_clear_error(&error);
    g_assert_false(g_file_test(path, G_FILE_TEST_EXISTS));
    g_assert_true(token_store_write(path, "a long test passphrase", "token", 5, &error));
    g_assert_no_error(error);
    g_assert_null(token_store_read(path, "", NULL, &error));
    g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
    g_clear_error(&error);
    g_unlink(path); g_rmdir(dir); g_free(path); g_free(dir);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/delinea/encrypted-file", test_encrypted_file);
    g_test_add_func("/delinea/token-store/damaged-file", test_damaged_file);
    g_test_add_func("/delinea/token-store/tightens-permissions", test_tightens_permissions);
    g_test_add_func("/delinea/token-store/requires-passphrase", test_requires_passphrase);
    return g_test_run();
}
