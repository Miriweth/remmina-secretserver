#include "token_store.h"

#include <glib/gstdio.h>
#include <sodium.h>
#include <errno.h>
#include <string.h>

#define TOKEN_MAGIC "RDTOK1"
#define TOKEN_MAGIC_LEN 6
#define TOKEN_MAX_PLAIN (16 * 1024)
#define TOKEN_HEADER_LEN (TOKEN_MAGIC_LEN + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES)

static gboolean derive_key(unsigned char key[crypto_secretbox_KEYBYTES],
                           const gchar *passphrase, const unsigned char *salt,
                           GError **error)
{
    if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, passphrase, strlen(passphrase),
                      salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) == 0) return TRUE;
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_NO_SPACE,
                        "Could not derive an encryption key for the token cache.");
    return FALSE;
}

gboolean token_store_write(const gchar *path, const gchar *passphrase,
                           const gchar *plain, gsize plain_len, GError **error)
{
    if (!passphrase || !*passphrase || !plain || plain_len > TOKEN_MAX_PLAIN ||
        sodium_init() < 0) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                            "Invalid token cache input.");
        return FALSE;
    }
    gsize total = TOKEN_HEADER_LEN + crypto_secretbox_MACBYTES + plain_len;
    unsigned char *blob = g_malloc(total);
    memcpy(blob, TOKEN_MAGIC, TOKEN_MAGIC_LEN);
    unsigned char *salt = blob + TOKEN_MAGIC_LEN;
    unsigned char *nonce = salt + crypto_pwhash_SALTBYTES;
    unsigned char *ciphertext = nonce + crypto_secretbox_NONCEBYTES;
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    unsigned char key[crypto_secretbox_KEYBYTES];
    gboolean ok = derive_key(key, passphrase, salt, error);
    if (ok) {
        crypto_secretbox_easy(ciphertext, (const unsigned char *)plain, plain_len, nonce, key);
        if (g_file_test(path, G_FILE_TEST_EXISTS) && g_chmod(path, 0600) != 0) {
            g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                        "Could not secure token cache permissions: %s", g_strerror(errno));
            ok = FALSE;
        }
    }
    if (ok) ok = g_file_set_contents_full(path, (const gchar *)blob, total,
                                          G_FILE_SET_CONTENTS_CONSISTENT, 0600, error);
    if (ok && g_chmod(path, 0600) != 0) {
        g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno),
                    "Could not secure token cache permissions: %s", g_strerror(errno));
        ok = FALSE;
    }
    sodium_memzero(key, sizeof key);
    sodium_memzero(blob, total);
    g_free(blob);
    return ok;
}

gchar *token_store_read(const gchar *path, const gchar *passphrase,
                        gsize *plain_len, GError **error)
{
    if (!passphrase || !*passphrase || sodium_init() < 0) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                            "An unlock passphrase is required.");
        return NULL;
    }
    gchar *blob = NULL;
    gsize length = 0;
    if (!g_file_get_contents(path, &blob, &length, error)) return NULL;
    if (length < TOKEN_HEADER_LEN + crypto_secretbox_MACBYTES ||
        length > TOKEN_HEADER_LEN + crypto_secretbox_MACBYTES + TOKEN_MAX_PLAIN ||
        memcmp(blob, TOKEN_MAGIC, TOKEN_MAGIC_LEN) != 0) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                            "Invalid token cache file.");
        sodium_memzero(blob, length); g_free(blob); return NULL;
    }
    const unsigned char *salt = (const unsigned char *)blob + TOKEN_MAGIC_LEN;
    const unsigned char *nonce = salt + crypto_pwhash_SALTBYTES;
    const unsigned char *ciphertext = nonce + crypto_secretbox_NONCEBYTES;
    gsize ciphertext_len = length - TOKEN_HEADER_LEN;
    unsigned char key[crypto_secretbox_KEYBYTES];
    if (!derive_key(key, passphrase, salt, error)) {
        sodium_memzero(key, sizeof key);
        sodium_memzero(blob, length); g_free(blob); return NULL;
    }
    gsize result_len = ciphertext_len - crypto_secretbox_MACBYTES;
    gchar *plain = g_malloc(result_len + 1);
    gboolean ok = crypto_secretbox_open_easy((unsigned char *)plain, ciphertext,
                                              ciphertext_len, nonce, key) == 0;
    sodium_memzero(key, sizeof key);
    sodium_memzero(blob, length); g_free(blob);
    if (!ok) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                            "Incorrect passphrase or damaged token cache.");
        sodium_memzero(plain, result_len + 1); g_free(plain); return NULL;
    }
    plain[result_len] = 0;
    if (plain_len) *plain_len = result_len;
    return plain;
}
