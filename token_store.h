#pragma once

#include <gio/gio.h>

gboolean token_store_write(const gchar *path, const gchar *passphrase,
                           const gchar *plain, gsize plain_len, GError **error);
gchar *token_store_read(const gchar *path, const gchar *passphrase,
                        gsize *plain_len, GError **error);
