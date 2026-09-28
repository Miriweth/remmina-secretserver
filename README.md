# Remmina Secret Server plugin

A Remmina plugin that reads RDP credentials from Delinea Secret Server when a
connection starts. Each Remmina profile stores a jump host and a Secret ID;
the RDP username, password, and domain come from the Secret Server API. The
password is fetched again on every connection and is not saved in the profile.

The plugin adds **Delinea RDP - Secret Server** to Remmina's protocol list and
a **Delinea** tab to Preferences. You can group four jump host profiles as
Tier 0 through Tier 3 in Remmina's normal connection list. RDP sessions use the
same Remmina group, so Remmina can show them as tabs.

## Build and install

On CachyOS or macOS, clone this repository and run:

```sh
./build-install.sh
```

The script installs build dependencies, builds and tests the plugin, installs
it for the current user, and creates `config.ini` only if it does not already
exist. On macOS it builds Remmina 1.4.43 from the official GitLab repository
under `~/.cache/remmina-delinea` if Remmina is missing. That build needs
Homebrew and takes longer than the plugin build. GitHub Actions runs the
script on macOS 15 and builds Remmina and the plugin there, but an RDP session
on macOS has not been tested yet. Restart Remmina after installation.

For a manual build, install GTK 3, JSON-GLib, libcurl, libsecret, libsodium,
and `pkg-config`, then run `make test && make && make install-user`. The
plugin uses Remmina 1.4.43 headers included under `vendor/remmina/`.

## Configure Remmina

1. Open **☰ → Preferences → Delinea**. Enter your Secret Server URL and choose
   the login mode. The settings are saved to
   `~/.config/remmina-delinea/config.ini` with permissions `0600`.
2. Create a Remmina profile with **Protocol: Delinea RDP - Secret Server**.
   Under **Basic**, enter the jump host in **Server** and the numeric
   **Secret Server ID**. Put the profile in a group such as `Tier 0`.
3. Repeat for the other tiers. Double-click a profile to connect.

To test the API lookup without starting RDP, choose the profile under **Test
profile** in **Preferences → Delinea** and click **Check secret**. The check
uses the saved settings, so save changes first.

The plugin reads fields with the slugs `username`, `password`, and `domain` by
default. Empty slug fields in Remmina use those defaults. If a Secret template
uses different slugs, enter them under the profile's **Advanced** tab.

## Authentication

**Browser sign-in + API token** opens Secret Server in your browser. Complete
ADFS and MFA there, then use **User Preferences → Generate API Token and Copy
to Clipboard** and paste the token into Remmina. The plugin uses a pasted
token for at most 15 minutes. If the API returns HTTP 401, the plugin asks for
a new token on the same connection attempt. This mode does not read browser
cookies or receive an OAuth callback.

**Direct API login** uses Secret Server's `/oauth2/token` endpoint with the
`password` grant and, if enabled in Preferences, an OTP. If Secret Server
returns a refresh token, the plugin uses it when the access token expires. If
refresh fails, it asks for the API password and OTP again. This mode does not
run the ADFS/Duo browser flow. Secret Server administrators can disable direct
API authentication for users.

API tokens, refresh tokens, and RDP passwords are never written to the
Remmina profile or `config.ini`. The plugin opens an in-memory RDP profile.
The Secret Server user must have permission to read each referenced Secret.
Secret checkout and Delinea RDP Proxy are not implemented.

### Token file

The plugin can keep the Secret Server token in
`~/.config/remmina-delinea/tokens.enc`, so a Remmina restart does not always
mean a new login. The file holds one token for the configured server, login
mode, and API user: the access token, and for direct API login also the
refresh token. RDP usernames, passwords, and domains are never written to it.
To turn the file off, clear **Save tokens in an encrypted file** in
**Preferences → Delinea**. That also deletes an existing file.

After the first login, the plugin asks for a passphrase of at least 12
characters. It derives a key from the passphrase with Argon2id and encrypts
the file with XSalsa20-Poly1305 from libsodium. The passphrase is not written
to disk, but Remmina keeps it in memory until it quits. After a restart, the
plugin asks for the passphrase when it first needs a token and the file
exists, even if the token in it has expired. It then uses the passphrase for
the next save. The file has permissions `0600` and its directory `0700`.

- Cancel on a passphrase prompt keeps tokens in memory until Remmina quits.
  The plugin asks again after the next start.
- The plugin uses a browser token for at most 15 minutes after you paste it,
  also across a restart. An expired token stays in the file until the next
  save replaces it. For browser sign-in, the file only saves you a paste when
  Remmina restarts within those 15 minutes.
- With direct API login, a saved refresh token lets the plugin get a new
  access token after a restart without asking for the API password or OTP.
  When Secret Server sends a new refresh token, the plugin saves it, and
  otherwise keeps the old one. If Secret Server refuses the refresh token, it
  stays in the file until the next successful login replaces it.
- If Secret Server rejects a token while reading a Secret (HTTP 401), the
  plugin deletes the file. The next login saves a new one.
- Saving a different URL, login mode, or direct-login API user in Preferences
  deletes the file.
- After three wrong passphrases, or if the file is damaged, the plugin asks
  for a new passphrase the next time it saves a token and replaces the file.
  To start over, quit Remmina and delete `tokens.enc`.

## Troubleshooting

If Remmina reports **Install the DelineaRDP protocol plugin first**, fully
quit Remmina with `remmina --quit` and start it again. Closing the window can
leave Remmina running in the tray.

If a Secret has no recognized username or password, **Check secret** lists
the API field slugs and whether each has a value. It never prints a password
value. Compare those slugs with the profile's **Advanced** fields.

The API request uses `GET /api/v2/secrets/{id}` and normal HTTPS certificate
verification. See Delinea's documentation for [API tokens](https://docs.delinea.com/online-help/secret-server/users-roles/users/user-preferences/index.htm),
[field slugs](https://docs.delinea.com/online-help/secret-server/secret-operations/secret-templates/secret-template-settings/field-slug-names/index.htm),
[refresh tokens](https://docs.delinea.com/online-help/secret-server/authentication/enable-refresh-token/index.htm),
and [direct API login restrictions](https://docs.delinea.com/online-help/secret-server/admin/app-settings/prevent-direct-api-authentication/index.htm).
