#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
platform=$(uname -s)
build_remmina=auto

usage() {
    cat <<'USAGE'
Usage: ./build-install.sh [--build-remmina] [--skip-remmina-build]

Installs build dependencies, builds and tests the Delinea plugin, installs it
for the current user, and creates a starter config if none exists.

On macOS, Remmina 1.4.43 is built in ~/.cache/remmina-delinea when missing.
--build-remmina forces that build; --skip-remmina-build requires an existing
Remmina installation. The script never overwrites an existing config.ini.
USAGE
}

while (($#)); do
    case "$1" in
        --build-remmina) build_remmina=yes ;;
        --skip-remmina-build) build_remmina=no ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

case "$platform" in
    Linux)
        if ! command -v pacman >/dev/null 2>&1; then
            printf 'This Linux installer expects CachyOS or another pacman-based distribution.\n' >&2
            exit 1
        fi
        sudo pacman -S --needed base-devel pkgconf remmina freerdp gtk3 json-glib curl libsecret libsodium
        ;;
    Darwin)
        if ! command -v brew >/dev/null 2>&1; then
            printf 'Homebrew is required on macOS: https://brew.sh\n' >&2
            exit 1
        fi
        brew install cmake ninja pkgconf gtk+3 json-glib curl libsecret libsodium \
            freerdp libssh vte3 pcre2 gettext
        brew_prefix=$(brew --prefix)
        curl_prefix=$(brew --prefix curl)
        export PKG_CONFIG_PATH="$curl_prefix/lib/pkgconfig:$brew_prefix/lib/pkgconfig:$brew_prefix/share/pkgconfig:${PKG_CONFIG_PATH:-}"
        export PATH="$brew_prefix/bin:$PATH"
        if [[ "$build_remmina" == yes ]] ||
           { [[ "$build_remmina" == auto ]] && ! command -v remmina >/dev/null 2>&1; }; then
            cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/remmina-delinea"
            source_dir="$cache_dir/remmina-1.4.43"
            build_dir="$cache_dir/remmina-build"
            # Official upstream; the GitHub mirror stops at v1.4.41.
            remmina_commit=7be0cf2348d149c6bf5bd882fe91d3bec7d6aebb
            mkdir -p "$cache_dir"
            if [[ ! -d "$source_dir/.git" ]]; then
                git clone --depth 1 --branch v1.4.43 \
                    https://gitlab.com/Remmina/Remmina.git "$source_dir"
            fi
            if [[ "$(git -C "$source_dir" rev-parse HEAD)" != "$remmina_commit" ]]; then
                printf 'Unexpected Remmina source in %s. Delete it and run again.\n' "$source_dir" >&2
                exit 1
            fi
            # The RDP plugin includes <cairo/cairo.h>, which needs Homebrew's include root.
            cmake -S "$source_dir" -B "$build_dir" -G Ninja \
                -DCMAKE_BUILD_TYPE=Release \
                -DCMAKE_C_FLAGS="-I$brew_prefix/include" \
                -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
                -DWITH_FREERDP3=ON \
                -DHAVE_LIBAPPINDICATOR=OFF \
                -DWITH_WEBKIT2GTK=OFF \
                -DWITH_GVNC=OFF \
                -DWITH_LIBVNCSERVER=OFF \
                -DWITH_SPICE=OFF \
                -DWITH_X2GO=OFF \
                -DWITH_PYTHONLIBS=OFF \
                -DWITH_KF5WALLET=OFF \
                -DWITH_MANPAGES=OFF \
                -DWITH_ICON_CACHE=OFF \
                -DWITH_NEWS=OFF \
                -DWITH_STATS=OFF \
                -DWITH_TIP=OFF
            cmake --build "$build_dir" --parallel
            cmake --install "$build_dir"
            export PATH="$HOME/.local/bin:$PATH"
        fi
        ;;
    *) printf 'Unsupported operating system: %s\n' "$platform" >&2; exit 1 ;;
esac

if ! command -v remmina >/dev/null 2>&1; then
    printf 'Remmina is not installed. Build it first or omit --skip-remmina-build.\n' >&2
    exit 1
fi

if ! remmina --version 2>&1 | grep -q '1\.4\.43'; then
    printf 'Note: this plugin is built against the Remmina 1.4.43 plugin API.\n' >&2
fi

make -C "$project_dir" -B all test install-user

config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/remmina-delinea"
if [[ ! -e "$config_dir/config.ini" ]]; then
    install -d -m 700 "$config_dir"
    install -m 600 "$project_dir/config.ini.example" "$config_dir/config.ini"
    printf 'Starter config: %s/config.ini\n' "$config_dir"
fi

printf 'Installed. Restart Remmina, then open Menu -> Preferences -> Delinea.\n'
