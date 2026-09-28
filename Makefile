CC ?= cc
UNAME_S := $(shell uname -s)
PKGS = gtk+-3.0 json-glib-1.0 libcurl libsecret-1 libsodium
CFLAGS += -O2 -Wall -Wextra -fPIC -Ivendor $(shell pkg-config --cflags $(PKGS))
LDLIBS += $(shell pkg-config --libs $(PKGS))
MODULE_LDFLAGS = -shared
ifeq ($(UNAME_S),Darwin)
MODULE_LDFLAGS = -bundle -undefined dynamic_lookup
endif
PLUGIN_DIR ?= $(or $(XDG_CONFIG_HOME),$(HOME)/.config)/remmina/plugins

all: remmina-plugin-delinea.so

remmina-plugin-delinea.so: plugin.c token_store.c token_store.h vendor/remmina/plugin.h
	$(CC) $(CFLAGS) $(MODULE_LDFLAGS) -o $@ plugin.c token_store.c $(LDLIBS)

# BSD install on macOS has no -D, so create the directory first.
install-user: remmina-plugin-delinea.so
	mkdir -p "$(PLUGIN_DIR)"
	install -m 755 $< "$(PLUGIN_DIR)/$<"

test: test-plugin test-token-store
	./test-plugin
	./test-token-store

test-plugin: tests/test_plugin.c plugin.c token_store.c token_store.h vendor/remmina/plugin.h
	$(CC) $(CFLAGS) -o $@ tests/test_plugin.c token_store.c $(LDLIBS)

test-token-store: tests/test_token_store.c token_store.c token_store.h
	$(CC) $(CFLAGS) -o $@ tests/test_token_store.c token_store.c $(LDLIBS)

.PHONY: all install-user test
