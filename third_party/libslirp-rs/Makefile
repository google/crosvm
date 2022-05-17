CARGO = cargo
CARGOFLAGS =
SLIRPHELPER = target/debug/libslirp-helper

.PHONY: $(SLIRPHELPER)
$(SLIRPHELPER):
	$(CARGO) build --all-features $(CARGOFLAGS)

.PHONY: test
test: $(SLIRPHELPER)
	SLIRPHELPER=$(SLIRPHELPER) \
	PYTHONPATH=. \
	PYTHONIOENCODING=utf-8 \
		unshare -Ur \
		dbus-run-session --config-file=tests/dbus.conf \
		python3 -m unittest -v
