PREFIX ?= /usr/local
ROOT ?= ~/
LIBDIR ?= $(PREFIX)/lib
SYSTEM_EXTENSION_DIR ?= $(LIBDIR)/password-store/extensions
SRC ?= $(SYSTEM_EXTENSION_DIR)/src

all:
	@echo "To use this extension tools that shown below are required."
	@echo "     password store"

install:
	@install -v -d "$(SYSTEM_EXTENSION_DIR)/"
	@install -v -d "$(SRC)/"
	@install -v -m0755 src/main_window.py "$(SRC)/main_window.py"
	@install -v -m0755 src/backup.py "$(SRC)/backup.py"
	@install -v -m0755 src/recover.py "$(SRC)/recover.py"
	@install -v -m0755 PassQR.bash "$(SYSTEM_EXTENSION_DIR)/PassQR.bash"
	@echo
	@echo "PassQR is installed successfully!"
	@echo

uninstall:
	@rm -vrf \
		"$(SYSTEM_EXTENSION_DIR)/PassQR.bash" \
	
	@rm -vrf \
		"$(SRC)/" \
	@echo "QR-Convert is uninstalled successfully!"

.PHONY: install uninstall