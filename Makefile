NAME = dovecot-submission
SYSTEMD_DIR = /etc/systemd/system
BIN_DIR = /usr/local/sbin

all:

prereqs:
	dnf install platform-python python3-firewall

install:
	# run as root
	if [ $$(id -u) != 0 ]; then \
		echo "must install as root"; \
	else \
		install ${NAME}.py ${BIN_DIR}/${NAME}; \
		umask 0133 && sed 's:BIN_DIR:${BIN_DIR}:' < ${NAME}.service > ${SYSTEMD_DIR}/${NAME}.service; \
		./dovecot-zone.sh; \
	fi

#
# Example pcs resource creation
#
pcs-install:
	pcs resource create Mail-submission systemd:dovecot-submission --group Mail --after Mail-Dovecot
