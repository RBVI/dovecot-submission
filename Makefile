NAME = dovecot-submission
SYSTEMD_DIR = /etc/systemd/system
BIN_DIR = /usr/local/sbin

all:

prereqs:
	# assume RHEL-compatible system
	dnf install platform-python python3-firewall

install:
	install ${NAME}.py ${BIN_DIR}/${NAME}
	umask 0133 && sed 's:BIN_DIR:${BIN_DIR}:' < ${NAME}.service > ${SYSTEMD_DIR}/${NAME}.service
	./dovecot-zone.sh

#
# Example pcs resource creation
#
pcs-install:
	pcs resource create Mail-submission systemd:dovecot-submission --group Mail --after Mail-Dovecot
