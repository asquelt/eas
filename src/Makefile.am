# $Id: Makefile.am,v 1.100 2005/11/04 02:08:54 dhanks Exp $
#
# eas - Enterprise Audit Shell
#
# Copyright 2004 and $Date: 2005/11/04 02:08:54 $
#                Douglas Richard Hanks Jr.
#
# Licensed under the Open Software License version 2.0
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the Open Software
# License, version 2.0 by Lauwrence E. Rosen.
#
# This program is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the Open Software License for details.

CLIENT_ID=client_id.c client_id.h
SOCKET=socket.c socket.h
SSL=ssl.c ssl.h
SIG=sig.c sig.h
CLIENTCONF=clientconf.c clientconf.h
SERVCONF=servconf.c servconf.h
LOG=log.c log.h
RANDOM=random.c random.h
SQL=sql.c sql.h
VD=vd.c vd.h
FUNCS=funcs.c funcs.h
IO=io.c io.h

bin_PROGRAMS=eash eas_test_pty eas_version eas_play
sbin_PROGRAMS=easd eas_dbtool eas_replay eas_report
eas_play_SOURCES=play.c $(IO)
eas_version_SOURCES=version.c
eash_SOURCES=pty.c openpty.c $(SOCKET) $(SSL) $(CLIENTCONF) $(LOG) $(CLIENT_ID) $(SIG) $(SQL) $(IO) $(FUNCS)
easd_SOURCES=daemon.c defines.h $(SOCKET) $(SSL) $(SIG) $(SERVCONF) $(LOG) $(RANDOM) $(SQL) $(VD) $(FUNCS) $(IO)
eas_replay_SOURCES=replay.c defines.h $(SOCKET) $(SSL) $(SIG) $(SERVCONF) $(LOG) $(RANDOM) $(SQL) $(VD) $(FUNCS) $(IO)
eas_report_SOURCES=report.c defines.h $(SOCKET) $(SSL) $(SIG) $(SERVCONF) $(LOG) $(RANDOM) $(SQL) $(VD) $(FUNCS) $(IO)
eas_test_pty_SOURCES=eash_test_pty.c $(CLIENT_ID)
eas_dbtool_SOURCES=shell.c
eas_dbtool_LDADD=$(top_builddir)/sqlite/libsqlite.a
eas_replay_LDADD=$(top_builddir)/sqlite/libsqlite.a
eas_report_LDADD=$(top_builddir)/sqlite/libsqlite.a
easd_LDADD=$(top_builddir)/sqlite/libsqlite.a
eash_LDADD=$(top_builddir)/sqlite/libsqlite.a


EXTRA_DIST=eash_config.in easd_config.in client.pem root.pem server.pem detailed.css report.css

config-setup:
	test -d "$(sysconfdir)" || ( mkdir -p "$(DESTDIR)$(sysconfdir)" && chmod 700 "$(DESTDIR)$(sysconfdir)" )
	test -f "$(sysconfdir)/eash_config" || ( cp eash_config "$(DESTDIR)$(sysconfdir)/eash_config" && chmod 400 "$(DESTDIR)$(sysconfdir)/eash_config" )
	test -f "$(sysconfdir)/easd_config" || ( cp easd_config "$(DESTDIR)$(sysconfdir)/easd_config" && chmod 400 "$(DESTDIR)$(sysconfdir)/easd_config" )
	test -d "$(CA_DIR)" || ( mkdir -p "$(DESTDIR)$(CA_DIR)" && chmod 700 "$(DESTDIR)$(CA_DIR)" )
	test -f "$(CA_DIR)/root.pem" || ( cp root.pem "$(DESTDIR)$(CA_DIR)/root.pem" && chmod 400 "$(DESTDIR)$(CA_DIR)/root.pem" )
	test -f "$(CA_DIR)/client.pem" || ( cp client.pem "$(DESTDIR)$(CA_DIR)/client.pem" && chmod 400 "$(DESTDIR)$(CA_DIR)/client.pem" )
	test -f "$(CA_DIR)/server.pem" || ( cp server.pem "$(DESTDIR)$(CA_DIR)/server.pem" && chmod 400 "$(DESTDIR)$(CA_DIR)/server.pem" )
	echo $(CA_DIR)
	test -d "$(sysconfdir)/css" || ( mkdir -p "$(DESTDIR)$(sysconfdir)/css" && chmod 700 "$(DESTDIR)$(sysconfdir)/css" )
	test -f "$(sysconfdir)/css/report.css" || ( cp report.css "$(DESTDIR)$(sysconfdir)/css/report.css" && chmod 400 "$(DESTDIR)$(sysconfdir)/css/report.css" )
	test -f "$(sysconfdir)/css/detailed.css" || ( cp detailed.css "$(DESTDIR)$(sysconfdir)/css/detailed.css" && chmod 400 "$(DESTDIR)$(sysconfdir)/css/detailed.css" )

config-perms:
	test -f "$(bindir)/eash" && ( chown 0:0 "$(bindir)/eash" && chmod 4555 "$(bindir)/eash" )
	test -f "$(bindir)/eas_test_pty" && ( chown 0:0 "$(bindir)/eas_test_pty" && chmod 4555 "$(bindir)/eas_test_pty" )

	test -f "$(sbindir)/easd" && ( chown 0:0 "$(sbindir)/easd" && chmod 500 "$(sbindir)/easd" )
	test -f "$(sbindir)/eas_dbtool" && ( chown 0:0 "$(sbindir)/eas_dbtool" && chmod 500 "$(sbindir)/eas_dbtool" )
	test -f "$(sbindir)/eas_replay" && ( chown 0:0 "$(sbindir)/eas_replay" && chmod 500 "$(sbindir)/eas_replay" )
	test -f "$(sbindir)/eas_report" && ( chown 0:0 "$(sbindir)/eas_report" && chmod 500 "$(sbindir)/eas_report" )

install: install-am config-setup config-perms
