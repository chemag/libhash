## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES = libhash.la
libhash_la_LIBADD = $(LIB_KPARTS)
libhash_la_SOURCES = md5.c util.c hash.c version.c
noinst_HEADERS = md5.h util.h hash.h

CCOPT = -W -Wall -Wno-unused -pedantic -fPIC
INCLS = -I. -I$(top_srcdir)/src -I$(srcdir) -I$(top_builddir)
AM_CFLAGS = $(INCLS) $(CCOPT)
AM_CPPFLAGS = $(INCLS) $(CCOPT)

opt:
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/-O2//;s/$$/ -O3/'`"

debug: 
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/-O2/-O0/g;s/$$/ -g -Wall -DDEBUG/'`"

profile:
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/$$/ -O0 -pg/'`" LDFLAGS="`echo $(LDFLAGS) | sed -e 's/$$/ -pg/'`"

mpatrol:
	@$(MAKE) $(MFLAGS) LIBS="`echo $(LIBS) | sed -e 's/$$/ -lmpatrol/'`"

version.c: ../VERSION
	@rm -f $@
	sed -e 's/.*/char version[] = "&";/' ../VERSION > $@


# files we want to delete with make maintainer-clean
MAINTAINERCLEANFILES = aclocal.m4 autoscan.log \
    config.h config.log configure Makefile.in \
    stamp-h1

maintainerclean-hook:
	rm -rf `find $(distdir) -name .deps

# files we want to delete with make distclean
DISTCLEANFILES = $(CLEANFILES) version.c

# Files created in the src dir. 
MOSTLYCLEANFILES = $(BIF_FUNC_H) $(BIF_FUNC_DEF) $(BIF_FUNC_INIT) \
	$(BIF_NETVAR_H) $(BIF_NETVAR_DEF) $(BIF_NETVAR_INIT) \
	$(BRO_BIF) \
	$(BINPAC_H) $(BINPAC_CC) \
	$(DISTCLEANFILES)

LIBS = @LIBS@ -lm -ldl

# XXX: testing unavailable for the moment 

