## Process this file with automake to produce Makefile.in

# snag the whole linux-include directory
EXTRA_DIST = AUTHORS ChangeLog COPYING INSTALL NEWS README VERSION

versiondir = $(prefix)/etc
dist_version_DATA = VERSION
chown = @CHOWN@

SUBDIRS = src

# files we want to delete with make maintainer-clean
MAINTAINERCLEANFILES = aclocal.m4 autoscan.log \
		config.h config.log configure Makefile.in \
		stamp-h1

maintainerclean-hook:
	rm -rf `find $(distdir) -name .deps

# files we want to delete with make distclean
DISTCLEANFILES = $(CLEANFILES)

test:
	( cd src && $(MAKE) test )

# make sure we don't leak CVS/SVN or private policy files
dist-hook:
	rm -rf `find $(distdir) -name CVS`
	rm -rf `find $(distdir) -name .svn`
	rm -rf $(distdir)/autom4te.cache
	rm -rf `find $(distdir) -name .deps`

# make sure all the dirs are correctly created and owned 
install-data-local:
	$(INSTALL) -d $(prefix)/logs
	$(INSTALL) -d $(prefix)/archive
	$(INSTALL) -d $(prefix)/var

release:
	./autogen.sh
	./configure
	$(MAKE) distcheck

