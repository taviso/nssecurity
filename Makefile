VERSION     = 0.99.10
CFLAGS      = -s -O2 -fPIC -W -Wall -std=gnu99 -fvisibility=hidden -fstack-protector-all $(EXTRA_CFLAGS)
CPPFLAGS    = -Ithird_party/inih -Ithird_party/npapi -DNSSECURITY_VERSION=\"$(VERSION)\" -DNDEBUG -D_FORTIFY_SOURCE=2 $(EXTRA_CPPFLAGS)
LDFLAGS     = $(EXTRA_LDFLAGS)

# Objects required by all targets.
COMMON      = config.o netscape.o log.o third_party/inih/ini.o instance.o export.o util.o policy.o
DIST_EXTRA  = README nssecurity.ini

ifeq ($(shell uname), Darwin)
CFLAGS      += -arch i386 -arch x86_64 -fno-constant-cfstrings
CPPFLAGS    += -DXP_MACOSX
LDFLAGS     += -bundle -framework CoreFoundation

all:    NetscapeSecurityWrapper.plugin
dist:   NetscapeSecurityWrapper-$(VERSION).dmg

NetscapeSecurityWrapper-$(VERSION).dmg: NetscapeSecurityWrapper.plugin $(DIST_EXTRA)
	mkdir -p dist/NetscapeSecurityWrapper
	cp -r $^ dist/NetscapeSecurityWrapper
	hdiutil create $@ -srcfolder dist -volname "NetscapeSecurityWrapper $(VERSION)" -ov
	rm -rf dist
endif

ifeq ($(shell uname), Linux)
CFLAGS      +=
CPPFLAGS    +=
LDFLAGS     += -ldl -shared

ifeq ($(shell uname -m), i686)
CFLAGS      += -m32
endif

all:    netscapesecuritywrapper.so
dist:   netscapesecuritywrapper-$(VERSION)-$(shell uname)-$(shell uname -m).tar.gz

netscapesecuritywrapper-$(VERSION)-$(shell uname)-$(shell uname -m).tar.gz: netscapesecuritywrapper.so $(DIST_EXTRA)
	mkdir -p dist/netscapesecuritywrapper-$(VERSION)-$(shell uname)-$(shell uname -m)
	cp -r $^ dist/netscapesecuritywrapper-$(VERSION)-$(shell uname)-$(shell uname -m)
	tar -C dist -zcvf $@ netscapesecuritywrapper-$(VERSION)-$(shell uname)-$(shell uname -m)
	rm -rf dist
endif

NetscapeSecurityWrapper: $(COMMON) apple.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

NetscapeSecurityWrapper.plugin: NetscapeSecurityWrapper
	install -d $@/Contents/MacOS
	install -v $^ $@/Contents/MacOS
	install -c Info.plist $@/Contents/
	sed -i "" 's/%Version%/$(VERSION)/g' $@/Contents/Info.plist
	rm $^

netscapesecuritywrapper.so: $(COMMON) linux.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^


clean:
	rm -rf *.so *.o third_party/*/*.o
	rm -rf *.plugin
	rm -rf *.dmg ._*.dmg
	rm -rf *.tar.gz
	rm -rf dist
