#CROSSPATH	:= $(CROSS)
CC	:= $(CROSS_COMPILE)gcc
STRIP	:= $(CROSS_COMPILE)strip --strip-all
MAKE	:= make

#mingw cross-compiler toolchains
MCC	:= i586-mingw32msvc-gcc
MSTRIP	:= i586-mingw32msvc-strip --strip-all
WCC	:= i686-pc-mingw32-gcc
WSTRIP	:= i686-pc-mingw32-strip --strip-all

# extra flags
CFLAGS	+=
LDFLAGS	+=

# cflags

WIN_CFLAGS 	+= -Wall -Wshadow -Os -DWIN32
WINMAIN_CFLAGS	+= -mwindows -Wall -Wshadow -Os -DWIN32 -DWINMAIN
UNIX_CFLAGS	+= -Wall -Wshadow -Os
UNIX32_CFLAGS	+= -Wall -Wshadow -Os -m32 -march=i386

# ldflags

WIN_LDFLAGS	+= -s -lwsock32
UNIX_LDFLAGS	+= -s
SUNOS_LDFLAGS	+= -s -lresolv -lsocket -lnsl

# make install (for unix-like only)
INSTALL	:= install
PREFIX	:= /usr/local
BINDIR	:= bin

#################################

out := dbd
outbg := dbdbg

files = pel.c aes.c sha1.c doexec.c dbd.c

#################################

none:
	@echo "usage:"
	@echo "  make unix         - Linux, NetBSD, FreeBSD, OpenBSD"
	@echo "  make unix32       - Linux, NetBSD, FreeBSD, OpenBSD 32-bit"
	@echo "  make sunos        - SunOS (Solaris)"
	@echo "  make win32        - native win32 console app (w/ Cygwin + MinGW)"
	@echo "  make win32bg      - create a native win32 no-console app (w/ Cygwin + MinGW)"
	@echo "  make win32bg CFLAGS=-DSTEALTH - stealthy no-console app"
	@echo "  make mingw        - native win32 console app (w/ MinGW MSYS)"
	@echo "  make mingwbg      - native win32 no-console app (w/ MinGW MSYS)"
	@echo "  make mingwbg CFLAGS=-DSTEALTH - stealthy no-console app (w/ MinGW MSYS)"
	@echo "  make cygwin       - Cygwin console app"
	@echo "  make darwin       - Darwin"
	@echo ""
	@echo "cross-compile options:"
	@echo "  make mingw-cross    - win32 cross compile (i586-mingw32msvc-gcc)"
	@echo "  make mingwbg-cross  - win32 no-console cross compile (i586-mingw32msvc-gcc)"
	@echo "  make mingwbg-cross CFLAGS=-DSTEALTH - stealthy win32 cross compile"
	@echo "  make unix CROSS_COMPILE=<"path/to/toolchain-"> - cross compile for any arch"
	@echo ""
	@echo "roll up a tarball (move your compiled stuff to binaries/ first:"
	@echo "  make dist         - create tarball with source files, readme, and binaries/"

unix: clean
	$(CC) $(UNIX_CFLAGS) $(CFLAGS) -o $(out) $(files) $(UNIX_LDFLAGS) $(LDFLAGS)

unix32: clean
	$(CC) $(UNIX32_CFLAGS) $(CFLAGS) -o $(out) $(files) $(UNIX_LDFLAGS) $(LDFLAGS)

sunos: clean
	@echo "*** tested on SunOS 5.9 x86 and r220 ***"
	$(CC) $(UNIX_CFLAGS) $(CFLAGS) -o $(out) $(files) $(SUNOS_LDFLAGS) $(LDFLAGS)

cygwin: unix

win32: cygmingw
windows: cygmingw
win32bg: cygmingwbg

#cygmingw: CROSS_COMPILE	:= i686-pc-mingw32-
cygmingw: clean
	$(WCC) $(WIN_CFLAGS) $(CFLAGS) -o $(out) $(files) $(WIN_LDFLAGS) $(LDFLAGS)
	$(WSTRIP) $(out)

#cygmingwbg: override CROSS_COMPILE        := i686-pc-mingw32-
cygmingwbg: clean
	$(WCC) $(WINMAIN_CFLAGS) $(CFLAGS) -o $(outbg) $(files) $(WIN_LDFLAGS) $(LDFLAGS)
	$(WSTRIP) $(outbg)

mingw: clean
	$(CC) $(WIN_CFLAGS) $(CFLAGS) -o $(out) $(files) $(WIN_LDFLAGS) $(LDFLAGS)

mingwbg: clean
	$(CC) $(WINMAIN_CFLAGS) $(CFLAGS) -o $(outbg) $(files) $(WIN_LDFLAGS) $(LDFLAGS)

darwin: clean
	$(CC) $(UNIX_CFLAGS) $(CFLAGS) -o $(out) $(files) $(LDFLAGS)
	$(STRIP) $(out)

#mingw-cross: CROSS_COMPILE = i586-mingw32msvc-
mingw-cross: clean
	$(MCC) $(WIN_CFLAGS) $(CFLAGS) -o $(out).exe $(files) $(WIN_LDFLAGS) $(LDFLAGS)
	$(MSTRIP) $(out).exe

#mingwbg-cross: override CROSS_COMPILE     := i586-mingw32msvc-
mingwbg-cross: clean
	$(MCC) $(WINMAIN_CFLAGS) $(CFLAGS) -o $(outbg).exe $(files) $(WIN_LDFLAGS) $(LDFLAGS)
	$(MSTRIP) $(outbg).exe

distclean: clean

clean:
	rm -f $(out) $(out).exe $(outbg) $(outbg).exe *.o core

install:
	$(INSTALL) -m 755 -d $(PREFIX)/$(BINDIR)
	$(INSTALL) -c -m 755 $(out) $(PREFIX)/$(BINDIR)/

uninstall:
	rm -f $(PREFIX)/$(BINDIR)/$(out)

dist:
	@./mktarball.sh
