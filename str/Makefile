#Makefile for libstr

CC      ?= i386-dietlibc-linux-gcc
CFLAGS	?= -std=c99 -O2 -pipe -Wall -g
LDFLAGS	?= 
OBJDIR  = .objs
LIBDIR  = .
WARNS   = -Wsystem-headers -Werror -Wall -Wno-format-y2k -W       \
          -Wstrict-prototypes -Wmissing-prototypes                \
          -Wpointer-arith -Wreturn-type -Wcast-qual               \
          -Wwrite-strings -Wswitch -Wshadow -Wcast-align          \
          -Wbad-function-cast -Wchar-subscripts -Winline          \
          -Wnested-externs -Wredundant-decls -std=c99

SOURCES = $(wildcard [^_]*.c)
HEADERS = $(wildcard *.h)

STATICLIB= $(LIBDIR)/libstr.a
SHAREDLIB= $(LIBDIR)/libstr.so

STRBUF  = $(shell grep "P_strbuf" _strbuf.c| sed -e "s/.*P_//")
STROBJ  = $(patsubst %, $(OBJDIR)/%.o, $(STRBUF))

OBJS    = $(patsubst %.c, $(OBJDIR)/%.o, $(SOURCES))
OBJS   += $(STROBJ)

LIBS    = $(STATICLIB) $(SHAREDLIB)

TARGETS = $(STROBJ) $(LIBS) installlibslocal installheaderslocal

all:	$(OBJDIR) $(STATICLIB)

$(OBJDIR):
	mkdir $(OBJDIR)

$(STATICLIB): $(SOURCES) $(OBJS)
	@if [ "$(SILENT)" = "@" ]; then echo "  AR      $@"; fi
	$(SILENT)ar cru $@ $(OBJS) 2>/dev/null
	@if [ "$(SILENT)" = "@" ]; then echo "  RANLIB  $@"; fi
	$(SILENT)ranlib $@ 2>/dev/null


$(OBJDIR)/%.o: %.c
	@if [ "$(SILENT)" = "@" ]; then echo "  CC      $@"; fi
	$(SILENT)$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -o $@ -c $^

$(OBJDIR)/strbuf_%.o: _strbuf.c strbuf.h
	@if [ "$(SILENT)" = "@" ]; then echo "  CC      $@"; fi
	$(SILENT)$(CC) -I. -D$(patsubst $(OBJDIR)/%.o,P_%,$@) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(STATICLIB)
