NAME      = gsclu
VERSION   = 0.7.1

# diet = 1

ifneq ($(diet),)
DIET      = /opt/diet
CC        = $(DIET)/bin/diet gcc
MOREFLAGS = -isystem $(DIET)/include
LIBRESOLV =
LDFLAGS   = -L/opt/diet/lib
else
CC        = gcc
LIBRESOLV = -lresolv
endif

LD        = $(CC)
SILENT    = @

INDENT    = indent -kr -i2 -ts8 -di1 -l80

CFLAGS   += -Wcast-align -Wall -Wsign-compare -Wpointer-arith -Wstrict-aliasing
CFLAGS   += -Os -fomit-frame-pointer
CFLAGS   += -ffunction-sections -fdata-sections
CFLAGS   += -DVERSION=\"$(NAME)-$(VERSION)\" -g
CFLAGS   += -Igtget -Istr -fno-inline 

LIBSSL  = -lpolarssl

LIBSTR    = str/libstr.a
LIBTIO    = tio/libtio.a

STRSRC    = $(wildcard str/*.c)

GTGETSRC  = gtget/check_cn.c gtget/gtget.c gtget/gtget_config.c
GTGETSRC += gtget/gtget_io.c gtget/gtget_utils.c gtget/timer_start.c
GTGETSRC += gtget/timer_stop.c
GTGETSRC += gtget/gtget_polarssl.c
GTGETOBJ  = $(patsubst %.c,%.o,$(GTGETSRC))

SOURCES   = read_write.c read_write.h ps.c mimencode.c attributes.h mmapfile.c mmapfile.h
SOURCES  += tunctl.c certinfo.c sstrip.c rblq.c rbld.c wakelan.c sievectl.c
SOURCES  += $(STRSRC) $(GTGETSRC)
SOURCES  += $(wildcard gtget/*.h) $(wildcard str/*.h)

PROGRAMS  = ps mimencode gtget tunctl rblq rbld wakelan sievectl # certinfo
TARGETS   = $(patsubst %,bin/%,$(PROGRAMS))

include rules.mk

DIRS = bin .objs

export CC CFLAGS LDFLAGS SILENT

.PHONY: tags

.objs/%.o: %.c
	$(THECC) -Istr -Igtget -I$(POLARSSL)/include $(CFLAGS) $(CPPFLAGS) -o $@ -c $^

gtget/%.o: gtget/%.c
	$(THECC) -Istr -Igtget -I$(POLARSSL)/include $(CFLAGS) $(CPPFLAGS) -o $@ -c $^

%: .objs/%.o
	$(THELD) $(LDFLAGS) -o $@ $^ $(LIBS)

all: config.h $(DIRS) $(TARGETS) bin/sstrip
	@ls -lh $(TARGETS)

static: LDFLAGS = -static -Wl,--gc-sections
static: all

bin:
	@mkdir -p $@

.objs:
	@mkdir -p $@

gsclu.spec: Makefile gsclu.spec.in
	@sed -e "s/@VERSION@/$(VERSION)/" gsclu.spec.in > gsclu.spec

config.h: configure
	sh configure

$(LIBSTR):
	$(MAKE) -C str

bin/%: %.c
	$(THELD) $(CFLAGS) $(LDFLAGS) -o $@ $^

bin/ps: .objs/read_write.o .objs/ps.o
	$(THELD) $(LDFLAGS) -o $@ $^ $(LIBS)

bin/tunctl: .objs/tunctl.o
	$(THECC) $(LDFLAGS) -o $@ $^

bin/sievectl: .objs/sievectl.o .objs/tio.o
	$(THELD) $(LDFLAGS) -o $@ $^ $(LIBSSL) $(LIBRESOLV)

bin/gtget: $(GTGETOBJ) $(LIBSTR)
	$(THELD) $(LDFLAGS) -o $@ $^ $(LIBSSL) -lm

bin/rbld: .objs/rbld.o .objs/mmapfile.o
	$(THELD) $(LDFLAGS) -o $@ $^ $(LIBRESOLV)

clean:
	rm -rf .objs *.[oa] */*.[oa] core core.* $(TARGETS)
	$(MAKE) -C str clean

realclean: clean
	rm -f *~

dist: gsclu.spec
	mkdir $(NAME)-$(VERSION)
	cp --parents Makefile configure str/Makefile CHANGES README*[^~] gsclu.spec $(SOURCES) $(NAME)-$(VERSION)
	tar -cjf $(NAME)-$(VERSION).tar.bz2 $(NAME)-$(VERSION)
	rm -rf $(NAME)-$(VERSION)


strip: $(TARGETS) bin/sstrip
	for i in $(TARGETS); do bin/sstrip $$i; done
	@ls -lh $(TARGETS)

install: $(TARGETS)
	mkdir -p $(DESTDIR)/bin
	mkdir -p $(DESTDIR)/etc/gtget
	cp $(TARGETS) $(DESTDIR)/bin

installstrip: strip install

uninstall:
	cd $(DESTDIR)/bin && rm -f $(TARGETS)

indent:
	$(INDENT) *.[ch] */*.[ch]

tags: $(SOURCES)
	ctags -R --exclude="*.html" --exclude=".svn" --exclude="*.xml" .

