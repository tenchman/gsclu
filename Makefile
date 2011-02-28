NAME      = gsclu
VERSION   = 0.5.1

SSLMODULE = polarssl

ARCH      = i386
DIET      = /opt/diet
CC        = $(DIET)/bin/$(ARCH)-tt-linux-dietlibc-gcc
SILENT    = @

KERNELINC = /lib/modules/$(shell uname -r)/build/include
MATRIX    = $(DIET)/include/matrixssl

INDENT    = indent -kr -i2 -ts8 -di1 -l80

CFLAGS    = -Wcast-align -Wpadded -Wall -Wsign-compare -Wpointer-arith -Wstrict-aliasing
CFLAGS   += -Os -fomit-frame-pointer
CFLAGS   += -ffunction-sections -fdata-sections -mpreferred-stack-boundary=2
CFLAGS   += -DVERSION=\"$(NAME)-$(VERSION)\" -g
CFLAGS   += -Igtget -Istr -fno-inline -isystem $(DIET)/include
LDFLAGS   = -static -Wl,--gc-sections

LIBSTR    = str/libstr.a

STRSRC    = $(wildcard str/*.c)
GTGET     = gtget
GTGETSRC  = gtget/check_cn.c gtget/gtget.c gtget/gtget_config.c
GTGETSRC += gtget/gtget_io.c gtget/gtget_utils.c gtget/timer_start.c
GTGETSRC += gtget/timer_stop.c

ifeq ($(SSLMODULE),matrixssl)
GTGETSRC += gtget/gtget_matrixssl.c gtget/sslSocket.c
SSLLIB    = -lmatrixssl
endif
ifeq ($(SSLMODULE),polarssl)
GTGETSRC += gtget/gtget_polarssl.c
SSLLIB    = -lpolarssl
endif

GTGETOBJ  = $(patsubst %.c,%.o,$(GTGETSRC))

SOURCES   = read_write.c read_write.h ps.c mimencode.c attributes.h mmapfile.c mmapfile.h
SOURCES  += tunctl.c certinfo.c sstrip.c rblq.c rbld.c wakelan.c
SOURCES  += typeinfo.c $(STRSRC) $(GTGETSRC)
SOURCES  += $(wildcard $(GTGET)/*.h) $(wildcard str/*.h)

PROGRAMS  = ps mimencode gtget health certinfo tunctl rblq rbld wakelan
PROGRAMS += xmlfilter typeinfo
TARGETS   = $(patsubst %,bin/%,$(PROGRAMS))
VIMAFTER  = ~/.vim/after/syntax

LINK    = @echo "  LINK    $@" ;
COMPILE = @echo "  COMPILE $@" ;

DIRS = bin .objs

export CC CFLAGS LDFLAGS SILENT

.PHONY: tags

.objs/%.o: %.c
	$(COMPILE)$(CC) -Istr -I$(GTGET) $(CFLAGS) $(CPPFLAGS) -o $@ -c $^

gtget/%.o: gtget/%.c
	$(COMPILE)$(CC) -Istr -I$(GTGET) $(CFLAGS) $(CPPFLAGS) -o $@ -c $^

%: .objs/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

all: config.h $(DIRS) $(TARGETS) bin/sstrip
	@ls -l $(TARGETS)

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
	$(LINK)$(CC) $(CFLAGS) -static -Wl,--gc-sections -o $@ $^

bin/ps: .objs/read_write.o .objs/ps.o
	$(LINK)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

bin/tunctl: .objs/tunctl.o
	$(LINK)$(CC) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS) -I$(KERNELINC) -o $@ $^

bin/typeinfo: .objs/typeinfo.o
	$(LINK)$(CC) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS) -o $@ $^ $(LIBSTR)

bin/xmlfilter: .objs/xmlfilter.o
	$(LINK)$(CC) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS) -o $@ $^

bin/health: .objs/health.o $(LIBSTR)
	$(LINK)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

bin/gtget: $(GTGETOBJ) $(LIBSTR) gtget/gtget.h
	$(LINK)$(CC) $(CFLAGS) -Istr -I$(GTGET) $(LDFLAGS) -o $@ $^ $(LIBS) $(SSLLIB) -lm -levent

bin/certinfo: .objs/certinfo.o $(LIBSTR)
	$(LINK)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS) -lmatrixssl

bin/rbld: .objs/rbld.o .objs/mmapfile.o
	$(LINK)$(CC) $(CFLAGS) -static -Wl,--gc-sections -o $@ $^

bin/menu: .objs/readkey.o .objs/menu.o
	$(LINK)$(CC) $(CFLAGS) -static -Wl,--gc-sections -o $@ $^

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
	@ls -l $(TARGETS)

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
	ctags -R --exclude="*.html" --exclude=".svn" --exclude="*.xml" . $(MATRIX)
 
 # Warning:
 #   "make syntax" will overwrite your ~/.vim/after/syntax/c.vim file.
syntax: tags
	[ -d $(VIMAFTER) ] || mkdir -p $(VIMAFTER)
	[ -f $(VIMAFTER)/c.vim ] && cp $(VIMAFTER)/c.vim $(VIMAFTER)/c.vim.new || :
	grep typedef tags| awk {'print "syn keyword cType "$$1'} >> $(VIMAFTER)/c.vim.new
	sort $(VIMAFTER)/c.vim.new |uniq > $(VIMAFTER)/c.vim && rm -f $(VIMAFTER)/c.vim.new

