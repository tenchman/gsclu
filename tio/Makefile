#Makefile for libtio

include ../rules.mk

CC      ?= i386-dietlibc-linux-gcc
CFLAGS	?= -std=c99 -O2 -pipe -Wall -g
LDFLAGS	?= 
OBJDIR  = .objs
LIBDIR  = .
WARNS   = -Wsystem-headers -Werror -Wall -Wno-format-y2k -W       \

SOURCES = $(wildcard *.c)
HEADERS = $(wildcard *.h)

STATICLIB= $(LIBDIR)/libtio.a
SHAREDLIB= $(LIBDIR)/libtio.so

OBJS    = $(patsubst %.c, $(OBJDIR)/%.o, $(SOURCES))

LIBS    = $(STATICLIB) $(SHAREDLIB)

TARGETS = $(STROBJ) $(LIBS) installlibslocal installheaderslocal

all:	$(OBJDIR) $(STATICLIB)

$(OBJDIR):
	mkdir $(OBJDIR)

$(STATICLIB): $(SOURCES) $(OBJS)
	$(THEAR) cru $@ $(OBJS) 2>/dev/null
	$(THERL) $@ 2>/dev/null


$(OBJDIR)/%.o: %.c
	$(THECC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -o $@ -c $^

clean:
	rm -rf $(OBJDIR) $(STATICLIB)
