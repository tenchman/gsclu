RANLIB ?= ranlib
AR     ?= ar

ifeq ($(V), 1)
THECC = $(CC)
THELD = $(LD)
THEAR = $(AR)
THERL = $(RANLIB)
VERBOSE = 
else
THECC = @echo "  CC     $@"; $(CC)
THELD = @echo "  LINK   $@"; $(LD)
THEAR = @echo "  AR     $@"; $(AR)
THERL = @echo "  RANLIB $@"; $(RANLIB)
VERBOSE = @
endif
