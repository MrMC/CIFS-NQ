#
# NQ core makefile
#

## paths

SRCDIR	= .
INCDIR	= $(SRCDIR)
SYSDIR	= $(SRCDIR)/../linux
DEPDIR  = $(SRCDIR)/../../dep
OBJDIR	= $(SRCDIR)/../../obj
LIBDIR  = $(SRCDIR)/../../lib

## output

LIBNAME	= $(LIBDIR)/nqcore.a

## source files

CFILES	:= $(wildcard *.c)

## object and dependency files

OBJS    = $(addprefix $(OBJDIR)/, $(CFILES:.c=.o))
DEPS    = $(addprefix $(DEPDIR)/, $(CFILES:.c=.d))

## determine compile flags depending on NQDEBUG environment variable
## if it's defined set compiler flags to "no optimization" and debug info
## otherwise set maximum optimization level

ifdef NQDEBUG 
CCOPT=-g -O0
else
CCOPT=-O3
endif

## build-configuration info

RM      = rm -f
CC      = gcc
#WRFLAGS = -Wall
WRFLAGS = -Wall -Wconversion #-Wextra -Wsign-conversion -Wsign-compare -Wno-unused-parameter
#CCFLAGS = -Wall $(CCOPT) -fno-builtin -fno-defer-pop -c
CCFLAGS = $(WRFLAGS) $(CCOPT) -nostdlib -fno-builtin -fno-defer-pop -c
INCPATH = -I$(SRCDIR) -I$(SYSDIR)
COMPILE = $(CC) $(CCFLAGS) $(INCPATH)
MAKEDEP = $(CC) -MM $(INCPATH)
AR      = ar ru
LIB     = ranlib

## targets

all: $(OBJDIR) $(LIBDIR) $(LIBNAME)

clean:
	@echo Cleaning up NQ core files
	$(RM) $(OBJS)
	$(RM) $(DEPS)
	$(RM) $(LIBNAME)

deps: $(DEPDIR) $(DEPS)

$(OBJDIR):
	mkdir $(OBJDIR)

$(LIBDIR):
	mkdir $(LIBDIR)

$(DEPDIR):
	mkdir $(DEPDIR)

## build rules

$(LIBNAME): $(DEPS) $(OBJS)
	@echo Creating library $@...
	@$(AR) $@ $(OBJS)
	@$(LIB) $@

## object rules

$(OBJS): $(OBJDIR)/%.o: %.c $(DEPDIR)/%.d
##	@echo Compiling $<...
	@$(COMPILE) $< -o $@

## dependencies

$(DEPS): $(DEPDIR)

$(DEPS): $(DEPDIR)/%.d: %.c Makefile
##	@echo Creating dependencies for $<...
	@$(MAKEDEP) $< -o temp
	@sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < temp > $@
	@$(RM) temp

ifeq ($(MAKECMDGOALS),all)
-include $(DEPS)
endif
