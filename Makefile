PROJECTROOT ?= ..
BUILDROOT   ?= $(PROJECTROOT)/build
CSHAREDDIR  ?= $(PROJECTROOT)/cshared
PROJECT      = fscrypt
DEBUG        = yes
packages     := openssl cshared
cflags      += -Wno-dangling-else -std=c99

alibs        = $(PROJECT)
solibs       = $(PROJECT)

sources       := fscrypt.c fsdatastorage.c

headers       := fscrypt.h fscrypt_plugins.h fsdatastorage.h

modules       := $(wildcard plugins/*)
defines       := FSCRYPT_HAVE_ENCRYPTION


include $(CSHAREDDIR)/common.mk
