bin_PROGRAMS = stressy
lib_LTLIBRARIES = 

ACLOCAL_AMFLAGS=-I m4

AUTOMAKE_OPTIONS=foreign subdir-objects
SUBDIRS = srclib/libwebstress/ 
EXTRA_DIST = resources/*.txt resources/*.xml

##
## Define the sources files 
##
stressy_SOURCES =  src/modules_export.h src/global_apr.h \
			src/stressy_ctx.c src/stressy_ctx.h \
			src/request_tools.c src/request_tools.h \
			src/stressy_core_setup.c src/stressy_core_setup.h \
                        src/site_map.h src/site_map.c \
                        src/cli_setup.c src/cli_setup.h \
                        src/xml_setup.c src/xml_setup.h \
                        src/module.c src/module.h \
                        src/module_tools.c src/module_tools.h \
                        src/module_so.c src/module_so.h \
			src/util_xml.c src/util_xml.h \
			src/stressy.c src/stressy.h

#
# Check if module var stress is enabled
#
stressy_CPPFLAGS = @PCRE_CPPFLAGS@ @APR_CPPFLAGS@ @XML_CPPFLAGS@ @APU_CPPFLAGS@ -I$(topdir)src/ -I$(topdir)srclib/libwebstress/src/ -I${prefix}/include/ 
stressy_CFLAGS=-Wall -Werror -g -O2 -ggdb -pipe -Wpointer-arith
stressy_LDADD = @PCRE_LDADD@ @APR_LDADD@ @XML_LIBS@ @APU_LDADD@ -lxml2 -lwebstress -L${prefix}/lib/ -L$(topdir)srclib/libwebstress/.libs/ -lyajl -ljansson
stressy_LDFLAGS =  

if HAVE_FUZZER
stressy_SOURCES += modules/fuzzer/fuzzer.c modules/fuzzer/fuzzer.h	
endif

if HAVE_FORM_AUTH_BRUTEFORCE

stressy_SOURCES += modules/form_auth_bruteforce/form_auth_bruteforce.c modules/form_auth_bruteforce/form_auth_bruteforce.h

endif

if HAVE_BASIC_AUTH_BRUTEFORCE

stressy_SOURCES += modules/basic_auth_bruteforce/basic_auth_bruteforce.c modules/basic_auth_bruteforce/basic_auth_bruteforce.h

endif

if HAVE_HEXA_ENCODER

stressy_SOURCES += modules/hexa_encoder/hexa_encoder.c modules/hexa_encoder/hexa_encoder.h

endif

if HAVE_VAR_STRESS

stressy_SOURCES += modules/var_stress/var_stress.c modules/var_stress/var_stress.h

endif

if HAVE_ERR_DETECT

stressy_SOURCES += modules/error_detect/error_msg_detect.c modules/error_detect/error_msg_detect.h

endif

if HAVE_CRAWLER2

stressy_SOURCES += modules/crawler2/crawler.c modules/crawler2/crawler.h

endif

if HAVE_FORM_AUTO_FILL

stressy_SOURCES += modules/form_auto_fill/form_auto_fill.c modules/form_auto_fill/form_auto_fill.h

endif


if HAVE_CRAWLER

stressy_SOURCES += modules/crawler/html_parsing.c modules/crawler/html_parsing.h

endif

if HAVE_DISCOVERY

stressy_SOURCES += modules/discovery/discovery.c modules/discovery/discovery.h

endif

if HAVE_REQUEST_CHECK
stressy_SOURCES += modules/request_check/request_check.c modules/request_check/request_check.h
endif

if HAVE_FULL_STATIC
stressy_LDFLAGS += -all-static --enable-static-link 
endif

if HAVE_MACOSX
stressy_LDFLAGS += -bind_at_load
endif

install-conf:
	@echo "Create resources directory"
	@mkdir -p $(prefix)/resources/
	@echo "Copy stressy conf files into $(prefix)"
	@install -c -t $(prefix)/resources/ resources/*
	@tar cvzf stressy-macosx.tar.gz stressy-static-macosx resources/*
