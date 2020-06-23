lib_LTLIBRARIES = libwebstress.la 
check_PROGRAMS = check_libwebstress
TESTS = check_libwebstress 

AUTOMAKE_OPTIONS=foreign subdir-objects

##
## Define for libwebstress
##
libwebstress_la_SOURCES =  src/parsing_tools.h src/parsing_tools.c \
				src/variables.h src/variables.c \
				src/request.h src/request.c \
				src/socket_pool.h src/socket_pool.c \
				src/hook.h src/hook.c \
				src/logs.h src/logs.c \
				src/request_process.h src/request_process.c \
				src/setup.h src/setup.c \
				src/request_list.h src/request_list.c \
				src/worker.h src/worker.c 

libwebstress_la_CPPFLAGS = @PCRE_CPPFLAGS@ @APR_CPPFLAGS@ @XML_CPPFLAGS@ @SSL_CFLAGS@ -Isrc/
libwebstress_la_CFLAGS=-Wall -Werror  -g -O2 -ggdb -pipe -Wpointer-arith
libwebstress_la_LIBADD = @PCRE_LDADD@ @APR_LDADD@ @XML_LIBS@ @SSL_LIBS@ @SSL_LDFLAGS@

if HAVE_MACOSX
libwebstress_la_LDFLAGS = -bind_at_load
endif

include_HEADERS = src/parsing_tools.h src/variables.h src/request.h src/socket_pool.h src/hook.h src/logs.h src/request_process.h src/setup.h \
		 src/request_list.h src/worker.h

##
## Declaration for check libwebstress
##

check_libwebstress_SOURCES = tests/check_libwebstress.c tests/check_parsing_tools.c tests/check_request.c \
				tests/check_request_list.c

check_libwebstress_CPPFLAGS = @CHECK_CFLAGS@ @PCRE_CPPFLAGS@ @APR_CPPFLAGS@ @XML_CPPFLAGS@ -I$(top_srcdir)/src -DCHECKS_DIR=\"$(top_srcdir)/tests\"
check_libwebstress_CFLAGS=-Wall -Werror -g -O2 -ggdb -pipe -Wpointer-arith
check_libwebstress_LDADD = @CHECK_LIBS@ @PCRE_LDADD@ @APR_LDADD@ @XML_LIBS@ -L$(top_builddir) -lwebstress

dox: Doxyfile
if HAVE_DOXYGEN
	@echo "Building documentation"
	@@DOXYGEN@
else
	@echo "Doxygen not found at configure time. Abort."
endif

