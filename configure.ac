# Required initializer

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([src])
AC_INIT([stressy], m4_esyscmd([tr -d '\n' < VERSION]))
AC_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE([stressy], [tr -d '\n' < VERSION])

# Add a test for a compiler.
AC_PROG_CC
AM_PROG_LIBTOOL

AM_CONDITIONAL(HAVE_MACOSX, test yes == "$host")
if test "*apple-darwin*" == "$host"; then
	AC_DEFINE(HAVE_MACOSX, [yes], [Define to 1 to enable mac os x support])
	AC_MSG_RESULT(Mac os x support enabled)
else
	AC_MSG_RESULT(Mac os x support disabled)
fi

if test "$prefix" = "NONE"; then
	AC_MSG_RESULT(No prefix - use /usr/local/stressy)
	AC_DEFINE_UNQUOTED(STRESSY_BASE, "/usr/local/stressy",[define to 1 to enable])
else
	AC_DEFINE_UNQUOTED(STRESSY_BASE, "$prefix", [define to 1 to enable])
fi

AM_PATH_XML2([2.6.22],, [AC_MSG_ERROR([libxml2 >= 2.6.22 not found.])])

APR_DIR
APR_UTIL_DIR
EFENCE
PCRE_DIR
MYSQLCLIENT
CHECK_SSL
DOXYGEN_BIN

MOD_FUZZER
MOD_VAR_STRESS
MOD_CRAWLER2
MOD_CRAWLER
MOD_ERR_DETECT
MOD_FORM_AUTO_FILL
MOD_DISCOVERY
MOD_HEXA_ENCODER
MOD_FORM_AUTH_BRUTEFORCE
MOD_BASIC_AUTH_BRUTEFORCE
MOD_REQUEST_CHECK

FULL_STATIC

AC_SUBST(efence_dir)
AC_SUBST(mysqlclient)

# Write config.status and the Makefile
AC_CONFIG_FILES([Makefile
srclib/libwebstress/Makefile])
AC_OUTPUT

