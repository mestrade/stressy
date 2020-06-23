AC_DEFUN([DOXYGEN_BIN],[
        AC_ARG_VAR([DOXYGEN], [Full path to doxygen binary.])
        AC_PATH_PROG([DOXYGEN], [doxygen],,)

        if test "x$DOXYGEN" = 'x'; then
            AC_MSG_WARN([*** doxygen not found, docs will not be available])
        fi

        AM_CONDITIONAL(HAVE_DOXYGEN, test "x$DOXYGEN" != 'x')

        AC_SUBST([DOXYGEN])
])

AC_DEFUN([FULL_STATIC], [
        AC_MSG_CHECKING([for full static binary])

        AC_ARG_ENABLE([full-static],[AC_HELP_STRING([--enable-full-static],
                    [compile stressy as non dynamic executable (default=no)])],
                    [ac_cv_use_full_static=$enableval], [ac_cv_use_full_static=no]
        )

        AM_CONDITIONAL(HAVE_FULL_STATIC, test yes == "$ac_cv_use_full_static")

        if test no == "$ac_cv_use_full_static"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_FULL_STATIC, [yes], [Define to 1 to enable full static mode])
                AC_MSG_RESULT([yes])
        fi
])
AC_DEFUN([MOD_FUZZER], [
        AC_MSG_CHECKING([for fuzzer module])

        AC_ARG_ENABLE([fuzzer],[AC_HELP_STRING([--enable-fuzzer],
                    [enable fuzzer module (default=yes)])],
                    [ac_cv_use_fuzzer=$enableval], [ac_cv_use_fuzzer=yes]
        )

        AM_CONDITIONAL(HAVE_FUZZER, test yes == "$ac_cv_use_fuzzer")

        if test no == "$ac_cv_use_fuzzer"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_FUZZER, [yes], [Define to 1 to enable])
        	AC_MSG_RESULT([yes])
	fi
])
AC_DEFUN([MOD_REQUEST_CHECK], [
        AC_MSG_CHECKING([for request check module])

        AC_ARG_ENABLE([request_check],[AC_HELP_STRING([--enable-request_check],
                    [enable request_check module (default=yes)])],
                    [ac_cv_use_request_check=$enableval], [ac_cv_use_request_check=yes]
        )

        AM_CONDITIONAL(HAVE_REQUEST_CHECK, test yes == "$ac_cv_use_request_check")

        if test no == "$ac_cv_use_request_check"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_REQUEST_CHECK, [yes], [Define to 1 to enable])
        fi
])
AC_DEFUN([MOD_DISCOVERY], [
        AC_MSG_CHECKING([for discovery module])

        AC_ARG_ENABLE([discovery],[AC_HELP_STRING([--enable-discovery],
                    [enable discovery module (default=yes)])],
                    [ac_cv_use_discovery=$enableval], [ac_cv_use_discovery=yes]
        )

        AM_CONDITIONAL(HAVE_DISCOVERY, test yes == "$ac_cv_use_discovery")

        if test no == "$ac_cv_use_discovery"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_DISCOVERY, [yes], [Define to 1 to enable])
                AC_MSG_RESULT([yes])
        fi
])
AC_DEFUN([MOD_BASIC_AUTH_BRUTEFORCE], [
        AC_MSG_CHECKING([for basic_auth_bruteforce module])

        AC_ARG_ENABLE([basic_auth_bruteforce],[AC_HELP_STRING([--enable-basic_auth_bruteforce],
                    [enable basic_auth_bruteforce (default=yes)])],
                    [ac_cv_use_basic_auth_bruteforce=$enableval], [ac_cv_use_basic_auth_bruteforce=yes]
        )

        AM_CONDITIONAL(HAVE_BASIC_AUTH_BRUTEFORCE, test yes == "$ac_cv_use_basic_auth_bruteforce")

        if test no == "$ac_cv_use_basic_auth_bruteforce"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_BASIC_AUTH_BRUTEFORCE, [yes], [Define to 1 to enable])
                AC_MSG_RESULT([yes])
        fi
])
AC_DEFUN([MOD_FORM_AUTH_BRUTEFORCE], [
        AC_MSG_CHECKING([for form_auth_bruteforce module])

        AC_ARG_ENABLE([form_auth_bruteforce],[AC_HELP_STRING([--enable-form_auth_bruteforce],
                    [enable form_auth_bruteforce (default=yes)])],
                    [ac_cv_use_form_auth_bruteforce=$enableval], [ac_cv_use_form_auth_bruteforce=yes]
        )

        AM_CONDITIONAL(HAVE_FORM_AUTH_BRUTEFORCE, test yes == "$ac_cv_use_form_auth_bruteforce")

        if test no == "$ac_cv_use_form_auth_bruteforce"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_FORM_AUTH_BRUTEFORCE, [yes], [Define to 1 to enable])
                AC_MSG_RESULT([yes])
        fi
])
AC_DEFUN([MOD_HEXA_ENCODER], [
        AC_MSG_CHECKING([for hexa encoder module])

        AC_ARG_ENABLE([hexa_encoder],[AC_HELP_STRING([--enable-hexa_encoder],
                    [enable hexa module (default=yes)])],
                    [ac_cv_use_hexa_encoder=$enableval], [ac_cv_use_hexa_encoder=yes]
        )

        AM_CONDITIONAL(HAVE_HEXA_ENCODER, test yes == "$ac_cv_use_hexa_encoder")

        if test no == "$ac_cv_use_hexa_encoder"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_HEXA_ENCODER, [yes], [Define to 1 to enable])
                AC_MSG_RESULT([yes])
        fi
])
AC_DEFUN([MOD_VAR_STRESS], [
        AC_MSG_CHECKING([for var_stress module])

        AC_ARG_ENABLE([var_stress],[AC_HELP_STRING([--enable-var_stress],
                    [disable var stress module (default=yes)])],
                    [ac_cv_use_var_stress=$enableval], [ac_cv_use_var_stress=yes]
        )

        AM_CONDITIONAL(HAVE_VAR_STRESS, test yes == "$ac_cv_use_var_stress")

        if test no == "$ac_cv_use_var_stress"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_VAR_STRESS, [yes], [Define to 1 to enable VAR_STRESS MODULE])
                AC_MSG_RESULT([yes])
        fi
])
AC_DEFUN([MOD_CRAWLER2], [
        AC_MSG_CHECKING([for crawler2 module])

        AC_ARG_ENABLE([crawler2],[AC_HELP_STRING([--enable-crawler2],
                    [disable crawler2 module (default=yes)])],
                    [ac_cv_use_crawler2=$enableval], [ac_cv_use_crawler2=yes]
        )

        AM_CONDITIONAL(HAVE_CRAWLER2, test yes == "$ac_cv_use_crawler2")

        if test no == "$ac_cv_use_crawler2"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_CRAWLER2, [yes], [Define to 1 to enable])
                AC_MSG_RESULT([yes])
        fi
])

AC_DEFUN([MOD_CRAWLER], [
        AC_MSG_CHECKING([for crawler module])

        AC_ARG_ENABLE([crawler],[AC_HELP_STRING([--enable-crawler],
                    [disable crawler module (default=no)])],
                    [ac_cv_use_crawler=$enableval], [ac_cv_use_crawler=no]
        )

        AM_CONDITIONAL(HAVE_CRAWLER, test yes == "$ac_cv_use_crawler")

        if test no == "$ac_cv_use_crawler"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_CRAWLER, [yes], [Define to 1 to enable])
                AC_MSG_RESULT([yes])
        fi

])

AC_DEFUN([MOD_ERR_DETECT], [
        AC_MSG_CHECKING([for error detection module])

        AC_ARG_ENABLE([error_detect],[AC_HELP_STRING([--enable-error_detect],
                    [disable error detection module (default=yes)])],
                    [ac_cv_use_error_detect=$enableval], [ac_cv_use_error_detect=yes]
        )

        AM_CONDITIONAL(HAVE_ERR_DETECT, test yes == "$ac_cv_use_error_detect")

        if test no == "$ac_cv_use_error_detect"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_ERR_DETECT, [yes], [Define to 1 to enable])
                AC_MSG_RESULT([yes])
        fi
])

AC_DEFUN([MOD_FORM_AUTO_FILL], [
        AC_MSG_CHECKING([for form auto fill module])

        AC_ARG_ENABLE([form_auto_fill],[AC_HELP_STRING([--enable-form_auto_fill],
                    [disable form auto fill module (default=yes)])],
                    [ac_cv_use_form_auto_fill=$enableval], [ac_cv_use_form_auto_fill=yes]
        )

        AM_CONDITIONAL(HAVE_FORM_AUTO_FILL, test yes == "$ac_cv_use_form_auto_fill")

        if test no == "$ac_cv_use_form_auto_fill"; then
                AC_MSG_RESULT([no])

        else
                AC_DEFINE(HAVE_FORM_AUTO_FILL, [yes], [Define to 1 to enable])
                AC_MSG_RESULT([yes])
        fi

])

AC_DEFUN([EFENCE],[
        AC_ARG_WITH(
                efence,
                [  --with-efence[=DIR]    enable_efence],
                ,
                [with_efence="no"]
        )

        AC_MSG_CHECKING(for enable efence)

        if test "$with_efence" = "no"; then
                AC_MSG_RESULT(Efence disabled)
        else
                AC_MSG_RESULT(Efence enabled)
                AC_DEFINE(HAVE_EFENCE, "YES", [define to 1 to enable efence])
                LIBS="-lefence $LIBS"
        fi
])

AC_DEFUN([MYSQLCLIENT],[
        AC_ARG_WITH(
                mysqlclient,
                [  --with-mysqlclient[=DIR]       enable_mysqlclient login],
                ,
                [with_mysqlclient="no"]
        )

        AC_MSG_CHECKING(for enable mysqlclient)

        if test "$with_mysqlclient" = "no"; then
                AC_MSG_RESULT(MySQL Logging disabled)
        else
                AC_MSG_RESULT(MySQL support enabled)
                AC_DEFINE(HAVE_MYSQLCLIENT, [YES], [define to 1 to enable efence])
                LIBS="-lmysqlclient $LIBS"
        fi
])

AC_DEFUN([APR_DIR], [
        AC_ARG_WITH([apr], AC_HELP_STRING([--with-apr=PATH],[Apache Portable Runtime Library installation directory]),
                ,
                [with_apr="no"]
        )

        AC_ARG_VAR([APR_CONFIG], [Full path to apr-1-config binary.])
        AC_PATH_PROG([APR_CONFIG], [apr-1-config], , [$with_apr/bin:$PATH])

        if test "x$APR_CONFIG" = 'x'; then
            AC_MSG_ERROR([apr-1-config executable not found.
**********
Please make sure you installed the developement files of APR-1.
You can try to add APR_CONFIG=/path/to/apr-1-config after ./configure
or you can also specify the apr installation prefix with --with-apr=/path/to/apr
**********])
        fi

        APR_CPPFLAGS="`$APR_CONFIG --cppflags --includes`"
        APR_LDADD="`$APR_CONFIG --link-ld`"
        AC_SUBST([APR_LDADD])
        AC_SUBST([APR_CPPFLAGS])
        AC_SUBST([APR_CONFIG])
        ])

AC_DEFUN([APR_UTIL_DIR], [
        AC_ARG_WITH([apr_util], AC_HELP_STRING([--with-apr-util=PATH],[Apache Portable Runtime Utility Library installation directory]),
                ,
                [with_apr_util="no"]
        )

        AC_ARG_VAR([APU_CONFIG], [Full path to apu-1-config binary.])
        AC_PATH_PROG([APU_CONFIG], [apu-1-config], , [$with_apr_util/bin:$PATH])

        if test "x$APU_CONFIG" = 'x'; then
            AC_MSG_ERROR([apu-1-config executable not found.
**********
Please make sure you installed the developement files of APR-UTIL-1.
You can try to add APU_CONFIG=/path/to/apu-1-config after ./configure
or you can specify the apr-util installation prefix with --with-apr-util=/path/to/apr-util
**********])
        fi

        APU_CPPFLAGS="`$APU_CONFIG --includes`"
        APU_LDADD="`$APU_CONFIG --link-ld`"
        AC_SUBST([APU_CPPFLAGS])
        AC_SUBST([APU_LDADD])
        AC_SUBST([APU_CONFIG])
        ])




AC_DEFUN([LIBXML2_DIR],[
        AC_ARG_WITH(
                libxml2,
                [  --with-libxml2[=DIR]   libxml2 directory],
                ,
                [with_libxml2="no"]
        )

        AC_MSG_CHECKING(for libxml2 directory)

        if test "$with_libxml2" = "no"; then
                if test -e /usr/lib/libxml2.so.2; then
                        AC_MSG_RESULT(libxml2 found in /usr/lib)
                        libxml2_dir=/usr
                else
                        AC_MSG_ERROR( You need to specify the libxml2 directory using --with-libxml2)
                fi
        else
                if test -e $with_libxml2/lib/libxml2.so; then
                        libxml2_dir=$with_libxml2
                        AC_MSG_RESULT(APR-UTIL found in $with_libxml2)
                else
                        AC_MSG_ERROR( $with_libxml2 not found.  Check the value you specified with --with-libxml2)
                fi

        fi

])

AC_DEFUN([CHECK_SSL], [
	AC_MSG_CHECKING(for OpenSSL)
	SSL_DIR=
	found_ssl="no"

	AC_ARG_WITH(ssl,
    		AC_HELP_STRING([--with-ssl],
       		[Use SSL (in specified installation directory)]),
    		[check_ssl_dir="$withval"],
    		[check_ssl_dir=]
	)

	for dir in $check_ssl_dir /usr /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local ; do
   		ssldir="$dir"
   		if test -f "$dir/include/openssl/ssl.h"; then
     			found_ssl="yes";
     			SSL_DIR="${ssldir}"
     			SSL_CFLAGS="-I$ssldir/include -I$ssldir/include/openssl";
     			break;
   		fi
   		if test -f "$dir/include/ssl.h"; then
     			found_ssl="yes";
     			SSL_DIR="${ssldir}"
     			SSL_CFLAGS="-I$ssldir/include/";
     			break
   		fi
	done

	AC_MSG_RESULT($found_ssl)
	if test x_$found_ssl != x_yes; then
   		AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find SSL libraries.
  Please install OpenSSL or specify installation directory with
  --with-ssl=(dir).
----------------------------------------------------------------------
		])

	else
        	printf "OpenSSL found in $ssldir\n";
		SSL_LIBS="-lssl -lcrypto";
        	SSL_LDFLAGS="-L$ssldir/lib";
		AC_DEFINE_UNQUOTED([HAVE_OPENSSL],[1],
	  		["Define to 1 if you want to use the OpenSSL crypto library"])
		AC_SUBST(SSL_CFLAGS)
		AC_SUBST(SSL_LDFLAGS)
		AC_SUBST(SSL_LIBS)
	fi
])


AC_DEFUN([OPENSSL_DIR],[
        AC_ARG_WITH(
                openssl,
                [  --with-openssl[=DIR]   OpenSSL directory],
                ,
                [with_openssl="no"]
        )

        AC_MSG_CHECKING(for openssl directory)

        if test "$with_openssl" = "no"; then
                if test -e /usr/lib/i386-linux-gnu/libssl.so; then
                        AC_MSG_RESULT(openssl found in /usr/lib)
                        openssl_dir=/usr
                        AC_DEFINE(HAVE_OPENSSL, [YES], [define to 1 to enable openssl])
                        LIBS="-lssl -lcrypto $LIBS"
                else
                        AC_MSG_RESULT(SSL Support disabled)
                fi
        else
                if test -e $with_openssl/lib/libssl.a; then
                        openssl_dir=$with_openssl
                        AC_MSG_RESULT(OPENSSL found in $with_openssl)
                        AC_DEFINE(HAVE_OPENSSL, [yes], [define to 1 to enable openssl])
                        LIBS="-lssl -lcrypto $LIBS"
                else
                        AC_MSG_ERROR( $with_openssl not found.  please put ssl directory with --with-openssl)
                fi

        fi

])

AC_DEFUN([PCRE_DIR], [
        AC_ARG_WITH([pcre], AC_HELP_STRING([--with-pcre=PATH],[Perl Regular complex expression Library installation directory]),
                ,
                [with_pcre="no"]
        )

        AC_ARG_VAR([PCRE_CONFIG], [Full path to pcre-config binary.])
        AC_PATH_PROG([PCRE_CONFIG], [pcre-config], , [$with_pcre/bin:$PATH])

        if test "x$PCRE_CONFIG" = 'x'; then
            AC_MSG_ERROR([pcre-config executable not found.
**********
Please make sure you installed the developement files of APR-1.
You can try to add PCRE_CONFIG=/path/to/pcre-config after ./configure
or you can also specify the apr installation prefix with --with-pcre=/path/to/pcre
**********])
        fi

        PCRE_CPPFLAGS="`$PCRE_CONFIG --cflags`"
        PCRE_LDADD="`$PCRE_CONFIG --libs`"
        AC_SUBST([PCRE_LDADD])
        AC_SUBST([PCRE_CPPFLAGS])
        AC_SUBST([PCRE_CONFIG])
        ])


