# Stressy - Web App Scanner
### an old project to scan and find security issues on web app

### Requirements

+ autoconf
+ automake
+ libtool
+ a C compiler
+ libapr and libaprutil from Apache

### Build

```
autoreconf -isf
./configure
make
make install
```

### Run

```
Using version  from /usr/local/stressy
[Tue Jun 23 14:12:37 2020][NOTICE] Loading modules from /usr/local/stressy/libexec/stressy/
[Tue Jun 23 14:12:37 2020][NOTICE] Loading builtin modules
[Tue Jun 23 14:12:37 2020][NOTICE] Init module: mod_crawler2
[Tue Jun 23 14:12:37 2020][NOTICE] Init module: mod_var_stress
[Tue Jun 23 14:12:37 2020][NOTICE] Init module: mod_error_detect
[Tue Jun 23 14:12:37 2020][NOTICE] Init module: mod_form_auto_fill
[Tue Jun 23 14:12:37 2020][NOTICE] Init module: mod_discovery
[Tue Jun 23 14:12:37 2020][NOTICE] Init module: mod_hexa_encoder
[Tue Jun 23 14:12:37 2020][NOTICE] Init module: mod_form_auth_bruteforce
[Tue Jun 23 14:12:37 2020][NOTICE] Init module: mod_parameter_fuzzer
-hostname=www.domain.com for the web application to scan
-uri=/start/uri to setup the first request uri
-port=80 of the web application to scan (default 80)
-ssl to enable ssl connections - set default port to 443
-proxy=proxy.isp.com of the proxy used to scan
-proxy-port=8080 of the proxy used to scan (default 8080)
-template=template.xml of the xml template file
-worker=16 of threads (default: 4)
-verbose=INFO can be DEBUG, WARN, NOTICE, INFO
-err-out=log_file containing error logs
-xml-out=out.xml of xml report
-request-sleep=5 number of second between request (per thread)
-redis-ip=10.0.0.1 ip of redis do get Scan setup from queue
-redis-port=6379 port of redis server (default: 6379)
-crawler2 enable crawler2
-crawler2_first_req make crawler2 add first request
-crawler2_basic_auth=login:password for a basic authentication
-crawler2_exclude=exclude_regexp
-var_stress_escape=var_escape_list.cfg containing char to escape variable content
-var_stress_insert=var_insert_list.cfg containing char to insert variable content
-var_stress_enable_cookie =var_insert_list.cfg containing char to insert variable content
-var_stress_enable_param =var_insert_list.cfg containing char to insert variable content
-var_stress_enable_urlencoded =var_insert_list.cfg containing char to insert variable content
-error_detect=error_file containing error detection pattern
-form_auto_fill=filename with variable auto fill definition
-form_auto_fill_unknown enable display of unsupported variables name
-brute_dir=directory_list.cfg to bruteforce directory
-hexa_encoder enable hexa_encoder
-hexa_encoder_uri enable hexa_encoder on uri
-hexa_encoder_var enable hexa_encoder on parameters
-hexa_encoder_headers enable hexa_encoder on headers
-form_auth_bruteforce=login/pass_file.xml enable form auth bruteforce
-form_auth_bruteforce_user_input=regexp to find username input
-form_auth_bruteforce_tolerance=number of word/lines to say the auth is valid
-basic_auth_bruteforce=login/pass_file.xml enable form auth bruteforce
-request_insert_dir=directory containing request definitions (.xml files)
-request_insert_file=file.xml containing request definitions
-request_insert_firefox=firefox.xml containing export request definitions from firefox
-fuzzer_setup=Parameter fuzzer config
-fuzzer_get Enable fuzzer on query string
-fuzzer_post Enable fuzzer on POST data
-fuzzer_cookies Enable fuzzer on cookies
-fuzzer_headers Enable fuzzer on headers
-fuzzer_xml Enable fuzzer on xml data
```

