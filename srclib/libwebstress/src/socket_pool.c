/* Copyright 2007 Matthieu Estrade
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "socket_pool.h"
#include "config.h"
#include <stdlib.h>

#ifdef HAVE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#endif

#include "apr_hash.h"
#include "apr_strings.h"


typedef struct socket_hostname_pool_t socket_hostname_pool_t;

static int init_socket_item(apr_pool_t *pool, socket_pool_item_t *item);
static int socket_item_reconnect(socket_pool_t spool, socket_pool_item_t item, char *hostname, char *port);

#ifdef HAVE_OPENSSL
static int bio_filter_out_write(BIO *bio, const char *buff, int len);
static int bio_filter_in_read(BIO *bio, char *in, int inlen);
static int bio_filter_create(BIO *bio);
static int bio_filter_destroy(BIO *bio);
static int ssl_get_error_data(logs_t logs, const char **data);
static long bio_filter_out_ctrl(BIO *bio, int cmd, long num, void *ptr);
static BIO_METHOD *mem_bio_meth();

#endif

struct socket_hostname_pool {
	socket_pool_item_t *list;
};

struct socket_pool {

	apr_pool_t *pool;
	apr_thread_mutex_t *lock;

	int num_item;
	socket_pool_item_t *list;

	char *hostname;
	char *port;
	apr_sockaddr_t *sockaddr;
	apr_size_t transfered_bytes;
	apr_hash_t *hostname_hash;

	int connect_async;	
	int ssl;
#ifdef HAVE_OPENSSL
	SSL_CTX *ssl_ctx;
	BIO *bio_in;
	BIO *bio_out;
#endif	
	logs_t logs;
};

struct socket_pool_item {

	
	int num;
	apr_pool_t *pool;
	apr_pool_t *conn_pool;

	apr_thread_mutex_t *lock;
	apr_socket_t *sock;
	apr_sockaddr_t *sockaddr;

	int state;
	apr_size_t transfered_bytes;
	apr_time_t created_time;
	apr_time_t timeout;

	apr_time_t time_resolv;
	apr_time_t time_connect;
	apr_time_t time_end;

	socket_pool_t spool;
	
	int ssl;
#ifdef HAVE_OPENSSL
	SSL *ssl_ctx;
	/*
	 * In out data with ssl
	 *
	 */
	BIO *bio_in;
	BIO *bio_out;
#endif	
	
	int num_req;
	int max_req;


	logs_t logs;

};

extern int socket_item_get_time(socket_pool_item_t item, apr_time_t *resolv, apr_time_t *connect, apr_time_t *end)
{
	if (item == NULL) return -1;

	*resolv = item->time_resolv;
	*connect = item->time_connect;
	*end = item->time_end;

	return 0;
}

extern int socket_item_get_sock(socket_pool_item_t item, apr_socket_t **sock)
{
	if (!item || !item->sock) return -1;
	*sock = item->sock;
	return 0;
}

extern int socket_item_close(socket_pool_item_t item)
{
	if (!item) return -1;

	if (item->sock) {
		apr_socket_close(item->sock);
	}

	item->state = S_CLOSE;
	item->num_req = 0;
	item->spool->transfered_bytes += item->transfered_bytes;
	item->transfered_bytes = 0;

	apr_pool_destroy(item->conn_pool);
	item->conn_pool = NULL;	

	if (item->ssl == 1) {
#ifdef HAVE_OPENSSL
		if (item->ssl_ctx) SSL_free(item->ssl_ctx);
//		if (item->bio_in) BIO_free(item->bio_in);
//		if (item->bio_out) BIO_free(item->bio_out);
#endif
	}

	return 0;
}

extern int socket_pool_set_logs(socket_pool_t spool, logs_t logs)
{
	if (!spool || !logs) return -1;
	spool->logs = logs;
	return 0;
}

extern int set_item_close(socket_pool_item_t item)
{
	if (!item) return -1;
	item->state = S_CLOSE;
	return 0;
}

extern int set_item_connected(socket_pool_item_t item)
{
	if (!item) return -1;
	item->state = S_CONNECTED;
	return 0;
}

extern int socket_pool_init(apr_pool_t *pool, socket_pool_t *spool, int num_item, int use_ssl)
{
	socket_pool_t new;
	apr_pool_t *new_pool;

	if (num_item <= 0) return -1;
	
	if (!pool) return -1;
	apr_pool_create(&new_pool, pool);
	if (!new_pool) return -1;

	new = (socket_pool_t) apr_pcalloc(new_pool, sizeof(struct socket_pool));
	if (!new) return -1;

	new->num_item = num_item;
	new->list = (socket_pool_item_t *) apr_pcalloc(new_pool, num_item * sizeof(socket_pool_item_t));
	if (!new->list) return -1;
	new->pool = new_pool;
	new->transfered_bytes = 0;
	apr_thread_mutex_create(&new->lock, APR_THREAD_MUTEX_DEFAULT, new->pool);

	new->hostname_hash = apr_hash_make(new->pool);
	
	/*
	 * We are in an ssl socket pool
	 *
	 */
	new->ssl = use_ssl;
	if(new->ssl == 1) {
#ifdef HAVE_OPENSSL		
		new->ssl_ctx = SSL_CTX_new(SSLv23_method());
#endif
	}	
	*spool = new;
	return 0;
}


static int init_socket_item(apr_pool_t *pool, socket_pool_item_t *item)
{
	socket_pool_item_t new;

	if (!pool) return -1;
	
	new = (socket_pool_item_t)apr_pcalloc(pool, sizeof(struct socket_pool_item));
	if (!new) return -1;

	new->sock = NULL;
	new->sockaddr = NULL;
	apr_thread_mutex_create(&new->lock, APR_THREAD_MUTEX_DEFAULT, pool);
	
	/*
	 * Register the item as connclosed
	 *
	 */
	apr_pool_create(&new->pool, NULL);
	set_item_close(new);
	new->num_req = 0;
	*item = new;
	return 0;
}


static int socket_item_reconnect(socket_pool_t spool, socket_pool_item_t item, char *hostname, char *port)
{
	int dport = 80;
	apr_status_t rv;
	
	if (!item || !hostname) return -1;

	if (port) dport = atoi(port); 

	//fprintf(stderr, "Reconnect\n");

	item->time_resolv = apr_time_now();

	if (item->conn_pool != NULL) {
		LOG_ERR(CRIT, spool->logs, "The connection pool is not null and it should be :(");
	}

	apr_pool_create(&item->conn_pool, NULL);
	
	if (apr_socket_create(&item->sock, APR_INET, SOCK_STREAM, APR_PROTO_TCP, item->conn_pool) != APR_SUCCESS) {
		return -1;
	}

	apr_socket_opt_set(item->sock, APR_SO_REUSEADDR, 1);

	item->time_connect = apr_time_now();

	if ((rv = apr_socket_connect(item->sock, spool->sockaddr)) != APR_SUCCESS) {
		char errbuf[256];
		apr_strerror(rv, errbuf, sizeof(errbuf));
		LOG_ERR(CRIT, spool->logs, "Item %i is unable to connect %s:%i: %s\n", item->num, hostname, dport, errbuf);
		socket_item_close(item);
		return -1;
	}

	if (spool->ssl == 1) {
#ifdef HAVE_OPENSSL
		int ret = 0;

		item->ssl_ctx = SSL_new(spool->ssl_ctx);
		if (!item->ssl_ctx) {
			ssl_get_error_data(spool->logs, NULL);
			socket_item_close(item);
			return -1;
		}
	
		/*
		 * Create custom BIO to use existing read/write function
		 *
		 */
		item->bio_in = BIO_new(mem_bio_meth());
		BIO_set_data(item->bio_in, item);
		BIO_set_init(item->bio_in,  1);

                item->bio_out = BIO_new(mem_bio_meth());
		BIO_set_data(item->bio_out, item);
                BIO_set_init(item->bio_out,  1);

		/*
		 * Now setup the BIO on the ssl 
		 *
		 */	
		SSL_set_bio(item->ssl_ctx, item->bio_in, item->bio_out);
		
		if ((ret = SSL_connect(item->ssl_ctx)) < 0) {
			int err_no = 0;
			const char *err_msg = NULL;
			
			err_no = SSL_get_error(item->ssl_ctx, ret);
			ssl_get_error_data(spool->logs, &err_msg);
			socket_item_close(item);
			LOG_ERR(CRIT, item->logs, "SSL Error: %i", err_no);
			return -1;
		}
	
		if ((ret = SSL_accept(item->ssl_ctx)) < 0) {
			int err_no = 0;
			const char *err_msg = NULL;
			
			err_no = SSL_get_error(item->ssl_ctx, ret);
			ssl_get_error_data(spool->logs, &err_msg);
			socket_item_close(item);
			LOG_ERR(CRIT, item->logs, "SSL Error: %i", err_no);
			return -1;
		}
		
#else
		LOG_ERR(CRIT, spool->logs, "Unable to connect with ssl without ssl support\n");
		socket_item_close(item);
		return -1;
#endif
	}

	item->time_end = apr_time_now();

	return 0;
}


extern int socket_pool_setasync(socket_pool_t spool)
{
	if (spool == NULL) return -1;

	spool->connect_async = 1;
	return 0;
}

extern int socket_pool_start(socket_pool_t spool, char *hostname, char *port)
{
	int index = 0;

	if (!hostname || !port || spool == NULL) return -1;

	/*
	 * First create socket_pool_item list
	 *
	 */
	
	spool->hostname = apr_pstrdup(spool->pool, hostname);
	spool->port = apr_pstrdup(spool->pool, port);

	if (apr_sockaddr_info_get(&spool->sockaddr, hostname, APR_UNSPEC, atoi(spool->port), 
		APR_IPV4_ADDR_OK , spool->pool) != APR_SUCCESS) {
		return -1;
	}
	
	for (index = 0; index < spool->num_item; index++) {
		socket_pool_item_t new_item;
		
		if (init_socket_item(spool->pool, &new_item) < 0) {
			return -1;
		}
		new_item->ssl = spool->ssl;
		new_item->num = index;
		new_item->spool = spool;
		new_item->logs = spool->logs;	
	
		if (spool->connect_async != 1) {
			if (socket_item_reconnect(spool, new_item, hostname, port) < 0) return -1;
			LOG_ERR(DEBUG, spool->logs, "Socket[%i] connected", index);
			set_item_connected(new_item);
		}
		else {
			set_item_close(new_item);
		}
		//fprintf(stderr, "Socket item connected to %s:%s\n", hostname, port);
		spool->list[index] = new_item;
	}

        //fprintf(stderr, "Socket pool connected %i socket to %s:%s\n", spool->num_item, hostname, port);
	return 0;
}


extern int socket_item_acquire(socket_pool_t spool, socket_pool_item_t *s_item)
{
	int index = 0;

	if (!spool) {
		return -1;
	}

	LOG_ERR(DEBUG, spool->logs, "Searching for a new socket");
	apr_thread_mutex_lock(spool->lock);

	LOG_ERR(DEBUG, spool->logs, "Socket pool locked (%p)", spool);
	for (index = 0; index < spool->num_item; index++) {
		apr_status_t rv;
		socket_pool_item_t item;

		if (!spool->list[index]) continue;
		item = spool->list[index];

		rv = apr_thread_mutex_trylock(item->lock);
		if (APR_STATUS_IS_EBUSY(rv)) continue;
	
		if (item->state == S_CLOSE) {
			LOG_ERR(DEBUG, spool->logs, "Reconnecting socket...");
			if (socket_item_reconnect(spool, item, spool->hostname, spool->port) < 0) {
				apr_thread_mutex_unlock(item->lock);
				continue;
			}
			set_item_connected(item);
		}
		
		*s_item = item;
		item->num_req++;
		LOG_ERR(DEBUG, spool->logs, "Found a new socket !");
		apr_thread_mutex_unlock(spool->lock);
		return 0;
	}

	LOG_ERR(DEBUG, spool->logs, "Unable to get a new socket !");
	apr_thread_mutex_unlock(spool->lock);
	return -1;
}

extern int socket_item_release(socket_pool_t spool, socket_pool_item_t item)
{
	if (!spool || !item) return -1;
	apr_thread_mutex_lock(spool->lock);
	//fprintf(stderr, "Unlock item lock %i\n", item->num);
	apr_thread_mutex_unlock(item->lock);
	apr_thread_mutex_unlock(spool->lock);
	return 0;
}


extern int socket_item_read_direct(socket_pool_item_t item, char *data, apr_size_t *len)
{
	if (!item) return -1;
	apr_socket_recv(item->sock, data, len);
	return *len;
}

extern int socket_item_read_simple(socket_pool_item_t item, char *data, apr_size_t *len)
{
	if (!item) return -1;

	if (item->ssl == 1) {
#ifdef HAVE_OPENSSL
		if (!item->ssl_ctx) return -1;
		*len = SSL_read(item->ssl_ctx, data, *len);
		return *len;
#endif
	}
	apr_socket_recv(item->sock, data, len);
	return *len;
}

extern int socket_item_read(apr_pool_t *pool, socket_pool_item_t item, char **data, apr_size_t len)
{
	/*int read = 0;*/
	apr_size_t read_len = 0;
	char buff[SOCKET_MAX_READ];
	apr_status_t rv;
#ifdef HAVE_OPENSSL
	int read = 0;
#endif


	if (!pool | !item) {
		return -1;
	}
	if (len > SOCKET_MAX_READ) {
		return -1;
	}

	if (item->ssl == 1) {
#ifdef HAVE_OPENSSL		
		if (!item->ssl_ctx) return -1;
		
		read = SSL_read(item->ssl_ctx, buff, len);
		if (read < 0) {
			LOG_ERR(CRIT, item->logs, "Can't read from SSL_read: %i", read);
			return -1;
		}
		*data = apr_pstrndup(pool, buff, read);
		return read;
#endif	
	}
		
	read_len = len;
	memset(buff, 0, SOCKET_MAX_READ);
	rv = apr_socket_recv(item->sock, buff, &read_len);
	if (rv != APR_SUCCESS) {
		LOG_ERR(CRIT, item->logs, "Error reading data");
		return -1;
	}

	if (read_len == 0) {
		return 0;
	}
	
	*data = apr_pstrndup(pool, buff, read_len);
	item->transfered_bytes += read_len;
	return read_len;
}

extern int socket_item_write(socket_pool_item_t item, char *data, apr_size_t len)
{
	apr_size_t wrote = 0;
	
	if (!item) return -1;
	if (len <= 0) return 0;

	if (item->ssl == 1) {
#ifdef HAVE_OPENSSL	
		if (!item->ssl_ctx) return -1;
		wrote = SSL_write(item->ssl_ctx, data, len);
		return wrote;
#endif
	}


	if (item->sock == NULL) return -1;
	
	wrote = len;
	if (apr_socket_send(item->sock, data, &wrote) != APR_SUCCESS) return -1;

	item->transfered_bytes += wrote;
	return wrote;
}

extern int socket_item_write_direct(socket_pool_item_t item, const char *data, apr_size_t len)
{
	apr_size_t wrote = 0;
	
	if (!item) return -1;
	if (len <= 0) return 0;

	wrote = len;
	if (apr_socket_send(item->sock, data, &wrote) != APR_SUCCESS) return -1;

	item->transfered_bytes += wrote;
	return wrote;
}


extern int socket_item_read_line(apr_pool_t *pool, socket_pool_item_t item, char **data)
{
        char *line = NULL;
        int line_len = 0;
        int end_status = 0;
        char buf[2];
        apr_size_t byte;

	if (!pool) return -1;
	
        while (end_status != 2) {
		apr_status_t rv = APR_SUCCESS;
		byte = 1;

		if (item->ssl == 1) {
#ifdef HAVE_OPENSSL
			memset(buf, 0, 2);
			if (!item->ssl_ctx) return -1;
			byte = SSL_read(item->ssl_ctx, buf, byte);
			if (byte <= 0) {
				return -1;
			}
#endif
		}
		else {	
			memset(buf, 0, 2);
			rv = apr_socket_recv(item->sock, buf, &byte);
			if (rv != APR_SUCCESS && rv != APR_EOF) {
				char errbuff[120];
				apr_strerror(rv, errbuff, sizeof(errbuff));
				return -1;
			}
		}
		/*
		 * update byte counter
		 *
		 */
		item->transfered_bytes ++;

		if (buf[0] == '\r' && end_status == 0) {
                        end_status++;
                       	continue;
		}
		else if (buf[0] == '\n' && end_status == 1) {
                        end_status++;
                        continue;
		}
		else if (buf[0] =='\n') break;

		end_status = 0;
		
		if (!line) line = apr_pstrndup(pool, buf, 1);
		else line = apr_pstrcat(pool, line, buf, NULL);	
		line_len++;
	
		if (rv == APR_EOF) {
			break;
		}
	}

	if (!line || line_len == 0) return 0;
        *data = line;

	return line_len;
}

#ifdef HAVE_OPENSSL

static BIO_METHOD *mem_bio_meth() 
{
	BIO_METHOD *biom_in = NULL;

	biom_in = BIO_meth_new(BIO_TYPE_MEM, "stressy mem bio in");
        BIO_meth_set_write(biom_in, bio_filter_out_write);
        BIO_meth_set_read(biom_in, bio_filter_in_read);
        BIO_meth_set_create(biom_in, bio_filter_create);
        BIO_meth_set_destroy(biom_in, bio_filter_destroy);
	BIO_meth_set_ctrl(biom_in, bio_filter_out_ctrl);
	return biom_in;
}

static int bio_filter_in_read(BIO *bio, char *in, int inlen)
{
	socket_pool_item_t item = NULL;
	apr_size_t read = inlen;
	int bytes = 0;
	
	if (!bio) return 0;
	item = (socket_pool_item_t)BIO_get_data(bio);
	bytes = socket_item_read_direct(item, in, &read);
	
	return bytes;
}

static int bio_filter_out_write(BIO *bio, const char *buff, int len)
{
	socket_pool_item_t item = NULL;
	int bytes = 0;
	
	if (!bio) return 0;
	item = (socket_pool_item_t)BIO_get_data(bio);
	bytes = socket_item_write_direct(item, buff, len);
	
	return bytes;
}

static int bio_filter_create(BIO *bio)
{
    	BIO_set_init(bio,  1);
    	BIO_set_shutdown(bio, 1);
	return 1;
}

static int bio_filter_destroy(BIO *bio)
{
	if (bio == NULL) return 0;
	return 1;
}


static int ssl_get_error_data(logs_t logs, const char **data)
{
	unsigned long e;

	LOG_ERR(CRIT, logs, "SSL Error from: %s", *data);

	while ((e = ERR_get_error())) {
		char buff[256];
		ERR_error_string_n(e, buff, sizeof buff);
		LOG_ERR(CRIT, logs, "SSL Error: %s", buff);
	}
	return -1;
}

static long bio_filter_out_ctrl(BIO *bio, int cmd, long num, void *ptr)
{

        return 1;
}

#endif

