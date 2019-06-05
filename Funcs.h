#pragma once

#include "Aliases.h"

typedef int CRYPTO_EX_new(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
	int idx, long argl, void* argp);
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA* to, CRYPTO_EX_DATA* from,
	void* from_d, int idx, long argl, void* argp);
typedef void (*DSO_FUNC_TYPE) (void);
typedef char* (*DSO_NAME_CONVERTER_FUNC)(DSO*, const char*);
typedef char* (*DSO_MERGER_FUNC)(DSO*, const char*, const char*);
typedef unsigned long (*dynamic_v_check_fn) (unsigned long ossl_version);
typedef int (*dynamic_bind_engine) (ENGINE* e, const char* id, const dynamic_fns* fns);
typedef int (*STORE_INITIALISE_FUNC_PTR) (STORE*);
typedef void (*STORE_CLEANUP_FUNC_PTR) (STORE*);
typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX* ctx);
typedef int (*STORE_STORE_OBJECT_FUNC_PTR) (STORE*, STORE_OBJECT_TYPES type,
	STORE_OBJECT* data,
	OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);
typedef int (*STORE_MODIFY_OBJECT_FUNC_PTR) (STORE*, STORE_OBJECT_TYPES type,
	OPENSSL_ITEM search_attributes[],
	OPENSSL_ITEM add_attributes[],
	OPENSSL_ITEM modify_attributes[],
	OPENSSL_ITEM delete_attributes[],
	OPENSSL_ITEM parameters[]);
typedef int (*STORE_HANDLE_OBJECT_FUNC_PTR) (STORE*, STORE_OBJECT_TYPES type,
	OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);
typedef int (*STORE_STORE_OBJECT_FUNC_PTR) (STORE*, STORE_OBJECT_TYPES type,
	STORE_OBJECT* data,
	OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);
typedef int (*STORE_STORE_OBJECT_FUNC_PTR) (STORE*, STORE_OBJECT_TYPES type,
	STORE_OBJECT* data,
	OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);
typedef int (*STORE_STORE_OBJECT_FUNC_PTR) (STORE*, STORE_OBJECT_TYPES type,
	STORE_OBJECT* data,
	OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);
typedef void* (*STORE_START_OBJECT_FUNC_PTR)(STORE*, STORE_OBJECT_TYPES type,
	OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);
typedef STORE_OBJECT* (*STORE_NEXT_OBJECT_FUNC_PTR)(STORE*, void* handle);
typedef int (*STORE_END_OBJECT_FUNC_PTR) (STORE*, void* handle);
typedef int (*STORE_GENERIC_FUNC_PTR) (STORE*, OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);
typedef int (*STORE_CTRL_FUNC_PTR) (STORE*, int cmd, long l, void* p,
	void (*f) (void));
typedef int (*ENGINE_CIPHERS_PTR) (ENGINE*, const EVP_CIPHER**,
	const int**, int);
typedef int (*ENGINE_DIGESTS_PTR) (ENGINE*, const EVP_MD**, const int**,
	int);
typedef int (*ENGINE_PKEY_METHS_PTR) (ENGINE*, EVP_PKEY_METHOD**,
	const int**, int);
typedef int (*ENGINE_PKEY_ASN1_METHS_PTR) (ENGINE*, EVP_PKEY_ASN1_METHOD**,
	const int**, int);
typedef int (*ENGINE_GEN_INT_FUNC_PTR) (ENGINE*);
typedef int (*ENGINE_CTRL_FUNC_PTR) (ENGINE*, int, long, void*,
	void (*f) (void));
typedef EVP_PKEY* (*ENGINE_LOAD_KEY_PTR)(ENGINE*, const char*,
	UI_METHOD* ui_method,
	void* callback_data);
typedef int (*ENGINE_SSL_CLIENT_CERT_PTR) (ENGINE*, SSL* ssl,
	STACK_OF(X509_NAME)* ca_dn,
	X509** pcert, EVP_PKEY** pkey,
	STACK_OF(X509)** pother,
	UI_METHOD* ui_method,
	void* callback_data);
typedef int (*GEN_SESSION_CB) (const SSL* ssl, unsigned char* id,
	unsigned int* id_len);
typedef int (*tls_session_ticket_ext_cb_fn) (SSL* s,
	const unsigned char* data,
	int len, void* arg);
typedef int (*tls_session_secret_cb_fn) (SSL* s, void* secret,
	int* secret_len,
	STACK_OF(SSL_CIPHER)* peer_ciphers,
	SSL_CIPHER** cipher, void* arg);
typedef void CRYPTO_EX_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
	int idx, long argl, void* argp);
