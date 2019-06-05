#pragma once

#include "Macros.h"

#pragma region enums

enum UI_string_types {
	UIT_NONE = 0,
	UIT_PROMPT,                 /* Prompt for a string */
	UIT_VERIFY,                 /* Prompt for a string and verify */
	UIT_BOOLEAN,                /* Prompt for a yes/no response */
	UIT_INFO,                   /* Send info to the user */
	UIT_ERROR                   /* Send an error message to the user */
};

#pragma endregion // enums

typedef struct ASN1_ITEM_st ASN1_ITEM;
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_pctx_st ASN1_PCTX;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ASN1_VALUE_st ASN1_VALUE;
typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
typedef struct bignum_ctx BN_CTX;
typedef struct bignum_st BIGNUM;
typedef struct bio_st BIO;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_gencb_st BN_GENCB;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct buf_mem_st BUF_MEM;
typedef struct comp_ctx_st COMP_CTX;
typedef struct comp_method_st COMP_METHOD;
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
typedef struct dsa_method DSA_METHOD;
typedef struct dsa_st DSA;
typedef struct dh_st DH;
typedef struct dh_method DH_METHOD;
typedef struct dso_st DSO;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_method_st EC_METHOD;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
typedef struct ecdh_method ECDH_METHOD;
typedef struct ecdsa_method ECDSA_METHOD;
typedef struct engine_st ENGINE;
typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;
typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;
typedef struct rand_meth_st RAND_METHOD;
typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_st SSL;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_session_st SSL_SESSION;
typedef struct store_st STORE;
typedef struct store_method_st STORE_METHOD;
typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;
typedef struct ui_st UI;
typedef struct ui_method_st UI_METHOD;
typedef struct ui_string_st UI_STRING;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_crl_st X509_CRL;
typedef struct x509_crl_method_st X509_CRL_METHOD;
typedef struct X509_name_st X509_NAME;
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;
typedef struct X509_POLICY_DATA_st X509_POLICY_DATA;
typedef struct X509_pubkey_st X509_PUBKEY;
typedef struct x509_revoked_st X509_REVOKED;
typedef struct x509_st X509;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct X509_VERIFY_PARAM_ID_st X509_VERIFY_PARAM_ID;
typedef struct st_ERR_FNS ERR_FNS;
typedef struct st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;
typedef struct CRYPTO_dynlock_value* (*dyn_dynlock_create_cb) (const char*, int);
typedef struct st_dynamic_data_ctx dynamic_data_ctx;

typedef void* (*dyn_MEM_malloc_cb) (size_t);
typedef void* (*dyn_MEM_realloc_cb) (void*, size_t);
typedef void (*dyn_MEM_free_cb) (void*);
typedef void (*dyn_lock_locking_cb) (int, int, const char*, int);
typedef void (*dyn_dynlock_lock_cb) (int, struct CRYPTO_dynlock_value*, const char*, int);
typedef void (*dyn_dynlock_destroy_cb) (struct CRYPTO_dynlock_value*, const char*, int);

typedef int ASN1_BOOLEAN;
typedef int (*dyn_lock_add_lock_cb) (int*, int, int, const char*, int);

#pragma region typedef enum
typedef enum STORE_object_types {
	STORE_OBJECT_TYPE_X509_CERTIFICATE = 0x01, /* X509 * */
	STORE_OBJECT_TYPE_X509_CRL = 0x02, /* X509_CRL * */
	STORE_OBJECT_TYPE_PRIVATE_KEY = 0x03, /* EVP_PKEY * */
	STORE_OBJECT_TYPE_PUBLIC_KEY = 0x04, /* EVP_PKEY * */
	STORE_OBJECT_TYPE_NUMBER = 0x05, /* BIGNUM * */
	STORE_OBJECT_TYPE_ARBITRARY = 0x06, /* BUF_MEM * */
	STORE_OBJECT_TYPE_NUM = 0x06 /* The amount of known object types */
} STORE_OBJECT_TYPES;

typedef enum STORE_certificate_status {
	STORE_X509_VALID = 0x00,
	STORE_X509_EXPIRED = 0x01,
	STORE_X509_SUSPENDED = 0x02,
	STORE_X509_REVOKED = 0x03
} STORE_CERTIFICATE_STATUS;

#pragma endregion // typedef enum

#pragma region typedef struct
typedef struct STORE_OBJECT_st {
	STORE_OBJECT_TYPES type;
	union {
		struct {
			STORE_CERTIFICATE_STATUS status;
			X509* certificate;
		} x509;
		X509_CRL* crl;
		EVP_PKEY* key;
		BIGNUM* number;
		BUF_MEM* arbitrary;
	} data;
} STORE_OBJECT;

typedef struct openssl_item_st {
	int code;
	void* value;                /* Not used for flag attributes */
	size_t value_size;          /* Max size of value for output, length for
								 * input */
	size_t* value_length;       /* Returned length of value for output */
} OPENSSL_ITEM;

typedef struct X509_VERIFY_PARAM_st {
	char* name;
	time_t check_time;          /* Time to use */
	unsigned long inh_flags;    /* Inheritance flags */
	unsigned long flags;        /* Various verify flags */
	int purpose;                /* purpose to check untrusted certificates */
	int trust;                  /* trust setting to check */
	int depth;                  /* Verify depth */
	STACK_OF(ASN1_OBJECT)* policies; /* Permissible policies */
	X509_VERIFY_PARAM_ID* id;   /* opaque ID data */
} X509_VERIFY_PARAM;

typedef struct ASN1_ENCODING_st {
	unsigned char* enc;         /* DER encoding */
	long len;                   /* Length of encoding */
	int modified;               /* set to 1 if 'enc' is invalid */
} ASN1_ENCODING;

typedef struct X509_val_st {
	ASN1_TIME* notBefore;
	ASN1_TIME* notAfter;
} X509_VAL;

typedef struct x509_cinf_st {
	ASN1_INTEGER* version;      /* [ 0 ] default of v1 */
	ASN1_INTEGER* serialNumber;
	X509_ALGOR* signature;
	X509_NAME* issuer;
	X509_VAL* validity;
	X509_NAME* subject;
	X509_PUBKEY* key;
	ASN1_BIT_STRING* issuerUID; /* [ 1 ] optional in v2 */
	ASN1_BIT_STRING* subjectUID; /* [ 2 ] optional in v2 */
	STACK_OF(X509_EXTENSION)* extensions; /* [ 3 ] optional in v3 */
	ASN1_ENCODING enc;
} X509_CINF;


typedef struct DSA_SIG_st {
	BIGNUM* r;
	BIGNUM* s;
} DSA_SIG;

typedef enum {
	/** the point is encoded as z||x, where the octet z specifies
	 *  which solution of the quadratic equation y is  */
	POINT_CONVERSION_COMPRESSED = 2,
	/** the point is encoded as z||x||y, where z is the octet 0x04  */
	POINT_CONVERSION_UNCOMPRESSED = 4,
	/** the point is encoded as z||x||y, where the octet z specifies
	 *  which solution of the quadratic equation y is  */
	POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef struct ec_extra_data_st {
	struct ec_extra_data_st* next;
	void* data;
	void* (*dup_func) (void*);
	void (*free_func) (void*);
	void (*clear_free_func) (void*);
} EC_EXTRA_DATA;                /* used in EC_GROUP */

typedef struct ECDSA_SIG_st {
	BIGNUM* r;
	BIGNUM* s;
} ECDSA_SIG;

typedef struct X509_crl_info_st {
	ASN1_INTEGER* version;
	X509_ALGOR* sig_alg;
	X509_NAME* issuer;
	ASN1_TIME* lastUpdate;
	ASN1_TIME* nextUpdate;
	STACK_OF(X509_REVOKED)* revoked;
	STACK_OF(X509_EXTENSION) /* [0] */* extensions;
	ASN1_ENCODING enc;
} X509_CRL_INFO;

typedef void bio_info_cb(struct bio_st*, int, const char*, int, long,
	long);

typedef struct bio_method_st {
	int type;
	const char* name;
	int (*bwrite) (BIO*, const char*, int);
	int (*bread) (BIO*, char*, int);
	int (*bputs) (BIO*, const char*);
	int (*bgets) (BIO*, char*, int);
	long (*ctrl) (BIO*, int, long, void*);
	int (*create) (BIO*);
	int (*destroy) (BIO*);
	long (*callback_ctrl) (BIO*, int, bio_info_cb*);
} BIO_METHOD;

typedef struct asn1_type_st {
	int type;
	union {
		char* ptr;
		ASN1_BOOLEAN boolean;
		ASN1_STRING* asn1_string;
		ASN1_OBJECT* object;
		ASN1_INTEGER* integer;
		ASN1_ENUMERATED* enumerated;
		ASN1_BIT_STRING* bit_string;
		ASN1_OCTET_STRING* octet_string;
		ASN1_PRINTABLESTRING* printablestring;
		ASN1_T61STRING* t61string;
		ASN1_IA5STRING* ia5string;
		ASN1_GENERALSTRING* generalstring;
		ASN1_BMPSTRING* bmpstring;
		ASN1_UNIVERSALSTRING* universalstring;
		ASN1_UTCTIME* utctime;
		ASN1_GENERALIZEDTIME* generalizedtime;
		ASN1_VISIBLESTRING* visiblestring;
		ASN1_UTF8STRING* utf8string;
		/*
		 * set and sequence are left complete and still contain the set or
		 * sequence bytes
		 */
		ASN1_STRING* set;
		ASN1_STRING* sequence;
		ASN1_VALUE* asn1_value;
	} value;
} ASN1_TYPE;

typedef struct otherName_st {
	ASN1_OBJECT* type_id;
	ASN1_TYPE* value;
} OTHERNAME;

typedef struct EDIPartyName_st {
	ASN1_STRING* nameAssigner;
	ASN1_STRING* partyName;
} EDIPARTYNAME;

typedef struct GENERAL_NAME_st {
# define GEN_OTHERNAME   0
# define GEN_EMAIL       1
# define GEN_DNS         2
# define GEN_X400        3
# define GEN_DIRNAME     4
# define GEN_EDIPARTY    5
# define GEN_URI         6
# define GEN_IPADD       7
# define GEN_RID         8
	int type;
	union {
		char* ptr;
		OTHERNAME* otherName;   /* otherName */
		ASN1_IA5STRING* rfc822Name;
		ASN1_IA5STRING* dNSName;
		ASN1_TYPE* x400Address;
		X509_NAME* directoryName;
		EDIPARTYNAME* ediPartyName;
		ASN1_IA5STRING* uniformResourceIdentifier;
		ASN1_OCTET_STRING* iPAddress;
		ASN1_OBJECT* registeredID;
		/* Old names */
		ASN1_OCTET_STRING* ip;  /* iPAddress */
		X509_NAME* dirn;        /* dirn */
		ASN1_IA5STRING* ia5;    /* rfc822Name, dNSName,
								 * uniformResourceIdentifier */
		ASN1_OBJECT* rid;       /* registeredID */
		ASN1_TYPE* other;       /* x400Address */
	} d;
} GENERAL_NAME;

typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;

typedef struct DIST_POINT_NAME_st {
	int type;
	union {
		GENERAL_NAMES* fullname;
		STACK_OF(X509_NAME_ENTRY)* relativename;
	} name;
	/* If relativename then this contains the full distribution point name */
	X509_NAME* dpname;
} DIST_POINT_NAME;

typedef struct x509_cert_aux_st {
	STACK_OF(ASN1_OBJECT)* trust; /* trusted uses */
	STACK_OF(ASN1_OBJECT)* reject; /* rejected uses */
	ASN1_UTF8STRING* alias;     /* "friendly name" */
	ASN1_OCTET_STRING* keyid;   /* key id of private key */
	STACK_OF(X509_ALGOR)* other; /* other unspecified info */
} X509_CERT_AUX;

typedef struct kssl_ctx_st {
	/*      used by:    disposition:            */
	char* service_name;         /* C,S default ok (kssl) */
	char* service_host;         /* C input, REQUIRED */
	char* client_princ;         /* S output from krb5 ticket */
	char* keytab_file;          /* S NULL (/etc/krb5.keytab) */
	char* cred_cache;           /* C NULL (default) */
	////krb5_enctype enctype;
	int length;
	////krb5_octet FAR* key;
} KSSL_CTX;

typedef const ASN1_ITEM* ASN1_ITEM_EXP(void);

typedef STORE_OBJECT* (*STORE_GET_OBJECT_FUNC_PTR)(STORE*,
	STORE_OBJECT_TYPES type,
	OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);

typedef struct ERR_string_data_st {
	unsigned long error;
	const char* string;
} ERR_STRING_DATA;

typedef struct crypto_threadid_st {
	void* ptr;
	unsigned long val;
} CRYPTO_THREADID;

typedef struct err_state_st {
	CRYPTO_THREADID tid;
	int err_flags[ERR_NUM_ERRORS];
	unsigned long err_buffer[ERR_NUM_ERRORS];
	char* err_data[ERR_NUM_ERRORS];
	int err_data_flags[ERR_NUM_ERRORS];
	const char* err_file[ERR_NUM_ERRORS];
	int err_line[ERR_NUM_ERRORS];
	int top, bottom;
} ERR_STATE;

typedef struct srp_ctx_st {
	/* param for all the callbacks */
	void* SRP_cb_arg;
	/* set client Hello login callback */
	int (*TLS_ext_srp_username_callback) (SSL*, int*, void*);
	/* set SRP N/g param callback for verification */
	int (*SRP_verify_param_callback) (SSL*, void*);
	/* set SRP client passwd callback */
	char* (*SRP_give_srp_client_pwd_callback) (SSL*, void*);
	char* login;
	BIGNUM* N, * g, * s, * B, * A;
	BIGNUM* a, * b, * v;
	char* info;
	int strength;
	unsigned long srp_Mask;
} SRP_CTX;

typedef struct st_dynamic_MEM_fns {
	dyn_MEM_malloc_cb malloc_cb;
	dyn_MEM_realloc_cb realloc_cb;
	dyn_MEM_free_cb free_cb;
} dynamic_MEM_fns;

typedef struct st_dynamic_LOCK_fns {
	dyn_lock_locking_cb lock_locking_cb;
	dyn_lock_add_lock_cb lock_add_lock_cb;
	dyn_dynlock_create_cb dynlock_create_cb;
	dyn_dynlock_lock_cb dynlock_lock_cb;
	dyn_dynlock_destroy_cb dynlock_destroy_cb;
} dynamic_LOCK_fns;

typedef struct st_dynamic_fns {
	void* static_state;
	const ERR_FNS* err_fns;
	const CRYPTO_EX_DATA_IMPL* ex_data_fns;
	dynamic_MEM_fns mem_fns;
	dynamic_LOCK_fns lock_fns;
} dynamic_fns;

typedef struct srtp_protection_profile_st {
	const char* name;
	unsigned long id;
} SRTP_PROTECTION_PROFILE;

typedef struct bignum_ctx_stack {
	/* Array of indexes into the bignum stack */
	unsigned int* indexes;
	/* Number of stack frames, and the size of the allocated array */
	unsigned int depth, size;
} BN_STACK;

struct bignum_st {
	BN_ULONG* d;                /* Pointer to an array of 'BN_BITS2' bit
								 * chunks. */
	int top;                    /* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;                   /* Size of the d array. */
	int neg;                    /* one if the number is negative */
	int flags;
};

typedef struct bignum_pool_item {
	/* The bignum values */
	BIGNUM vals[BN_CTX_POOL_SIZE];
	/* Linked-list admin */
	struct bignum_pool_item* prev, * next;
} BN_POOL_ITEM;

typedef struct bignum_pool {
	/* Linked-list admin */
	BN_POOL_ITEM* head, * current, * tail;
	/* Stack depth and allocation size */
	unsigned used, size;
} BN_POOL;

typedef struct ENGINE_CMD_DEFN_st {
	unsigned int cmd_num;       /* The command number */
	const char* cmd_name;       /* The command name itself */
	const char* cmd_desc;       /* A short description of the command */
	unsigned int cmd_flags;     /* The input the command expects */
} ENGINE_CMD_DEFN;

#pragma endregion // typedef struct
