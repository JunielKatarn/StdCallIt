#include <stdlib.h>
//#include <winnt.h>

#define BN_CTX_POOL_SIZE        16
# define STACK_OF(type) struct stack_st_##type
# define PREDECLARE_STACK_OF(type) STACK_OF(type);
# define EVP_MAX_IV_LENGTH               16
# define EVP_MAX_BLOCK_LENGTH            32
# define SSL_MAX_SID_CTX_LENGTH                  32
# define SSL_MAX_KEY_ARG_LENGTH                  8
# define SSL_MAX_MASTER_KEY_LENGTH               48
# define SSL_MAX_SSL_SESSION_ID_LENGTH           32
# define SSL_MAX_KRB5_PRINCIPAL_LENGTH  256
//#define X509_EXTENSIONS                     ((LPCSTR) 5)
# define ERR_NUM_ERRORS  16

//#  define BN_ULONG        unsigned long
//#  define BN_ULONG        unsigned long long
#  define BN_ULONG        unsigned int

# define SHA_DIGEST_LENGTH 20

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

# define LHASH_OF(type) struct lhash_st_##type

typedef void (*DSO_FUNC_TYPE) (void);
typedef char* (*DSO_NAME_CONVERTER_FUNC)(DSO*, const char*);
typedef char* (*DSO_MERGER_FUNC)(DSO*, const char*, const char*);
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
typedef unsigned long (*dynamic_v_check_fn) (unsigned long ossl_version);
typedef int (*dynamic_bind_engine) (ENGINE* e, const char* id, const dynamic_fns* fns);
typedef struct st_ERR_FNS ERR_FNS;
typedef struct st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;
typedef int (*STORE_INITIALISE_FUNC_PTR) (STORE*);
typedef void (*STORE_CLEANUP_FUNC_PTR) (STORE*);
typedef int ASN1_BOOLEAN;
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
typedef int CRYPTO_EX_new(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
	int idx, long argl, void* argp);
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA* to, CRYPTO_EX_DATA* from,
	void* from_d, int idx, long argl, void* argp);
typedef void CRYPTO_EX_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
	int idx, long argl, void* argp);

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

typedef STORE_OBJECT* (*STORE_GENERATE_OBJECT_FUNC_PTR)(STORE*,
	STORE_OBJECT_TYPES
	type,
	OPENSSL_ITEM
	attributes[],
	OPENSSL_ITEM
	parameters[]);

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

typedef struct openssl_item_st {
	int code;
	void* value;                /* Not used for flag attributes */
	size_t value_size;          /* Max size of value for output, length for
								 * input */
	size_t* value_length;       /* Returned length of value for output */
} OPENSSL_ITEM;

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

typedef struct X509_val_st {
	ASN1_TIME* notBefore;
	ASN1_TIME* notAfter;
} X509_VAL;

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

typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;

typedef const ASN1_ITEM* ASN1_ITEM_EXP(void);

typedef STORE_OBJECT* (*STORE_GET_OBJECT_FUNC_PTR)(STORE*,
	STORE_OBJECT_TYPES type,
	OPENSSL_ITEM attributes[],
	OPENSSL_ITEM parameters[]);

typedef struct ERR_string_data_st {
	unsigned long error;
	const char* string;
} ERR_STRING_DATA;

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

enum UI_string_types {
	UIT_NONE = 0,
	UIT_PROMPT,                 /* Prompt for a string */
	UIT_VERIFY,                 /* Prompt for a string and verify */
	UIT_BOOLEAN,                /* Prompt for a yes/no response */
	UIT_INFO,                   /* Send info to the user */
	UIT_ERROR                   /* Send an error message to the user */
};

struct st_ERR_FNS {
	/* Works on the "error_hash" string table */
	LHASH_OF(ERR_STRING_DATA)* (*cb_err_get) (int create);
	void (*cb_err_del) (void);
	ERR_STRING_DATA* (*cb_err_get_item) (const ERR_STRING_DATA*);
	ERR_STRING_DATA* (*cb_err_set_item) (ERR_STRING_DATA*);
	ERR_STRING_DATA* (*cb_err_del_item) (ERR_STRING_DATA*);
	/* Works on the "thread_hash" error-state table */
	LHASH_OF(ERR_STATE)* (*cb_thread_get) (int create);
	void (*cb_thread_release) (LHASH_OF(ERR_STATE)** hash);
	ERR_STATE* (*cb_thread_get_item) (const ERR_STATE*);
	ERR_STATE* (*cb_thread_set_item) (ERR_STATE*);
	void (*cb_thread_del_item) (const ERR_STATE*);
	/* Returns the next available error "library" numbers */
	int (*cb_get_next_lib) (void);
};

struct st_CRYPTO_EX_DATA_IMPL {
	/*********************/
/* GLOBAL OPERATIONS */
/* Return a new class index */
	int (*cb_new_class) (void);
	/* Cleanup all state used by the implementation */
	void (*cb_cleanup) (void);
	/************************/
/* PER-CLASS OPERATIONS */
/* Get a new method index within a class */
	int (*cb_get_new_index) (int class_index, long argl, void* argp,
		CRYPTO_EX_new* new_func, CRYPTO_EX_dup* dup_func,
		CRYPTO_EX_free* free_func);
	/* Initialise a new CRYPTO_EX_DATA of a given class */
	int (*cb_new_ex_data) (int class_index, void* obj, CRYPTO_EX_DATA* ad);
	/* Duplicate a CRYPTO_EX_DATA of a given class onto a copy */
	int (*cb_dup_ex_data) (int class_index, CRYPTO_EX_DATA* to,
		CRYPTO_EX_DATA* from);
	/* Cleanup a CRYPTO_EX_DATA of a given class */
	void (*cb_free_ex_data) (int class_index, void* obj, CRYPTO_EX_DATA* ad);
};

struct tls_session_ticket_ext_st {
	unsigned short length;
	void* data;
};

struct x509_store_st {
	/* The following is a cache of trusted certs */
	int cache;                  /* if true, stash any hits */
	STACK_OF(X509_OBJECT)* objs; /* Cache of all objects */
	/* These are external lookup methods */
	STACK_OF(X509_LOOKUP)* get_cert_methods;
	X509_VERIFY_PARAM* param;
	/* Callbacks for various operations */
	/* called to verify a certificate */
	int (*verify) (X509_STORE_CTX* ctx);
	/* error callback */
	int (*verify_cb) (int ok, X509_STORE_CTX* ctx);
	/* get issuers cert from ctx */
	int (*get_issuer) (X509** issuer, X509_STORE_CTX* ctx, X509* x);
	/* check issued */
	int (*check_issued) (X509_STORE_CTX* ctx, X509* x, X509* issuer);
	/* Check revocation status of chain */
	int (*check_revocation) (X509_STORE_CTX* ctx);
	/* retrieve CRL */
	int (*get_crl) (X509_STORE_CTX* ctx, X509_CRL** crl, X509* x);
	/* Check CRL validity */
	int (*check_crl) (X509_STORE_CTX* ctx, X509_CRL* crl);
	/* Check certificate against CRL */
	int (*cert_crl) (X509_STORE_CTX* ctx, X509_CRL* crl, X509* x);
	STACK_OF(X509)* (*lookup_certs) (X509_STORE_CTX* ctx, X509_NAME* nm);
	STACK_OF(X509_CRL)* (*lookup_crls) (X509_STORE_CTX* ctx, X509_NAME* nm);
	int (*cleanup) (X509_STORE_CTX* ctx);
	CRYPTO_EX_DATA ex_data;
	int references;
} /* X509_STORE */;

struct ssl_session_st {
	int ssl_version;            /* what ssl version session info is being
								 * kept in here? */
								 /* only really used in SSLv2 */
	unsigned int key_arg_length;
	unsigned char key_arg[SSL_MAX_KEY_ARG_LENGTH];
	int master_key_length;
	unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
	/* session_id - valid? */
	unsigned int session_id_length;
	unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
	/*
	 * this is used to determine whether the session is being reused in the
	 * appropriate context. It is up to the application to set this, via
	 * SSL_new
	 */
	unsigned int sid_ctx_length;
	unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
#  ifndef OPENSSL_NO_KRB5
	unsigned int krb5_client_princ_len;
	unsigned char krb5_client_princ[SSL_MAX_KRB5_PRINCIPAL_LENGTH];
#  endif                        /* OPENSSL_NO_KRB5 */
#  ifndef OPENSSL_NO_PSK
	char* psk_identity_hint;
	char* psk_identity;
#  endif
	/*
	 * Used to indicate that session resumption is not allowed. Applications
	 * can also set this bit for a new session via not_resumable_session_cb
	 * to disable session caching and tickets.
	 */
	int not_resumable;
	/* The cert is the certificate used to establish this connection */
	struct sess_cert_st /* SESS_CERT */* sess_cert;
	/*
	 * This is the cert for the other end. On clients, it will be the same as
	 * sess_cert->peer_key->x509 (the latter is not enough as sess_cert is
	 * not retained in the external representation of sessions, see
	 * ssl_asn1.c).
	 */
	X509* peer;
	/*
	 * when app_verify_callback accepts a session where the peer's
	 * certificate is not ok, we must remember the error for session reuse:
	 */
	long verify_result;         /* only for servers */
	int references;
	long timeout;
	long time;
	unsigned int compress_meth; /* Need to lookup the method */
	const SSL_CIPHER* cipher;
	unsigned long cipher_id;    /* when ASN.1 loaded, this needs to be used
								 * to load the 'cipher' structure */
	STACK_OF(SSL_CIPHER)* ciphers; /* ciphers offered by the client */
	CRYPTO_EX_DATA ex_data;     /* application specific data */
	/*
	 * These are used to make removal of session-ids more efficient and to
	 * implement a maximum cache size.
	 */
	struct ssl_session_st* prev, * next;
#  ifndef OPENSSL_NO_TLSEXT
	char* tlsext_hostname;
#   ifndef OPENSSL_NO_EC
	size_t tlsext_ecpointformatlist_length;
	unsigned char* tlsext_ecpointformatlist; /* peer's list */
	size_t tlsext_ellipticcurvelist_length;
	unsigned char* tlsext_ellipticcurvelist; /* peer's list */
#   endif                       /* OPENSSL_NO_EC */
	/* RFC4507 info */
	unsigned char* tlsext_tick; /* Session ticket */
	size_t tlsext_ticklen;      /* Session ticket length */
	long tlsext_tick_lifetime_hint; /* Session lifetime hint in seconds */
#  endif
#  ifndef OPENSSL_NO_SRP
	char* srp_username;
#  endif
};

struct comp_method_st {
	int type;                   /* NID for compression library */
	const char* name;           /* A text string to identify the library */
	int (*init) (COMP_CTX* ctx);
	void (*finish) (COMP_CTX* ctx);
	int (*compress) (COMP_CTX* ctx,
		unsigned char* out, unsigned int olen,
		unsigned char* in, unsigned int ilen);
	int (*expand) (COMP_CTX* ctx,
		unsigned char* out, unsigned int olen,
		unsigned char* in, unsigned int ilen);
	/*
	 * The following two do NOTHING, but are kept for backward compatibility
	 */
	long (*ctrl) (void);
	long (*callback_ctrl) (void);
};

struct comp_ctx_st {
	COMP_METHOD* meth;
	unsigned long compress_in;
	unsigned long compress_out;
	unsigned long expand_in;
	unsigned long expand_out;
	CRYPTO_EX_DATA ex_data;
};

struct X509_VERIFY_PARAM_ID_st {
	STACK_OF(OPENSSL_STRING)* hosts; /* Set of acceptable names */
	unsigned int hostflags;     /* Flags to control matching features */
	char* peername;             /* Matching hostname in peer certificate */
	char* email;                /* If not NULL email address to match */
	size_t emaillen;
	unsigned char* ip;          /* If not NULL IP address to match */
	size_t iplen;               /* Length of IP address */
};

struct ssl_cipher_st {
	int valid;
	const char* name;           /* text name */
	unsigned long id;           /* id, 4 bytes, first is version */
	/*
	 * changed in 0.9.9: these four used to be portions of a single value
	 * 'algorithms'
	 */
	unsigned long algorithm_mkey; /* key exchange algorithm */
	unsigned long algorithm_auth; /* server authentication */
	unsigned long algorithm_enc; /* symmetric encryption */
	unsigned long algorithm_mac; /* symmetric authentication */
	unsigned long algorithm_ssl; /* (major) protocol version */
	unsigned long algo_strength; /* strength and export flags */
	unsigned long algorithm2;   /* Extra flags */
	int strength_bits;          /* Number of bits really used */
	int alg_bits;               /* Number of bits for algorithm */
};

struct ssl_method_st {
	int version;
	int (*ssl_new) (SSL* s);
	void (*ssl_clear) (SSL* s);
	void (*ssl_free) (SSL* s);
	int (*ssl_accept) (SSL* s);
	int (*ssl_connect) (SSL* s);
	int (*ssl_read) (SSL* s, void* buf, int len);
	int (*ssl_peek) (SSL* s, void* buf, int len);
	int (*ssl_write) (SSL* s, const void* buf, int len);
	int (*ssl_shutdown) (SSL* s);
	int (*ssl_renegotiate) (SSL* s);
	int (*ssl_renegotiate_check) (SSL* s);
	long (*ssl_get_message) (SSL* s, int st1, int stn, int mt, long
		max, int* ok);
	int (*ssl_read_bytes) (SSL* s, int type, unsigned char* buf, int len,
		int peek);
	int (*ssl_write_bytes) (SSL* s, int type, const void* buf_, int len);
	int (*ssl_dispatch_alert) (SSL* s);
	long (*ssl_ctrl) (SSL* s, int cmd, long larg, void* parg);
	long (*ssl_ctx_ctrl) (SSL_CTX* ctx, int cmd, long larg, void* parg);
	const SSL_CIPHER* (*get_cipher_by_char) (const unsigned char* ptr);
	int (*put_cipher_by_char) (const SSL_CIPHER* cipher, unsigned char* ptr);
	int (*ssl_pending) (const SSL* s);
	int (*num_ciphers) (void);
	const SSL_CIPHER* (*get_cipher) (unsigned ncipher);
	const struct ssl_method_st* (*get_ssl_method) (int version);
	long (*get_timeout) (void);
	struct ssl3_enc_method* ssl3_enc; /* Extra SSLv3/TLS stuff */
	int (*ssl_version) (void);
	long (*ssl_callback_ctrl) (SSL* s, int cb_id, void (*fp) (void));
	long (*ssl_ctx_callback_ctrl) (SSL_CTX* s, int cb_id, void (*fp) (void));
};

struct ssl_st {
	/*
	 * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
	 * DTLS1_VERSION)
	 */
	int version;
	/* SSL_ST_CONNECT or SSL_ST_ACCEPT */
	int type;
	/* SSLv3 */
	const SSL_METHOD* method;
	/*
	 * There are 2 BIO's even though they are normally both the same.  This
	 * is so data can be read and written to different handlers
	 */
#  ifndef OPENSSL_NO_BIO
	 /* used by SSL_read */
	BIO* rbio;
	/* used by SSL_write */
	BIO* wbio;
	/* used during session-id reuse to concatenate messages */
	BIO* bbio;
#  else
	 /* used by SSL_read */
	char* rbio;
	/* used by SSL_write */
	char* wbio;
	char* bbio;
#  endif
	/*
	 * This holds a variable that indicates what we were doing when a 0 or -1
	 * is returned.  This is needed for non-blocking IO so we know what
	 * request needs re-doing when in SSL_accept or SSL_connect
	 */
	int rwstate;
	/* true when we are actually in SSL_accept() or SSL_connect() */
	int in_handshake;
	int (*handshake_func) (SSL*);
	/*
	 * Imagine that here's a boolean member "init" that is switched as soon
	 * as SSL_set_{accept/connect}_state is called for the first time, so
	 * that "state" and "handshake_func" are properly initialized.  But as
	 * handshake_func is == 0 until then, we use this test instead of an
	 * "init" member.
	 */
	 /* are we the server side? - mostly used by SSL_clear */
	int server;
	/*
	 * Generate a new session or reuse an old one.
	 * NB: For servers, the 'new' session may actually be a previously
	 * cached session or even the previous session unless
	 * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
	 */
	int new_session;
	/* don't send shutdown packets */
	int quiet_shutdown;
	/* we have shut things down, 0x01 sent, 0x02 for received */
	int shutdown;
	/* where we are */
	int state;
	/* where we are when reading */
	int rstate;
	BUF_MEM* init_buf;          /* buffer used during init */
	void* init_msg;             /* pointer to handshake message body, set by
								 * ssl3_get_message() */
	int init_num;               /* amount read/written */
	int init_off;               /* amount read/written */
	/* used internally to point at a raw packet */
	unsigned char* packet;
	unsigned int packet_length;
	struct ssl2_state_st* s2;   /* SSLv2 variables */
	struct ssl3_state_st* s3;   /* SSLv3 variables */
	struct dtls1_state_st* d1;  /* DTLSv1 variables */
	int read_ahead;             /* Read as many input bytes as possible (for
								 * non-blocking reads) */
								 /* callback that allows applications to peek at protocol messages */
	void (*msg_callback) (int write_p, int version, int content_type,
		const void* buf, size_t len, SSL* ssl, void* arg);
	void* msg_callback_arg;
	int hit;                    /* reusing a previous session */
	X509_VERIFY_PARAM* param;
#  if 0
	int purpose;                /* Purpose setting */
	int trust;                  /* Trust setting */
#  endif
	/* crypto */
	STACK_OF(SSL_CIPHER)* cipher_list;
	STACK_OF(SSL_CIPHER)* cipher_list_by_id;
	/*
	 * These are the ones being used, the ones in SSL_SESSION are the ones to
	 * be 'copied' into these ones
	 */
	int mac_flags;
	EVP_CIPHER_CTX* enc_read_ctx; /* cryptographic state */
	EVP_MD_CTX* read_hash;      /* used for mac generation */
#  ifndef OPENSSL_NO_COMP
	COMP_CTX* expand;           /* uncompress */
#  else
	char* expand;
#  endif
	EVP_CIPHER_CTX* enc_write_ctx; /* cryptographic state */
	EVP_MD_CTX* write_hash;     /* used for mac generation */
#  ifndef OPENSSL_NO_COMP
	COMP_CTX* compress;         /* compression */
#  else
	char* compress;
#  endif
	/* session info */
	/* client cert? */
	/* This is used to hold the server certificate used */
	struct cert_st /* CERT */* cert;
	/*
	 * the session_id_context is used to ensure sessions are only reused in
	 * the appropriate context
	 */
	unsigned int sid_ctx_length;
	unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
	/* This can also be in the session once a session is established */
	SSL_SESSION* session;
	/* Default generate session ID callback. */
	GEN_SESSION_CB generate_session_id;
	/* Used in SSL2 and SSL3 */
	/*
	 * 0 don't care about verify failure.
	 * 1 fail if verify fails
	 */
	int verify_mode;
	/* fail if callback returns 0 */
	int (*verify_callback) (int ok, X509_STORE_CTX* ctx);
	/* optional informational callback */
	void (*info_callback) (const SSL* ssl, int type, int val);
	/* error bytes to be written */
	int error;
	/* actual code */
	int error_code;
#  ifndef OPENSSL_NO_KRB5
	/* Kerberos 5 context */
	KSSL_CTX* kssl_ctx;
#  endif                        /* OPENSSL_NO_KRB5 */
#  ifndef OPENSSL_NO_PSK
	unsigned int (*psk_client_callback) (SSL* ssl, const char* hint,
		char* identity,
		unsigned int max_identity_len,
		unsigned char* psk,
		unsigned int max_psk_len);
	unsigned int (*psk_server_callback) (SSL* ssl, const char* identity,
		unsigned char* psk,
		unsigned int max_psk_len);
#  endif
	SSL_CTX* ctx;
	/*
	 * set this flag to 1 and a sleep(1) is put into all SSL_read() and
	 * SSL_write() calls, good for nbio debuging :-)
	 */
	int debug;
	/* extra application data */
	long verify_result;
	CRYPTO_EX_DATA ex_data;
	/* for server side, keep the list of CA_dn we can use */
	STACK_OF(X509_NAME)* client_CA;
	int references;
	/* protocol behaviour */
	unsigned long options;
	/* API behaviour */
	unsigned long mode;
	long max_cert_list;
	int first_packet;
	/* what was passed, used for SSLv3/TLS rollback check */
	int client_version;
	unsigned int max_send_fragment;
#  ifndef OPENSSL_NO_TLSEXT
	/* TLS extension debug callback */
	void (*tlsext_debug_cb) (SSL* s, int client_server, int type,
		unsigned char* data, int len, void* arg);
	void* tlsext_debug_arg;
	char* tlsext_hostname;
	/*-
	 * no further mod of servername
	 * 0 : call the servername extension callback.
	 * 1 : prepare 2, allow last ack just after in server callback.
	 * 2 : don't call servername callback, no ack in server hello
	 */
	int servername_done;
	/* certificate status request info */
	/* Status type or -1 if no status type */
	int tlsext_status_type;
	/* Expect OCSP CertificateStatus message */
	int tlsext_status_expected;
	/* OCSP status request only */
	STACK_OF(OCSP_RESPID)* tlsext_ocsp_ids;
	////X509_EXTENSIONS* tlsext_ocsp_exts;
	/* OCSP response received or to be sent */
	unsigned char* tlsext_ocsp_resp;
	int tlsext_ocsp_resplen;
	/* RFC4507 session ticket expected to be received or sent */
	int tlsext_ticket_expected;
#   ifndef OPENSSL_NO_EC
	size_t tlsext_ecpointformatlist_length;
	/* our list */
	unsigned char* tlsext_ecpointformatlist;
	size_t tlsext_ellipticcurvelist_length;
	/* our list */
	unsigned char* tlsext_ellipticcurvelist;
#   endif                       /* OPENSSL_NO_EC */
	/*
	 * draft-rescorla-tls-opaque-prf-input-00.txt information to be used for
	 * handshakes
	 */
	void* tlsext_opaque_prf_input;
	size_t tlsext_opaque_prf_input_len;
	/* TLS Session Ticket extension override */
	TLS_SESSION_TICKET_EXT* tlsext_session_ticket;
	/* TLS Session Ticket extension callback */
	tls_session_ticket_ext_cb_fn tls_session_ticket_ext_cb;
	void* tls_session_ticket_ext_cb_arg;
	/* TLS pre-shared secret session resumption */
	tls_session_secret_cb_fn tls_session_secret_cb;
	void* tls_session_secret_cb_arg;
	SSL_CTX* initial_ctx;       /* initial ctx, used to store sessions */
#   ifndef OPENSSL_NO_NEXTPROTONEG
	/*
	 * Next protocol negotiation. For the client, this is the protocol that
	 * we sent in NextProtocol and is set when handling ServerHello
	 * extensions. For a server, this is the client's selected_protocol from
	 * NextProtocol and is set when handling the NextProtocol message, before
	 * the Finished message.
	 */
	unsigned char* next_proto_negotiated;
	unsigned char next_proto_negotiated_len;
#   endif
#   define session_ctx initial_ctx
	/* What we'll do */
	STACK_OF(SRTP_PROTECTION_PROFILE)* srtp_profiles;
	/* What's been chosen */
	SRTP_PROTECTION_PROFILE* srtp_profile;
	/*-
	 * Is use of the Heartbeat extension negotiated?
	 * 0: disabled
	 * 1: enabled
	 * 2: enabled, but not allowed to send Requests
	 */
	unsigned int tlsext_heartbeat;
	/* Indicates if a HeartbeatRequest is in flight */
	unsigned int tlsext_hb_pending;
	/* HeartbeatRequest sequence number */
	unsigned int tlsext_hb_seq;
#  else
#   define session_ctx ctx
#  endif                        /* OPENSSL_NO_TLSEXT */
	/*-
	 * 1 if we are renegotiating.
	 * 2 if we are a server and are inside a handshake
	 * (i.e. not just sending a HelloRequest)
	 */
	int renegotiate;
#  ifndef OPENSSL_NO_SRP
	/* ctx for SRP authentication */
	SRP_CTX srp_ctx;
#  endif
#  ifndef OPENSSL_NO_TLSEXT
	/*
	 * For a client, this contains the list of supported protocols in wire
	 * format.
	 */
	unsigned char* alpn_client_proto_list;
	unsigned alpn_client_proto_list_len;
#  endif                        /* OPENSSL_NO_TLSEXT */
};

struct ui_st {
	const UI_METHOD* meth;
	STACK_OF(UI_STRING)* strings; /* We might want to prompt for more than
								   * one thing at a time, and with different
								   * echoing status.  */
	void* user_data;
	CRYPTO_EX_DATA ex_data;
# define UI_FLAG_REDOABLE        0x0001
# define UI_FLAG_PRINT_ERRORS    0x0100
	int flags;
};

struct ui_string_st {
	enum UI_string_types type;  /* Input */
	const char* out_string;     /* Input */
	int input_flags;            /* Flags from the user */
	/*
	 * The following parameters are completely irrelevant for UIT_INFO, and
	 * can therefore be set to 0 or NULL
	 */
	char* result_buf;           /* Input and Output: If not NULL,
								 * user-defined with size in result_maxsize.
								 * Otherwise, it may be allocated by the UI
								 * routine, meaning result_minsize is going
								 * to be overwritten. */
	union {
		struct {
			int result_minsize; /* Input: minimum required size of the
								 * result. */
			int result_maxsize; /* Input: maximum permitted size of the
								 * result */
			const char* test_buf; /* Input: test string to verify against */
		} string_data;
		struct {
			const char* action_desc; /* Input */
			const char* ok_chars; /* Input */
			const char* cancel_chars; /* Input */
		} boolean_data;
	} _;

# define OUT_STRING_FREEABLE 0x01
	int flags;                  /* flags for internal use */
};

struct ui_method_st {
	char* name;
	/*
	 * All the functions return 1 or non-NULL for success and 0 or NULL for
	 * failure
	 */
	 /*
	  * Open whatever channel for this, be it the console, an X window or
	  * whatever. This function should use the ex_data structure to save
	  * intermediate data.
	  */
	int (*ui_open_session) (UI* ui);
	int (*ui_write_string) (UI* ui, UI_STRING* uis);
	/*
	 * Flush the output.  If a GUI dialog box is used, this function can be
	 * used to actually display it.
	 */
	int (*ui_flush) (UI* ui);
	int (*ui_read_string) (UI* ui, UI_STRING* uis);
	int (*ui_close_session) (UI* ui);
	/*
	 * Construct a prompt in a user-defined manner.  object_desc is a textual
	 * short description of the object, for example "pass phrase", and
	 * object_name is the name of the object (might be a card name or a file
	 * name. The returned string shall always be allocated on the heap with
	 * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
	 */
	char* (*ui_construct_prompt) (UI* ui, const char* object_desc,
		const char* object_name);
};

struct evp_cipher_ctx_st {
	const EVP_CIPHER* cipher;
	ENGINE* engine;             /* functional reference if 'cipher' is
								 * ENGINE-provided */
	int encrypt;                /* encrypt or decrypt */
	int buf_len;                /* number we have left */
	unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
	unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
	unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
	int num;                    /* used by cfb/ofb/ctr mode */
	void* app_data;             /* application stuff */
	int key_len;                /* May change for variable length cipher */
	unsigned long flags;        /* Various flags */
	void* cipher_data;          /* per EVP data */
	int final_used;
	int block_mask;
	unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVP_CIPHER_CTX */;

struct evp_cipher_st {
	int nid;
	int block_size;
	/* Default value for variable length ciphers */
	int key_len;
	int iv_len;
	/* Various flags */
	unsigned long flags;
	/* init key */
	int (*init) (EVP_CIPHER_CTX* ctx, const unsigned char* key,
		const unsigned char* iv, int enc);
	/* encrypt/decrypt data */
	int (*do_cipher) (EVP_CIPHER_CTX* ctx, unsigned char* out,
		const unsigned char* in, size_t inl);
	/* cleanup ctx */
	int (*cleanup) (EVP_CIPHER_CTX*);
	/* how big ctx->cipher_data needs to be */
	int ctx_size;
	/* Populate a ASN1_TYPE with parameters */
	int (*set_asn1_parameters) (EVP_CIPHER_CTX*, ASN1_TYPE*);
	/* Get parameters from a ASN1_TYPE */
	int (*get_asn1_parameters) (EVP_CIPHER_CTX*, ASN1_TYPE*);
	/* Miscellaneous operations */
	int (*ctrl) (EVP_CIPHER_CTX*, int type, int arg, void* ptr);
	/* Application data */
	void* app_data;
} /* EVP_CIPHER */;

struct NAME_CONSTRAINTS_st {
	STACK_OF(GENERAL_SUBTREE)* permittedSubtrees;
	STACK_OF(GENERAL_SUBTREE)* excludedSubtrees;
};

struct X509_POLICY_DATA_st {
	unsigned int flags;
	/* Policy OID and qualifiers for this data */
	ASN1_OBJECT* valid_policy;
	STACK_OF(POLICYQUALINFO)* qualifier_set;
	STACK_OF(ASN1_OBJECT)* expected_policy_set;
};

struct X509_POLICY_CACHE_st {
	/* anyPolicy data or NULL if no anyPolicy */
	X509_POLICY_DATA* anyPolicy;
	/* other policy data */
	STACK_OF(X509_POLICY_DATA)* data;
	/* If InhibitAnyPolicy present this is its value or -1 if absent. */
	long any_skip;
	/*
	 * If policyConstraints and requireExplicitPolicy present this is its
	 * value or -1 if absent.
	 */
	long explicit_skip;
	/*
	 * If policyConstraints and policyMapping present this is its value or -1
	 * if absent.
	 */
	long map_skip;
};

struct x509_crl_method_st {
	int flags;
	int (*crl_init) (X509_CRL* crl);
	int (*crl_free) (X509_CRL* crl);
	int (*crl_lookup) (X509_CRL* crl, X509_REVOKED** ret,
		ASN1_INTEGER* ser, X509_NAME* issuer);
	int (*crl_verify) (X509_CRL* crl, EVP_PKEY* pk);
};

struct x509_crl_method_st {
	int flags;
	int (*crl_init) (X509_CRL* crl);
	int (*crl_free) (X509_CRL* crl);
	int (*crl_lookup) (X509_CRL* crl, X509_REVOKED** ret,
		ASN1_INTEGER* ser, X509_NAME* issuer);
	int (*crl_verify) (X509_CRL* crl, EVP_PKEY* pk);
};

struct ISSUING_DIST_POINT_st {
	DIST_POINT_NAME* distpoint;
	int onlyuser;
	int onlyCA;
	ASN1_BIT_STRING* onlysomereasons;
	int indirectCRL;
	int onlyattr;
};

struct ASN1_TEMPLATE_st {
	unsigned long flags;        /* Various flags */
	long tag;                   /* tag, not used if no tagging */
	unsigned long offset;       /* Offset of this field in structure */
# ifndef NO_ASN1_FIELD_NAMES
	const char* field_name;     /* Field name */
# endif
	ASN1_ITEM_EXP* item;        /* Relevant ASN1_ITEM or ASN1_ADB */
};

struct ASN1_ITEM_st {
	char itype;                 /* The item type, primitive, SEQUENCE, CHOICE
								 * or extern */
	long utype;                 /* underlying type */
	const ASN1_TEMPLATE* templates; /* If SEQUENCE or CHOICE this contains
									 * the contents */
	long tcount;                /* Number of templates if SEQUENCE or CHOICE */
	const void* funcs;          /* functions that handle this type */
	long size;                  /* Structure size (usually) */
# ifndef NO_ASN1_FIELD_NAMES
	const char* sname;          /* Structure name */
# endif
};

struct evp_pkey_method_st {
	int pkey_id;
	int flags;
	int (*init) (EVP_PKEY_CTX* ctx);
	int (*copy) (EVP_PKEY_CTX* dst, EVP_PKEY_CTX* src);
	void (*cleanup) (EVP_PKEY_CTX* ctx);
	int (*paramgen_init) (EVP_PKEY_CTX* ctx);
	int (*paramgen) (EVP_PKEY_CTX* ctx, EVP_PKEY* pkey);
	int (*keygen_init) (EVP_PKEY_CTX* ctx);
	int (*keygen) (EVP_PKEY_CTX* ctx, EVP_PKEY* pkey);
	int (*sign_init) (EVP_PKEY_CTX* ctx);
	int (*sign) (EVP_PKEY_CTX* ctx, unsigned char* sig, size_t* siglen,
		const unsigned char* tbs, size_t tbslen);
	int (*verify_init) (EVP_PKEY_CTX* ctx);
	int (*verify) (EVP_PKEY_CTX* ctx,
		const unsigned char* sig, size_t siglen,
		const unsigned char* tbs, size_t tbslen);
	int (*verify_recover_init) (EVP_PKEY_CTX* ctx);
	int (*verify_recover) (EVP_PKEY_CTX* ctx,
		unsigned char* rout, size_t* routlen,
		const unsigned char* sig, size_t siglen);
	int (*signctx_init) (EVP_PKEY_CTX* ctx, EVP_MD_CTX* mctx);
	int (*signctx) (EVP_PKEY_CTX* ctx, unsigned char* sig, size_t* siglen,
		EVP_MD_CTX* mctx);
	int (*verifyctx_init) (EVP_PKEY_CTX* ctx, EVP_MD_CTX* mctx);
	int (*verifyctx) (EVP_PKEY_CTX* ctx, const unsigned char* sig, int siglen,
		EVP_MD_CTX* mctx);
	int (*encrypt_init) (EVP_PKEY_CTX* ctx);
	int (*encrypt) (EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen,
		const unsigned char* in, size_t inlen);
	int (*decrypt_init) (EVP_PKEY_CTX* ctx);
	int (*decrypt) (EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen,
		const unsigned char* in, size_t inlen);
	int (*derive_init) (EVP_PKEY_CTX* ctx);
	int (*derive) (EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen);
	int (*ctrl) (EVP_PKEY_CTX* ctx, int type, int p1, void* p2);
	int (*ctrl_str) (EVP_PKEY_CTX* ctx, const char* type, const char* value);
} /* EVP_PKEY_METHOD */;

struct evp_pkey_ctx_st {
	/* Method associated with this operation */
	const EVP_PKEY_METHOD* pmeth;
	/* Engine that implements this method or NULL if builtin */
	ENGINE* engine;
	/* Key: may be NULL */
	EVP_PKEY* pkey;
	/* Peer key for key agreement, may be NULL */
	EVP_PKEY* peerkey;
	/* Actual operation */
	int operation;
	/* Algorithm specific data */
	void* data;
	/* Application specific data */
	void* app_data;
	/* Keygen callback */
	EVP_PKEY_gen_cb* pkey_gencb;
	/* implementation specific keygen data */
	int* keygen_info;
	int keygen_info_count;
} /* EVP_PKEY_CTX */;

struct env_md_st {
	int type;
	int pkey_type;
	int md_size;
	unsigned long flags;
	int (*init) (EVP_MD_CTX* ctx);
	int (*update) (EVP_MD_CTX* ctx, const void* data, size_t count);
	int (*final) (EVP_MD_CTX* ctx, unsigned char* md);
	int (*copy) (EVP_MD_CTX* to, const EVP_MD_CTX* from);
	int (*cleanup) (EVP_MD_CTX* ctx);
	/* FIXME: prototype these some day */
	int (*sign) (int type, const unsigned char* m, unsigned int m_length,
		unsigned char* sigret, unsigned int* siglen, void* key);
	int (*verify) (int type, const unsigned char* m, unsigned int m_length,
		const unsigned char* sigbuf, unsigned int siglen,
		void* key);
	int required_pkey_type[5];  /* EVP_PKEY_xxx */
	int block_size;
	int ctx_size;               /* how big does the ctx->md_data need to be */
	/* control function */
	int (*md_ctrl) (EVP_MD_CTX* ctx, int cmd, int p1, void* p2);
} /* EVP_MD */;

struct env_md_ctx_st {
	const EVP_MD* digest;
	ENGINE* engine;             /* functional reference if 'digest' is
								 * ENGINE-provided */
	unsigned long flags;
	void* md_data;
	/* Public key context for sign/verify */
	EVP_PKEY_CTX* pctx;
	/* Update function: usually copied from EVP_MD */
	int (*update) (EVP_MD_CTX* ctx, const void* data, size_t count);
} /* EVP_MD_CTX */;

struct pkcs8_priv_key_info_st {
	/* Flag for various broken formats */
	int broken;
# define PKCS8_OK                0
# define PKCS8_NO_OCTET          1
# define PKCS8_EMBEDDED_PARAM    2
# define PKCS8_NS_DB             3
# define PKCS8_NEG_PRIVKEY       4
	ASN1_INTEGER * version;
	X509_ALGOR* pkeyalg;
	/* Should be OCTET STRING but some are broken */
	ASN1_TYPE* pkey;
	STACK_OF(X509_ATTRIBUTE)* attributes;
};

struct asn1_pctx_st {
	unsigned long flags;
	unsigned long nm_flags;
	unsigned long cert_flags;
	unsigned long oid_flags;
	unsigned long str_flags;
} /* ASN1_PCTX */;

struct bio_st {
	BIO_METHOD* method;
	/* bio, mode, argp, argi, argl, ret */
	long (*callback) (struct bio_st*, int, const char*, int, long, long);
	char* cb_arg;               /* first argument for the callback */
	int init;
	int shutdown;
	int flags;                  /* extra storage */
	int retry_reason;
	int num;
	void* ptr;
	struct bio_st* next_bio;    /* used by filter BIOs */
	struct bio_st* prev_bio;    /* used by filter BIOs */
	int references;
	unsigned long num_read;
	unsigned long num_write;
	CRYPTO_EX_DATA ex_data;
};

struct evp_pkey_asn1_method_st {
	int pkey_id;
	int pkey_base_id;
	unsigned long pkey_flags;
	char* pem_str;
	char* info;
	int (*pub_decode) (EVP_PKEY* pk, X509_PUBKEY* pub);
	int (*pub_encode) (X509_PUBKEY* pub, const EVP_PKEY* pk);
	int (*pub_cmp) (const EVP_PKEY* a, const EVP_PKEY* b);
	int (*pub_print) (BIO* out, const EVP_PKEY* pkey, int indent,
		ASN1_PCTX* pctx);
	int (*priv_decode) (EVP_PKEY* pk, PKCS8_PRIV_KEY_INFO* p8inf);
	int (*priv_encode) (PKCS8_PRIV_KEY_INFO* p8, const EVP_PKEY* pk);
	int (*priv_print) (BIO* out, const EVP_PKEY* pkey, int indent,
		ASN1_PCTX* pctx);
	int (*pkey_size) (const EVP_PKEY* pk);
	int (*pkey_bits) (const EVP_PKEY* pk);
	int (*param_decode) (EVP_PKEY* pkey,
		const unsigned char** pder, int derlen);
	int (*param_encode) (const EVP_PKEY* pkey, unsigned char** pder);
	int (*param_missing) (const EVP_PKEY* pk);
	int (*param_copy) (EVP_PKEY* to, const EVP_PKEY* from);
	int (*param_cmp) (const EVP_PKEY* a, const EVP_PKEY* b);
	int (*param_print) (BIO* out, const EVP_PKEY* pkey, int indent,
		ASN1_PCTX* pctx);
	int (*sig_print) (BIO* out,
		const X509_ALGOR* sigalg, const ASN1_STRING* sig,
		int indent, ASN1_PCTX* pctx);
	void (*pkey_free) (EVP_PKEY* pkey);
	int (*pkey_ctrl) (EVP_PKEY* pkey, int op, long arg1, void* arg2);
	/* Legacy functions for old PEM */
	int (*old_priv_decode) (EVP_PKEY* pkey,
		const unsigned char** pder, int derlen);
	int (*old_priv_encode) (const EVP_PKEY* pkey, unsigned char** pder);
	/* Custom ASN1 signature verification */
	int (*item_verify) (EVP_MD_CTX* ctx, const ASN1_ITEM* it, void* asn,
		X509_ALGOR* a, ASN1_BIT_STRING* sig, EVP_PKEY* pkey);
	int (*item_sign) (EVP_MD_CTX* ctx, const ASN1_ITEM* it, void* asn,
		X509_ALGOR* alg1, X509_ALGOR* alg2,
		ASN1_BIT_STRING* sig);
} /* EVP_PKEY_ASN1_METHOD */;

struct evp_pkey_st {
	int type;
	int save_type;
	int references;
	const EVP_PKEY_ASN1_METHOD* ameth;
	ENGINE* engine;
	union {
		char* ptr;
# ifndef OPENSSL_NO_RSA
		struct rsa_st* rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
		struct dsa_st* dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
		struct dh_st* dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
		struct ec_key_st* ec;   /* ECC */
# endif
	} pkey;
	int save_parameters;
	STACK_OF(X509_ATTRIBUTE)* attributes; /* [ 0 ] */
} /* EVP_PKEY */;

struct AUTHORITY_KEYID_st {
	ASN1_OCTET_STRING* keyid;
	GENERAL_NAMES* issuer;
	ASN1_INTEGER* serial;
};

struct X509_crl_st {
	/* actual signature */
	X509_CRL_INFO* crl;
	X509_ALGOR* sig_alg;
	ASN1_BIT_STRING* signature;
	int references;
	int flags;
	/* Copies of various extensions */
	AUTHORITY_KEYID* akid;
	ISSUING_DIST_POINT* idp;
	/* Convenient breakdown of IDP */
	int idp_flags;
	int idp_reasons;
	/* CRL and base CRL numbers for delta processing */
	ASN1_INTEGER* crl_number;
	ASN1_INTEGER* base_crl_number;
# ifndef OPENSSL_NO_SHA
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
# endif
	STACK_OF(GENERAL_NAMES)* issuers;
	const X509_CRL_METHOD* meth;
	void* meth_data;
} /* X509_CRL */;

struct X509_pubkey_st {
	X509_ALGOR* algor;
	ASN1_BIT_STRING* public_key;
	EVP_PKEY* pkey;
};

struct asn1_string_st {
	int length;
	int type;
	unsigned char* data;
	/*
	 * The value of the following field depends on the type being held.  It
	 * is mostly being used for BIT_STRING so if the input data has a
	 * non-zero 'unused bits' value, it will be handled correctly
	 */
	long flags;
};

struct buf_mem_st {
	size_t length;              /* current number of bytes */
	char* data;
	size_t max;                 /* size of buffer */
};

struct X509_name_st {
	STACK_OF(X509_NAME_ENTRY)* entries;
	int modified;               /* true if 'bytes' needs to be built */
# ifndef OPENSSL_NO_BUFFER
	BUF_MEM* bytes;
# else
	char* bytes;
# endif
	/*      unsigned long hash; Keep the hash around for lookups */
	unsigned char* canon_enc;
	int canon_enclen;
} /* X509_NAME */;

struct asn1_object_st {
	const char* sn, * ln;
	int nid;
	int length;
	const unsigned char* data;  /* data remains const after init */
	int flags;                  /* Should we free this one */
};

struct X509_algor_st {
	ASN1_OBJECT* algorithm;
	ASN1_TYPE* parameter;
} /* X509_ALGOR */;

struct asn1_string_st {
	int length;
	int type;
	unsigned char* data;
	/*
	 * The value of the following field depends on the type being held.  It
	 * is mostly being used for BIT_STRING so if the input data has a
	 * non-zero 'unused bits' value, it will be handled correctly
	 */
	long flags;
};

struct x509_st {
	X509_CINF* cert_info;
	X509_ALGOR* sig_alg;
	ASN1_BIT_STRING* signature;
	int valid;
	int references;
	char* name;
	CRYPTO_EX_DATA ex_data;
	/* These contain copies of various extension values */
	long ex_pathlen;
	long ex_pcpathlen;
	unsigned long ex_flags;
	unsigned long ex_kusage;
	unsigned long ex_xkusage;
	unsigned long ex_nscert;
	ASN1_OCTET_STRING* skid;
	AUTHORITY_KEYID* akid;
	X509_POLICY_CACHE* policy_cache;
	STACK_OF(DIST_POINT)* crldp;
	STACK_OF(GENERAL_NAME)* altname;
	NAME_CONSTRAINTS* nc;
# ifndef OPENSSL_NO_RFC3779
	STACK_OF(IPAddressFamily)* rfc3779_addr;
	struct ASIdentifiers_st* rfc3779_asid;
# endif
# ifndef OPENSSL_NO_SHA
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
# endif
	X509_CERT_AUX* aux;
} /* X509 */;

struct store_st {
	const STORE_METHOD* meth;
	/* functional reference if 'meth' is ENGINE-provided */
	ENGINE* engine;
	CRYPTO_EX_DATA ex_data;
	int references;
};

struct store_method_st {
	char* name;
	/*
	 * All the functions return a positive integer or non-NULL for success
	 * and 0, a negative integer or NULL for failure
	 */
	 /* Initialise the STORE with private data */
	STORE_INITIALISE_FUNC_PTR init;
	/* Initialise the STORE with private data */
	STORE_CLEANUP_FUNC_PTR clean;
	/* Generate an object of a given type */
	STORE_GENERATE_OBJECT_FUNC_PTR generate_object;
	/*
	 * Get an object of a given type.  This function isn't really very useful
	 * since the listing functions (below) can be used for the same purpose
	 * and are much more general.
	 */
	STORE_GET_OBJECT_FUNC_PTR get_object;
	/* Store an object of a given type. */
	STORE_STORE_OBJECT_FUNC_PTR store_object;
	/* Modify the attributes bound to an object of a given type. */
	STORE_MODIFY_OBJECT_FUNC_PTR modify_object;
	/* Revoke an object of a given type. */
	STORE_HANDLE_OBJECT_FUNC_PTR revoke_object;
	/* Delete an object of a given type. */
	STORE_HANDLE_OBJECT_FUNC_PTR delete_object;
	/*
	 * List a bunch of objects of a given type and with the associated
	 * attributes.
	 */
	STORE_START_OBJECT_FUNC_PTR list_object_start;
	STORE_NEXT_OBJECT_FUNC_PTR list_object_next;
	STORE_END_OBJECT_FUNC_PTR list_object_end;
	STORE_END_OBJECT_FUNC_PTR list_object_endp;
	/* Store-level function to make any necessary update operations. */
	STORE_GENERIC_FUNC_PTR update_store;
	/* Store-level function to get exclusive access to the store. */
	STORE_GENERIC_FUNC_PTR lock_store;
	/* Store-level function to release exclusive access to the store. */
	STORE_GENERIC_FUNC_PTR unlock_store;
	/* Generic control function */
	STORE_CTRL_FUNC_PTR ctrl;
};

struct rand_meth_st {
	void (*seed) (const void* buf, int num);
	int (*bytes) (unsigned char* buf, int num);
	void (*cleanup) (void);
	void (*add) (const void* buf, int num, double entropy);
	int (*pseudorand) (unsigned char* buf, int num);
	int (*status) (void);
};

struct ecdsa_method {
	const char* name;
	ECDSA_SIG* (*ecdsa_do_sign) (const unsigned char* dgst, int dgst_len,
		const BIGNUM* inv, const BIGNUM* rp,
		EC_KEY* eckey);
	int (*ecdsa_sign_setup) (EC_KEY* eckey, BN_CTX* ctx, BIGNUM** kinv,
		BIGNUM** r);
	int (*ecdsa_do_verify) (const unsigned char* dgst, int dgst_len,
		const ECDSA_SIG* sig, EC_KEY* eckey);
# if 0
	int (*init) (EC_KEY * eckey);
	int (*finish) (EC_KEY* eckey);
# endif
	int flags;
	void* app_data;
};

struct ec_point_st {
	const EC_METHOD* meth;
	/*
	 * All members except 'meth' are handled by the method functions, even if
	 * they appear generic
	 */
	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z;                   /* Jacobian projective coordinates: (X, Y, Z)
								 * represents (X/Z^2, Y/Z^3) if Z != 0 */
	int Z_is_one;               /* enable optimized point arithmetics for
								 * special case */
} /* EC_POINT */;

struct ec_method_st {
	/* Various method flags */
	int flags;
	/* used by EC_METHOD_get_field_type: */
	int field_type;             /* a NID */
	/*
	 * used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free,
	 * EC_GROUP_copy:
	 */
	int (*group_init) (EC_GROUP*);
	void (*group_finish) (EC_GROUP*);
	void (*group_clear_finish) (EC_GROUP*);
	int (*group_copy) (EC_GROUP*, const EC_GROUP*);
	/* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
	/* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */
	int (*group_set_curve) (EC_GROUP*, const BIGNUM* p, const BIGNUM* a,
		const BIGNUM* b, BN_CTX*);
	int (*group_get_curve) (const EC_GROUP*, BIGNUM* p, BIGNUM* a, BIGNUM* b,
		BN_CTX*);
	/* used by EC_GROUP_get_degree: */
	int (*group_get_degree) (const EC_GROUP*);
	/* used by EC_GROUP_check: */
	int (*group_check_discriminant) (const EC_GROUP*, BN_CTX*);
	/*
	 * used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free,
	 * EC_POINT_copy:
	 */
	int (*point_init) (EC_POINT*);
	void (*point_finish) (EC_POINT*);
	void (*point_clear_finish) (EC_POINT*);
	int (*point_copy) (EC_POINT*, const EC_POINT*);
	/*-
	 * used by EC_POINT_set_to_infinity,
	 * EC_POINT_set_Jprojective_coordinates_GFp,
	 * EC_POINT_get_Jprojective_coordinates_GFp,
	 * EC_POINT_set_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_get_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_set_compressed_coordinates_GFp, ..._GF2m:
	 */
	int (*point_set_to_infinity) (const EC_GROUP*, EC_POINT*);
	int (*point_set_Jprojective_coordinates_GFp) (const EC_GROUP*,
		EC_POINT*, const BIGNUM* x,
		const BIGNUM* y,
		const BIGNUM* z, BN_CTX*);
	int (*point_get_Jprojective_coordinates_GFp) (const EC_GROUP*,
		const EC_POINT*, BIGNUM* x,
		BIGNUM* y, BIGNUM* z,
		BN_CTX*);
	int (*point_set_affine_coordinates) (const EC_GROUP*, EC_POINT*,
		const BIGNUM* x, const BIGNUM* y,
		BN_CTX*);
	int (*point_get_affine_coordinates) (const EC_GROUP*, const EC_POINT*,
		BIGNUM* x, BIGNUM* y, BN_CTX*);
	int (*point_set_compressed_coordinates) (const EC_GROUP*, EC_POINT*,
		const BIGNUM* x, int y_bit,
		BN_CTX*);
	/* used by EC_POINT_point2oct, EC_POINT_oct2point: */
	size_t(*point2oct) (const EC_GROUP*, const EC_POINT*,
		point_conversion_form_t form, unsigned char* buf,
		size_t len, BN_CTX*);
	int (*oct2point) (const EC_GROUP*, EC_POINT*, const unsigned char* buf,
		size_t len, BN_CTX*);
	/* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
	int (*add) (const EC_GROUP*, EC_POINT* r, const EC_POINT* a,
		const EC_POINT* b, BN_CTX*);
	int (*dbl) (const EC_GROUP*, EC_POINT* r, const EC_POINT* a, BN_CTX*);
	int (*invert) (const EC_GROUP*, EC_POINT*, BN_CTX*);
	/*
	 * used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp:
	 */
	int (*is_at_infinity) (const EC_GROUP*, const EC_POINT*);
	int (*is_on_curve) (const EC_GROUP*, const EC_POINT*, BN_CTX*);
	int (*point_cmp) (const EC_GROUP*, const EC_POINT* a, const EC_POINT* b,
		BN_CTX*);
	/* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
	int (*make_affine) (const EC_GROUP*, EC_POINT*, BN_CTX*);
	int (*points_make_affine) (const EC_GROUP*, size_t num, EC_POINT* [],
		BN_CTX*);
	/*
	 * used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult,
	 * EC_POINT_have_precompute_mult (default implementations are used if the
	 * 'mul' pointer is 0):
	 */
	int (*mul) (const EC_GROUP* group, EC_POINT* r, const BIGNUM* scalar,
		size_t num, const EC_POINT* points[], const BIGNUM* scalars[],
		BN_CTX*);
	int (*precompute_mult) (EC_GROUP* group, BN_CTX*);
	int (*have_precompute_mult) (const EC_GROUP* group);
	/* internal functions */
	/*
	 * 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and
	 * 'dbl' so that the same implementations of point operations can be used
	 * with different optimized implementations of expensive field
	 * operations:
	 */
	int (*field_mul) (const EC_GROUP*, BIGNUM* r, const BIGNUM* a,
		const BIGNUM* b, BN_CTX*);
	int (*field_sqr) (const EC_GROUP*, BIGNUM* r, const BIGNUM* a, BN_CTX*);
	int (*field_div) (const EC_GROUP*, BIGNUM* r, const BIGNUM* a,
		const BIGNUM* b, BN_CTX*);
	/* e.g. to Montgomery */
	int (*field_encode) (const EC_GROUP*, BIGNUM* r, const BIGNUM* a,
		BN_CTX*);
	/* e.g. from Montgomery */
	int (*field_decode) (const EC_GROUP*, BIGNUM* r, const BIGNUM* a,
		BN_CTX*);
	int (*field_set_to_one) (const EC_GROUP*, BIGNUM* r, BN_CTX*);
} /* EC_METHOD */;

struct ec_group_st {
	const EC_METHOD* meth;
	EC_POINT* generator;        /* optional */
	BIGNUM order, cofactor;
	int curve_name;             /* optional NID for named curve */
	int asn1_flag;              /* flag to control the asn1 encoding */
	/*
	 * Kludge: upper bit of ans1_flag is used to denote structure
	 * version. If set, then last field is present. This is done
	 * for interoperation with FIPS code.
	 */
#define EC_GROUP_ASN1_FLAG_MASK 0x7fffffff
#define EC_GROUP_VERSION(p) (p->asn1_flag&~EC_GROUP_ASN1_FLAG_MASK)
	point_conversion_form_t asn1_form;
	unsigned char* seed;        /* optional seed for parameters (appears in
								 * ASN1) */
	size_t seed_len;
	EC_EXTRA_DATA* extra_data;  /* linked list */
	/*
	 * The following members are handled by the method functions, even if
	 * they appear generic
	 */
	 /*
	  * Field specification. For curves over GF(p), this is the modulus; for
	  * curves over GF(2^m), this is the irreducible polynomial defining the
	  * field.
	  */
	BIGNUM field;
	/*
	 * Field specification for curves over GF(2^m). The irreducible f(t) is
	 * then of the form: t^poly[0] + t^poly[1] + ... + t^poly[k] where m =
	 * poly[0] > poly[1] > ... > poly[k] = 0. The array is terminated with
	 * poly[k+1]=-1. All elliptic curve irreducibles have at most 5 non-zero
	 * terms.
	 */
	int poly[6];
	/*
	 * Curve coefficients. (Here the assumption is that BIGNUMs can be used
	 * or abused for all kinds of fields, not just GF(p).) For characteristic
	 * > 3, the curve is defined by a Weierstrass equation of the form y^2 =
	 * x^3 + a*x + b. For characteristic 2, the curve is defined by an
	 * equation of the form y^2 + x*y = x^3 + a*x^2 + b.
	 */
	BIGNUM a, b;
	/* enable optimized point arithmetics for special case */
	int a_is_minus3;
	/* method-specific (e.g., Montgomery structure) */
	void* field_data1;
	/* method-specific */
	void* field_data2;
	/* method-specific */
	int (*field_mod_func) (BIGNUM*, const BIGNUM*, const BIGNUM*,
		BN_CTX*);
	BN_MONT_CTX* mont_data;     /* data for ECDSA inverse */
} /* EC_GROUP */;

struct ec_key_st {
	int version;
	EC_GROUP* group;
	EC_POINT* pub_key;
	BIGNUM* priv_key;
	unsigned int enc_flag;
	point_conversion_form_t conv_form;
	int references;
	int flags;
	EC_EXTRA_DATA* method_data;
} /* EC_KEY */;

struct ecdh_method {
	const char* name;
	int (*compute_key) (void* key, size_t outlen, const EC_POINT* pub_key,
		EC_KEY* ecdh, void* (*KDF) (const void* in,
			size_t inlen, void* out,
			size_t* outlen));
# if 0
	int (*init) (EC_KEY * eckey);
	int (*finish) (EC_KEY* eckey);
# endif
	int flags;
	char* app_data;
};

struct dh_st {
	/*
	 * This first argument is used to pick up errors when a DH is passed
	 * instead of a EVP_PKEY
	 */
	int pad;
	int version;
	BIGNUM* p;
	BIGNUM* g;
	long length;                /* optional */
	BIGNUM* pub_key;            /* g^x % p */
	BIGNUM* priv_key;           /* x */
	int flags;
	BN_MONT_CTX* method_mont_p;
	/* Place holders if we want to do X9.42 DH */
	BIGNUM* q;
	BIGNUM* j;
	unsigned char* seed;
	int seedlen;
	BIGNUM* counter;
	int references;
	CRYPTO_EX_DATA ex_data;
	const DH_METHOD* meth;
	ENGINE* engine;
};

struct dh_method {
	const char* name;
	/* Methods here */
	int (*generate_key) (DH* dh);
	int (*compute_key) (unsigned char* key, const BIGNUM* pub_key, DH* dh);
	/* Can be null */
	int (*bn_mod_exp) (const DH* dh, BIGNUM* r, const BIGNUM* a,
		const BIGNUM* p, const BIGNUM* m, BN_CTX* ctx,
		BN_MONT_CTX* m_ctx);
	int (*init) (DH* dh);
	int (*finish) (DH* dh);
	int flags;
	char* app_data;
	/* If this is non-NULL, it will be used to generate parameters */
	int (*generate_params) (DH* dh, int prime_len, int generator,
		BN_GENCB* cb);
};

struct dsa_st {
	/*
	 * This first variable is used to pick up errors where a DSA is passed
	 * instead of of a EVP_PKEY
	 */
	int pad;
	long version;
	int write_params;
	BIGNUM* p;
	BIGNUM* q;                  /* == 20 */
	BIGNUM* g;
	BIGNUM* pub_key;            /* y public key */
	BIGNUM* priv_key;           /* x private key */
	BIGNUM* kinv;               /* Signing pre-calc */
	BIGNUM* r;                  /* Signing pre-calc */
	int flags;
	/* Normally used to cache montgomery values */
	BN_MONT_CTX* method_mont_p;
	int references;
	CRYPTO_EX_DATA ex_data;
	const DSA_METHOD* meth;
	/* functional reference if 'meth' is ENGINE-provided */
	ENGINE* engine;
};

struct dsa_method {
	const char* name;
	DSA_SIG* (*dsa_do_sign) (const unsigned char* dgst, int dlen, DSA* dsa);
	int (*dsa_sign_setup) (DSA* dsa, BN_CTX* ctx_in, BIGNUM** kinvp,
		BIGNUM** rp);
	int (*dsa_do_verify) (const unsigned char* dgst, int dgst_len,
		DSA_SIG* sig, DSA* dsa);
	int (*dsa_mod_exp) (DSA* dsa, BIGNUM* rr, BIGNUM* a1, BIGNUM* p1,
		BIGNUM* a2, BIGNUM* p2, BIGNUM* m, BN_CTX* ctx,
		BN_MONT_CTX* in_mont);
	/* Can be null */
	int (*bn_mod_exp) (DSA* dsa, BIGNUM* r, BIGNUM* a, const BIGNUM* p,
		const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);
	int (*init) (DSA* dsa);
	int (*finish) (DSA* dsa);
	int flags;
	char* app_data;
	/* If this is non-NULL, it is used to generate DSA parameters */
	int (*dsa_paramgen) (DSA* dsa, int bits,
		const unsigned char* seed, int seed_len,
		int* counter_ret, unsigned long* h_ret,
		BN_GENCB* cb);
	/* If this is non-NULL, it is used to generate DSA keys */
	int (*dsa_keygen) (DSA* dsa);
};

struct bn_gencb_st {
	unsigned int ver;           /* To handle binary (in)compatibility */
	void* arg;                  /* callback-specific data */
	union {
		/* if(ver==1) - handles old style callbacks */
		void (*cb_1) (int, int, void*);
		/* if(ver==2) - new callback style */
		int (*cb_2) (int, int, BN_GENCB*);
	} cb;
};

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

struct bignum_ctx {
	/* The bignum bundles */
	BN_POOL pool;
	/* The "stack frames", if you will */
	BN_STACK stack;
	/* The number of bignums currently assigned */
	unsigned int used;
	/* Depth of stack overflow */
	int err_stack;
	/* Block "gets" until an "end" (compatibility behaviour) */
	int too_many;
};

typedef struct crypto_threadid_st {
	void* ptr;
	unsigned long val;
} CRYPTO_THREADID;

struct bn_blinding_st {
	BIGNUM* A;
	BIGNUM* Ai;
	BIGNUM* e;
	BIGNUM* mod;                /* just a reference */
#ifndef OPENSSL_NO_DEPRECATED
	unsigned long thread_id;    /* added in OpenSSL 0.9.6j and 0.9.7b; used
								 * only by crypto/rsa/rsa_eay.c, rsa_lib.c */
#endif
	CRYPTO_THREADID tid;
	int counter;
	unsigned long flags;
	BN_MONT_CTX* m_ctx;
	int (*bn_mod_exp) (BIGNUM* r, const BIGNUM* a, const BIGNUM* p,
		const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);
};

struct bn_mont_ctx_st {
	int ri;                     /* number of bits in R */
	BIGNUM RR;                  /* used to convert to montgomery form */
	BIGNUM N;                   /* The modulus */
	BIGNUM Ni;                  /* R*(1/R mod N) - N*Ni = 1 (Ni is only
								 * stored for bignum algorithm) */
	BN_ULONG n0[2];             /* least significant word(s) of Ni; (type
								 * changed with 0.9.9, was "BN_ULONG n0;"
								 * before) */
	int flags;
};

struct bignum_st {
	BN_ULONG* d;                /* Pointer to an array of 'BN_BITS2' bit
								 * chunks. */
	int top;                    /* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;                   /* Size of the d array. */
	int neg;                    /* one if the number is negative */
	int flags;
};

struct rsa_st {
	/*
	 * The first parameter is used to pickup errors where this is passed
	 * instead of aEVP_PKEY, it is set to 0
	 */
	int pad;
	long version;
	const RSA_METHOD* meth;
	/* functional reference if 'meth' is ENGINE-provided */
	ENGINE* engine;
	BIGNUM* n;
	BIGNUM* e;
	BIGNUM* d;
	BIGNUM* p;
	BIGNUM* q;
	BIGNUM* dmp1;
	BIGNUM* dmq1;
	BIGNUM* iqmp;
	/* be careful using this if the RSA structure is shared */
	CRYPTO_EX_DATA ex_data;
	int references;
	int flags;
	/* Used to cache montgomery values */
	BN_MONT_CTX* _method_mod_n;
	BN_MONT_CTX* _method_mod_p;
	BN_MONT_CTX* _method_mod_q;
	/*
	 * all BIGNUM values are actually in the following data, if it is not
	 * NULL
	 */
	char* bignum_data;
	BN_BLINDING* blinding;
	BN_BLINDING* mt_blinding;
};

struct rsa_meth_st {
	const char* name;
	int (*rsa_pub_enc) (int flen, const unsigned char* from,
		unsigned char* to, RSA* rsa, int padding);
	int (*rsa_pub_dec) (int flen, const unsigned char* from,
		unsigned char* to, RSA* rsa, int padding);
	int (*rsa_priv_enc) (int flen, const unsigned char* from,
		unsigned char* to, RSA* rsa, int padding);
	int (*rsa_priv_dec) (int flen, const unsigned char* from,
		unsigned char* to, RSA* rsa, int padding);
	/* Can be null */
	int (*rsa_mod_exp) (BIGNUM* r0, const BIGNUM* I, RSA* rsa, BN_CTX* ctx);
	/* Can be null */
	int (*bn_mod_exp) (BIGNUM* r, const BIGNUM* a, const BIGNUM* p,
		const BIGNUM* m, BN_CTX* ctx, BN_MONT_CTX* m_ctx);
	/* called at new */
	int (*init) (RSA* rsa);
	/* called at free */
	int (*finish) (RSA* rsa);
	/* RSA_METHOD_FLAG_* things */
	int flags;
	/* may be needed! */
	char* app_data;
	/*
	 * New sign and verify functions: some libraries don't allow arbitrary
	 * data to be signed/verified: this allows them to be used. Note: for
	 * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
	 * *NOT* be used RSA_sign(), RSA_verify() should be used instead. Note:
	 * for backwards compatibility this functionality is only enabled if the
	 * RSA_FLAG_SIGN_VER option is set in 'flags'.
	 */
	int (*rsa_sign) (int type,
		const unsigned char* m, unsigned int m_length,
		unsigned char* sigret, unsigned int* siglen,
		const RSA* rsa);
	int (*rsa_verify) (int dtype, const unsigned char* m,
		unsigned int m_length, const unsigned char* sigbuf,
		unsigned int siglen, const RSA* rsa);
	/*
	 * If this callback is NULL, the builtin software RSA key-gen will be
	 * used. This is for behavioural compatibility whilst the code gets
	 * rewired, but one day it would be nice to assume there are no such
	 * things as "builtin software" implementations.
	 */
	int (*rsa_keygen) (RSA* rsa, int bits, BIGNUM* e, BN_GENCB* cb);
};

struct engine_st {
	const char* id;
	const char* name;
	const RSA_METHOD* rsa_meth;
	const DSA_METHOD* dsa_meth;
	const DH_METHOD* dh_meth;
	const ECDH_METHOD* ecdh_meth;
	const ECDSA_METHOD* ecdsa_meth;
	const RAND_METHOD* rand_meth;
	const STORE_METHOD* store_meth;
	/* Cipher handling is via this callback */
	ENGINE_CIPHERS_PTR ciphers;
	/* Digest handling is via this callback */
	ENGINE_DIGESTS_PTR digests;
	/* Public key handling via this callback */
	ENGINE_PKEY_METHS_PTR pkey_meths;
	/* ASN1 public key handling via this callback */
	ENGINE_PKEY_ASN1_METHS_PTR pkey_asn1_meths;
	ENGINE_GEN_INT_FUNC_PTR destroy;
	ENGINE_GEN_INT_FUNC_PTR init;
	ENGINE_GEN_INT_FUNC_PTR finish;
	ENGINE_CTRL_FUNC_PTR ctrl;
	ENGINE_LOAD_KEY_PTR load_privkey;
	ENGINE_LOAD_KEY_PTR load_pubkey;
	ENGINE_SSL_CLIENT_CERT_PTR load_ssl_client_cert;
	const ENGINE_CMD_DEFN* cmd_defns;
	int flags;
	/* reference count on the structure itself */
	int struct_ref;
	/*
	 * reference count on usability of the engine type. NB: This controls the
	 * loading and initialisation of any functionlity required by this
	 * engine, whereas the previous count is simply to cope with
	 * (de)allocation of this structure. Hence, running_ref <= struct_ref at
	 * all times.
	 */
	int funct_ref;
	/* A place to store per-ENGINE data */
	CRYPTO_EX_DATA ex_data;
	/* Used to maintain the linked-list of engines. */
	struct engine_st* prev;
	struct engine_st* next;
};

typedef void* (*dyn_MEM_malloc_cb) (size_t);
typedef void* (*dyn_MEM_realloc_cb) (void*, size_t);
typedef void (*dyn_MEM_free_cb) (void*);
typedef struct st_dynamic_MEM_fns {
	dyn_MEM_malloc_cb malloc_cb;
	dyn_MEM_realloc_cb realloc_cb;
	dyn_MEM_free_cb free_cb;
} dynamic_MEM_fns;

typedef void (*dyn_lock_locking_cb) (int, int, const char*, int);
typedef int (*dyn_lock_add_lock_cb) (int*, int, int, const char*, int);
typedef struct CRYPTO_dynlock_value* (*dyn_dynlock_create_cb) (const char*, int);
typedef void (*dyn_dynlock_lock_cb) (int, struct CRYPTO_dynlock_value*, const char*, int);
typedef void (*dyn_dynlock_destroy_cb) (struct CRYPTO_dynlock_value*, const char*, int);
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


struct crypto_ex_data_st {
	STACK_OF(void)* sk;
	/* gcc is screwing up this data structure :-( */
	int dummy;
};

typedef struct dso_meth_st {
	const char* name;
	/*
	 * Loads a shared library, NB: new DSO_METHODs must ensure that a
	 * successful load populates the loaded_filename field, and likewise a
	 * successful unload OPENSSL_frees and NULLs it out.
	 */
	int (*dso_load) (DSO* dso);
	/* Unloads a shared library */
	int (*dso_unload) (DSO* dso);
	/* Binds a variable */
	void* (*dso_bind_var) (DSO* dso, const char* symname);
	/*
	 * Binds a function - assumes a return type of DSO_FUNC_TYPE. This should
	 * be cast to the real function prototype by the caller. Platforms that
	 * don't have compatible representations for different prototypes (this
	 * is possible within ANSI C) are highly unlikely to have shared
	 * libraries at all, let alone a DSO_METHOD implemented for them.
	 */
	DSO_FUNC_TYPE(*dso_bind_func) (DSO* dso, const char* symname);
	/* I don't think this would actually be used in any circumstances. */
# if 0
	/* Unbinds a variable */
	int (*dso_unbind_var) (DSO * dso, char* symname, void* symptr);
	/* Unbinds a function */
	int (*dso_unbind_func) (DSO* dso, char* symname, DSO_FUNC_TYPE symptr);
# endif
	/*
	 * The generic (yuck) "ctrl()" function. NB: Negative return values
	 * (rather than zero) indicate errors.
	 */
	long (*dso_ctrl) (DSO* dso, int cmd, long larg, void* parg);
	/*
	 * The default DSO_METHOD-specific function for converting filenames to a
	 * canonical native form.
	 */
	DSO_NAME_CONVERTER_FUNC dso_name_converter;
	/*
	 * The default DSO_METHOD-specific function for converting filenames to a
	 * canonical native form.
	 */
	DSO_MERGER_FUNC dso_merger;
	/* [De]Initialisation handlers. */
	int (*init) (DSO* dso);
	int (*finish) (DSO* dso);
	/* Return pathname of the module containing location */
	int (*pathbyaddr) (void* addr, char* path, int sz);
	/* Perform global symbol lookup, i.e. among *all* modules */
	void* (*globallookup) (const char* symname);
} DSO_METHOD;

struct dso_st {
	DSO_METHOD* meth;
	/*
	 * Standard dlopen uses a (void *). Win32 uses a HANDLE. VMS doesn't use
	 * anything but will need to cache the filename for use in the dso_bind
	 * handler. All in all, let each method control its own destiny.
	 * "Handles" and such go in a STACK.
	 */
	STACK_OF(void)* meth_data;
	int references;
	int flags;
	/*
	 * For use by applications etc ... use this for your bits'n'pieces, don't
	 * touch meth_data!
	 */
	CRYPTO_EX_DATA ex_data;
	/*
	 * If this callback function pointer is set to non-NULL, then it will be
	 * used in DSO_load() in place of meth->dso_name_converter. NB: This
	 * should normally set using DSO_set_name_converter().
	 */
	DSO_NAME_CONVERTER_FUNC name_converter;
	/*
	 * If this callback function pointer is set to non-NULL, then it will be
	 * used in DSO_load() in place of meth->dso_merger. NB: This should
	 * normally set using DSO_set_merger().
	 */
	DSO_MERGER_FUNC merger;
	/*
	 * This is populated with (a copy of) the platform-independant filename
	 * used for this DSO.
	 */
	char* filename;
	/*
	 * This is populated with (a copy of) the translated filename by which
	 * the DSO was actually loaded. It is NULL iff the DSO is not currently
	 * loaded. NB: This is here because the filename translation process may
	 * involve a callback being invoked more than once not only to convert to
	 * a platform-specific form, but also to try different filenames in the
	 * process of trying to perform a load. As such, this variable can be
	 * used to indicate (a) whether this DSO structure corresponds to a
	 * loaded library or not, and (b) the filename with which it was actually
	 * loaded.
	 */
	char* loaded_filename;
};

struct st_dynamic_data_ctx {
	/* The DSO object we load that supplies the ENGINE code */
	DSO* dynamic_dso;
	/*
	 * The function pointer to the version checking shared library function
	 */
	dynamic_v_check_fn v_check;
	/*
	 * The function pointer to the engine-binding shared library function
	 */
	dynamic_bind_engine bind_engine;
	/* The default name/path for loading the shared library */
	const char* DYNAMIC_LIBNAME;
	/* Whether to continue loading on a version check failure */
	int no_vcheck;
	/* If non-NULL, stipulates the 'id' of the ENGINE to be loaded */
	const char* engine_id;
	/*
	 * If non-zero, a successfully loaded ENGINE should be added to the
	 * internal ENGINE list. If 2, the add must succeed or the entire load
	 * should fail.
	 */
	int list_add_value;
	/* The symbol name for the version checking function */
	const char* DYNAMIC_F1;
	/* The symbol name for the "initialise ENGINE structure" function */
	const char* DYNAMIC_F2;
	/*
	 * Whether to never use 'dirs', use 'dirs' as a fallback, or only use
	 * 'dirs' for loading. Default is to use 'dirs' as a fallback.
	 */
	int dir_load;
	/* A stack of directories from which ENGINEs could be loaded */
	STACK_OF(OPENSSL_STRING)* dirs;
};

typedef struct st_dynamic_data_ctx dynamic_data_ctx;


void CRYPTO_get_mem_functions(void* (__cdecl** m) (size_t),
	void* (__cdecl** r) (void*, size_t),
	void(__cdecl** f) (void*)) {}

static int dynamic_load(ENGINE* e, dynamic_data_ctx* ctx)
{


	return 0;
}

int __cdecl main()
{
	//malloc_func(16);

	//dyn_fns dnf;
	//
	//get_mem_fns(dnf.mem_fns);
}
