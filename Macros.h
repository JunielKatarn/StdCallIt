#pragma once

# define LHASH_OF(type) struct lhash_st_##type
# define STACK_OF(type) struct stack_st_##type

#define BN_CTX_POOL_SIZE        16
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
