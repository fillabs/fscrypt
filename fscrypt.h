#ifndef fscrypt_h
#define fscrypt_h

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <e4c_lite.h>

#ifndef FSCRYPT_EXPORT
# ifdef _MSC_VER
#  ifdef LIBFSCRYPT_EXPORTS
#   define FSCRYPT_EXPORT __declspec(dllexport)
#  else
#   define FSCRYPT_EXPORT __declspec(dllimport)
#  endif
# else
#  define FSCRYPT_EXPORT
# endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FSCrypt FSCrypt;

FSCRYPT_EXPORT FSCrypt* FSCrypt_FindEngine(const char* name);

FSCRYPT_EXPORT bool FSCrypt_InitEngine(FSCrypt* const e, const char* params);
FSCRYPT_EXPORT bool FSCrypt_DeinitEngine( FSCrypt* const e, const char * params);

#ifdef FSCRYPT_ASYNC
/**
 * Check for finished async calls and execute async handlers
*/
typedef int (FSCrypt_Handler_fn) (FSCrypt * const engine, int rc, void * const user, ...);
FSCRYPT_EXPORT void FSCrypt_Proceed(FSCrypt * const e);
#endif

typedef enum FSHashAlg {
	FS_SHA256,
	FS_SHA384,
	FS_SM3,
	
	FSHashAlg_Max
}FSHashAlg;

static inline uint8_t FSHash_Size(FSHashAlg alg) {
	return (alg&0x01) ? 48 : 32;
}
#define FSHash_Digest(SIZE,PTR) (*(uint64_t*)((PTR)-8+SIZE))
static inline uint64_t FSHash_DigestByHashAlg(FSHashAlg alg, const uint8_t * hash) {
    return *(uint64_t*) (hash + ((alg&0x01) ? 40 : 24));
}

FSCRYPT_EXPORT
size_t FSHash_Calc(FSCrypt * const engine, FSHashAlg alg,
   			  		const void * const ptr, const size_t size,
			  		uint8_t * const digest);

#ifdef FSCRYPT_ASYNC
FSCRYPT_EXPORT
int    FSHash_Calc_a(FSCrypt * const engine, FSHashAlg alg,
			    	const void * const ptr, const size_t size,
					const FSCrypt_Handler_fn * const handler, void * const user);
#endif

FSCRYPT_EXPORT
const uint8_t* FSHash_EmptyString(FSHashAlg alg);

typedef enum FSCurve {
	FS_NISTP256,
	FS_BRAINPOOLP256R1,
	FS_BRAINPOOLP384R1,
	FS_NISTP384,
	FS_SM2,

	FSCurve_Max
}FSCurve;

static inline bool FSCurve_Is384(FSCurve curve) {
	return (curve&0x02);
}

static inline uint8_t FSCurve_FieldSize(FSCurve curve) {
	return (curve&0x02) ? 48 : 32;
}

static inline FSHashAlg FSCurve_HashAlg(FSCurve curve) {
	return (curve&0x04) ? FS_SM3 : (curve&0x02) ? FS_SHA384 : FS_SHA256;
}

typedef enum {
	FS_X_COORDINATE_ONLY = 0,
	FS_COMPRESSED_LSB_Y_0 = 2,
	FS_COMPRESSED_LSB_Y_1 = 3,
	FS_UNCOMPRESSED = 4
}FSPointType;

typedef struct FSECPoint {
	FSPointType type;
	uint8_t     * x;
	uint8_t     * y;
} FSECPoint;

typedef struct FSPublicKey {
	FSCurve   curve;
	FSECPoint point;
	void    * k; // for plugin usage
}FSPublicKey;
#define FSPublicKey_Exists(key) (key != NULL && key->point.x != NULL)

typedef void * FSPrivateKey;

FSCRYPT_EXPORT FSPrivateKey*   FSKey_ImportPrivate   (FSCrypt* e, FSCurve curve, const uint8_t * data, size_t len);
FSCRYPT_EXPORT void            FSKey_InitPublic 	    (FSPublicKey * k, FSCurve curve, FSPointType  pType, const uint8_t * x, const uint8_t * y);

FSCRYPT_EXPORT FSPrivateKey*   FSKey_Generate        (FSCrypt* e, FSCurve curve, FSPublicKey * k);

FSCRYPT_EXPORT void            FSKey_FreePrivate     (FSCrypt* e, FSPrivateKey* k);
FSCRYPT_EXPORT void            FSKey_CleanPublic     (FSCrypt* e, FSPublicKey * k);

FSCRYPT_EXPORT bool            FSKey_ExportPublic    (FSCrypt* e, const FSPrivateKey * pK, FSPublicKey * k);
FSCRYPT_EXPORT size_t          FSKey_ExportPrivate   (FSCrypt* e, const FSPrivateKey * pK, uint8_t * buf);

FSCRYPT_EXPORT size_t          FSKey_Derive          (FSCrypt* e, const FSPublicKey* k, const FSPrivateKey* eph,
														const void* salt, size_t salt_len,
														void* digest, size_t digest_len);

FSCRYPT_EXPORT bool            FSKey_ReconstructPublic(FSCrypt* e, const FSPublicKey* rv, 
														const FSPublicKey* ca, const unsigned char * hash);


typedef struct FSSignature {
    FSCurve   curve;
    FSECPoint point;
    uint8_t * s;
}FSSignature;

FSCRYPT_EXPORT bool FSSignature_Sign(FSCrypt* e, FSSignature * s, const FSPrivateKey* key, const uint8_t * digest);
FSCRYPT_EXPORT bool FSSignature_Sign_ex(FSCrypt* e, FSSignature * s, const FSPrivateKey* key, const uint8_t * digest, const uint8_t * k);

FSCRYPT_EXPORT bool FSSignature_Verify(FSCrypt* e, const FSSignature * s, const FSPublicKey* pk, const uint8_t * digest);

typedef enum {
	FS_HMAC256
} FSMAC;
FSCRYPT_EXPORT size_t FSCrypt_MAC(FSCrypt* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out);

typedef enum {
	FS_AES_128_CCM = 0,
	FS_SM4_CCM,

	FSSymmAlg_Max
}FSSymmAlg;

static inline uint8_t FSSymm_KeySize(FSSymmAlg alg) {
	return 16;
}
FSCRYPT_EXPORT const char * FSSymm_AlgName(FSSymmAlg alg);

FSCRYPT_EXPORT size_t FSSymm_Encrypt(FSCrypt* e, FSSymmAlg alg,
                                        const uint8_t* key, const uint8_t* nonce,
                                        const uint8_t* in_buf, size_t in_size,
                                        uint8_t* out_buf, size_t out_size);
FSCRYPT_EXPORT size_t FSSymm_Decrypt(FSCrypt* e, FSSymmAlg alg,
                                        const uint8_t* key, const uint8_t* nonce,
                                        const uint8_t* in_buf, size_t in_size,
                                        uint8_t* out_buf, size_t out_size);

FSCRYPT_EXPORT void   FS_Random(FSCrypt* e, void* ptr, size_t const len);


#ifdef __cplusplus
}
#endif

#endif
