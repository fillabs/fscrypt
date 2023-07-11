#ifndef fscrypt_h
#define fscrypt_h

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <e4c_lite.h>

#ifndef FITSEC_EXPORT
#define FITSEC_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FSCrypt FSCrypt;

FITSEC_EXPORT FSCrypt* FSCrypt_FindEngine(const char* name);

FITSEC_EXPORT bool FSCrypt_InitEngine(FSCrypt* const e, const char* params);
FITSEC_EXPORT bool FSCrypt_DeinitEngine( FSCrypt* const e, const char * params);

#ifdef FSCRYPT_ASYNC
/**
 * Check for finished async calls and execute async handlers
*/
typedef int (FSCrypt_Handler_fn) (FSCrypt * const engine, int rc, void * const user, ...);
FITSEC_EXPORT void FSCrypt_Proceed(FSCrypt * const e);
#endif

typedef enum FSHashAlg {
	FS_SHA256,
	FS_SHA384,
	FS_SM3,
	
	FSHashAlg_Max
}FSHashAlg;

static inline size_t FSHash_Size(FSHashAlg alg) {
	return (alg&0x01) ? 48 : 32;
}

static inline uint64_t FSHash_Digest(FSHashAlg alg, const uint8_t * hash) {
    return *(uint64_t*) (hash + ((alg&0x01) ? 40 : 24));
}

size_t FITSEC_EXPORT FSHash_Calc(FSCrypt * const engine, FSHashAlg alg,
   			  		const void * const ptr, const size_t size,
			  		uint8_t * const digest);

#ifdef FSCRYPT_ASYNC
int    FITSEC_EXPORT FSHash_Calc_a(FSCrypt * const engine, FSHashAlg alg,
			    	const void * const ptr, const size_t size,
					const FSCrypt_Handler_fn * const handler, void * const user);
#endif

const uint8_t* FSHash_EmptyString(FSHashAlg alg);

typedef enum FSCurve {
	FS_NISTP256,
	FS_BRAINPOOLP256R1,
	FS_BRAINPOOLP384R1,
	FS_NISTP384,
	FS_SM2,

	FSCurve_Max
}FSCurve;

static inline bool FSCurveIs384(FSCurve curve) {
	return (curve&0x02);
}

static inline size_t FSCurveFieldSize(FSCurve curve) {
	return (curve&0x02) ? 48 : 32;
}

static inline FSHashAlg FSCurveHashAlg(FSCurve curve) {
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

FITSEC_EXPORT FSPrivateKey*   FSKey_ImportPrivate   (FSCrypt* e, FSCurve curve, const uint8_t * data, size_t len);
FITSEC_EXPORT void            FSKey_InitPublic 	    (FSPublicKey * k, FSCurve curve, FSPointType  pType, const uint8_t * x, const uint8_t * y);

FITSEC_EXPORT FSPrivateKey*   FSKey_Generate        (FSCrypt* e, FSCurve curve, FSPublicKey * k);

FITSEC_EXPORT void            FSKey_FreePrivate     (FSCrypt* e, FSPrivateKey* k);
FITSEC_EXPORT void            FSKey_CleanPublic     (FSCrypt* e, FSPublicKey * k);

FITSEC_EXPORT bool            FSKey_ExportPublic    (FSCrypt* e, FSCurve curve, const FSPrivateKey * pK, FSPublicKey * k);

FITSEC_EXPORT size_t          FSKey_Derive          (FSCrypt* e, const FSPublicKey* k, const FSPrivateKey* eph,
														const void* salt, size_t salt_len,
														void* digest, size_t digest_len);

FITSEC_EXPORT bool            FSKey_ReconstructPublic(FSCrypt* e, const FSPublicKey* rv, 
														const FSPublicKey* ca, const unsigned char * hash);


typedef struct FSSignature {
    FSCurve   curve;
    FSECPoint point;
    uint8_t * s;
}FSSignature;

FITSEC_EXPORT bool FSSignature_Sign(FSCrypt* e, FSSignature * s, const FSPrivateKey* k, const uint8_t * digest);

FITSEC_EXPORT bool FSSignature_Verify(FSCrypt* e, const FSSignature * s, const FSPublicKey* pk, const uint8_t * digest);

typedef enum {
	FS_HMAC256
} FSMAC;
FITSEC_EXPORT size_t FSCrypt_MAC(FSCrypt* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out);

typedef enum {
	FS_AES_128_CCM = 0,
	FS_SM4_CCM,

	FSSymmAlg_Max
}FSSymmAlg;

inline size_t FSSymm_KeySize(FSSymmAlg alg) {
	return 16;
}

FITSEC_EXPORT size_t FSSymm_Encrypt(FSCrypt* e, FSSymmAlg alg,
                                        const uint8_t* key, const uint8_t* nonce,
                                        const uint8_t* in_buf, size_t in_size,
                                        uint8_t* out_buf, size_t out_size);
FITSEC_EXPORT size_t FSSymm_Decrypt(FSCrypt* e, FSSymmAlg alg,
                                        const uint8_t* key, const uint8_t* nonce,
                                        const uint8_t* in_buf, size_t in_size,
                                        uint8_t* out_buf, size_t out_size);

FITSEC_EXPORT void   FS_Random(FSCrypt* e, void* ptr, size_t const len);


#ifdef __cplusplus
}
#endif

#endif
