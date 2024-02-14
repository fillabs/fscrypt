#ifndef FITSEC_PLUGIN_H
#define FITSEC_PLUGIN_H

#include "fscrypt.h"
#include <cring.h>
#include <stdlib.h>
#include <stdbool.h>
#ifndef FSCRYPT_EXPORT
#define FSCRYPT_EXPORT
#endif
#ifdef __cplusplus
extern "C" {
#endif

    typedef struct FSSignature FSSignature;

    typedef bool   (FSCrypt_Init_Fn)      (FSCrypt * e, const char * params);
    
    typedef void (FSRandom_Fn)(FSCrypt * e, void * ptr, size_t length);

    typedef struct {
        bool  (*Sign)    (FSCrypt * e, const FSPrivateKey * key,
                          FSSignature * s, const uint8_t * digest, const uint8_t * k);
        bool  (*Verify)  (FSCrypt * e, const FSPublicKey * pk,
                          const FSSignature * s, const uint8_t * digest);
    }FSSignatureOps;

    typedef struct {
        // allocate new private key 
        FSPrivateKey*   (*Import)      (FSCrypt* c, FSCurve curve, const uint8_t * data, size_t len);
        bool            (*Generate)    (FSCrypt* c, FSCurve curve,
                                        FSPrivateKey** pPrivateKey, FSPublicKey * publicKey);
        void            (*FreePrivate) (FSCrypt* c, FSPrivateKey* k);
        void            (*FreePublic)  (FSCrypt* c, FSPublicKey* k);
        bool            (*ExportPublic)(FSCrypt* c,  
                                        const FSPrivateKey* k, FSPublicKey * publicKey);
        size_t          (*ExportPrivate)(FSCrypt* c, const FSPrivateKey* priv, uint8_t * buf);
        bool            (*ReconstructPublic) (FSCrypt* c, FSPublicKey* rv, const FSPublicKey * ca, const uint8_t * digest);
        size_t          (*Derive)      (FSCrypt* e,
                                        const FSPublicKey* k, const FSPrivateKey* eph,
                                        const void* salt, size_t salt_len,
                                        void* digest, size_t digest_len);
    }FSEccKeyOps;

    typedef struct FSCryptSymmOps {

        size_t          (*Encrypt)    (FSCrypt* e, FSSymmAlg alg,
                                       const uint8_t * key, const uint8_t * nonce,
                                       const uint8_t* in_buf,  size_t in_size,
                                       uint8_t* out_buf, size_t out_size);

        size_t          (*Decrypt)    (FSCrypt* e, FSSymmAlg alg,
                                       const uint8_t* key, const uint8_t* nonce,
                                       const uint8_t* in_buf, size_t in_size,
                                       uint8_t* out_buf, size_t out_size);
    }FSCryptSymmOps;

    typedef struct FSMACOps {
        size_t (*mac)(FSCrypt * e, FSMAC alg, const uint8_t * data, size_t size, const uint8_t * key, size_t key_len, uint8_t * out);
    }FSMACOps;

    typedef struct FSHashOps
    {
        size_t       (*Calc)          (FSCrypt * e, FSHashAlg alg, const void* data, size_t len, uint8_t* digest);
    }FSHashOps;

    struct FSCrypt
    {
        FSCrypt* _next;
        const char* name;
        const char* description;

        FSCrypt_Init_Fn          * Init;
        FSCrypt_Init_Fn          * Deinit;
        const FSHashOps          * HashOps;
        const FSSignatureOps     * SignatureOps;
        const FSEccKeyOps        * KeyOps;
        const FSCryptSymmOps     * SymmOps;
        const FSMACOps           * MACOps;
        FSRandom_Fn              * Random;
        // to be extended in plugin
    };

    FSCRYPT_EXPORT void FSCrypt_Register(FSCrypt* e);

#ifdef __cplusplus
}
#endif

#endif
