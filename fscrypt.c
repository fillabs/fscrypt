/*********************************************************************
 * This file is a part of FItsSec2 project: Implementation of 
 * IEEE Std. 1609.2,
 * ETSI TS 103 097 v1.3.1,
 * ETSI TS 102 941 v1.3.1
 * Copyright (C) 2020  Denis Filatov (denis.filatov()fillabs.com)

 * This file is NOT a free or open source software and shall not me used
 * in any way not explicitly authorized by the author.
*********************************************************************/

#include "fscrypt_plugin.h"
#include <e4c_lite.h>
#include <cstr.h>
#include <assert.h>

static FSCrypt* _e = NULL;

FSCRYPT_EXPORT
void FSCrypt_Register(FSCrypt* e)
{
    e->_next = _e;
    _e = e;
}

#ifndef FS_ECC_DEFAULT_ENGINE
#define FS_ECC_DEFAULT_ENGINE "openssl"
#endif

FSCRYPT_EXPORT
FSCrypt* FSCrypt_FindEngine(const char* name)
{
    FSCrypt* e = _e;
    if (name == NULL)
        name = FS_ECC_DEFAULT_ENGINE;
    for(; e; e=e->_next){
        if(cstrequal(name, e->name))
            break;
    }
    return e;
}

FSCRYPT_EXPORT
bool FSCrypt_InitEngine( FSCrypt* const e, const char * params)
{
    if(e && e->Init){
        return e->Init(e, params);
    }
    return true;
}

FSCRYPT_EXPORT
bool FSCrypt_DeinitEngine( FSCrypt* const e, const char * params)
{
    if(e && e->Deinit){
        return e->Deinit(e, params);
    }
    return true;
}

FSCRYPT_EXPORT
void FSKey_InitPublic (FSPublicKey * k, FSCurve curve, FSPointType  pType, const uint8_t * x, const uint8_t * y)
{
    k->k = NULL;
    k->curve = curve;
    k->point.type = pType;
    k->point.x = (uint8_t*) x;
    k->point.y = (uint8_t*) ((pType == FS_UNCOMPRESSED) ? y : NULL);
}

FSCRYPT_EXPORT
bool FSKey_ExportPublic (FSCrypt* e, const FSPrivateKey * pK, FSPublicKey * k)
{
    return e->KeyOps->ExportPublic(e, pK, k);
}

FSCRYPT_EXPORT
void FSKey_CleanPublic (FSCrypt* e, FSPublicKey * k)
{
    e->KeyOps->FreePublic(e, k);
}

FSCRYPT_EXPORT
FSPrivateKey*   FSKey_ImportPrivate (FSCrypt* e, FSCurve curve, const uint8_t * data, size_t len)
{
    if(data && len)
        return e->KeyOps->Import(e, curve, data, len);
    return NULL;
}

FSCRYPT_EXPORT
FSPrivateKey*   FSKey_Generate        (FSCrypt* e, FSCurve curve, FSPublicKey * k)
{
    FSPrivateKey* pK = NULL;
    if(!e->KeyOps->Generate(e, curve, &pK, k)) {
        pK = NULL;
    }
    return pK;
}

FSCRYPT_EXPORT
void FSKey_FreePrivate     (FSCrypt* e, FSPrivateKey* k)
{
    e->KeyOps->FreePrivate(e, k);
}

FSCRYPT_EXPORT
void FS_Random(FSCrypt* e, void* ptr, size_t const len)
{
    e->Random(e, ptr, len);
}

FSCRYPT_EXPORT
size_t FSKey_Derive(FSCrypt* e, const FSPublicKey* k, const FSPrivateKey* pK,
    const void* salt, size_t salt_len,
    void* digest, size_t digest_len)
{
#ifdef FSCRYPT_HAVE_ENCRYPTION
    return e->KeyOps->Derive(e, k, pK, salt, salt_len, digest, digest_len);
#else
    return 0;
#endif
}

FSCRYPT_EXPORT
bool FSKey_ReconstructPublic(FSCrypt* e, const FSPublicKey* rv, const FSPublicKey* ca, const unsigned char * hash)
{
    return e->KeyOps->ReconstructPublic(e, (FSPublicKey*)rv, ca, hash);
}

FSCRYPT_EXPORT
size_t FSKey_ExportPrivate   (FSCrypt* e, const FSPrivateKey * pK, uint8_t * buf)
{
    return e->KeyOps->ExportPrivate(e, pK, buf);
}

/*
void FN_THROW(RuntimeException) FSEccPoint_Read(FSECPoint* p, FSCurve curve, const char** ptr, const char* end, int error)
{
    uint8_t * s = (uint8_t *)(*ptr);
    size_t psize = FSEccPoint_Size(curve);
    if (*s < 0x80 || *s > (0x80 + FS_UNCOMPRESSED))
        throw(RuntimeException, error | FSERR_ECC_POINT | FSERR_TYPE | FSERR_PARSEERROR, NULL);
    p->type = (*s) & 0x3F;
    p->x = s + 1;
    if(p->type == FS_UNCOMPRESSED){
        p->y = p->x + psize;
        *ptr = (const char*)p->y + psize;
    }else{
        p->y = NULL;
        *ptr = (const char*)p->x + psize;
    }
    if( (*ptr) > end){
            throw(RuntimeException, error | FSERR_ECC_POINT | FSERR_NOSPACE, NULL);
    }
}

void FN_THROW(RuntimeException) FSSignature_Read(FSSignature* s, const char** ptr, const char* end, int error)
{
    const uint8_t * b = (const uint8_t*)*ptr;

    s->curve = *(b++);
    if (s->curve < 0x80 || s->curve >= (0x80 + FSCurve_Max)) {
        throw(RuntimeException, error | FSERR_SIGNATURE | FSERR_PK_ALGORITHM | FSERR_PARSEERROR, NULL);
    }
    s->curve &= 0x3F;
    if (s->curve > FS_BRAINPOOLP256R1) {
        // skip extension length
        size_t l = *(b++);
        if ((b + l) > (const uint8_t*)end) {
            throw(RuntimeException, error | FSERR_SIGNATURE | FSERR_NOSPACE, NULL);
        }
    }

    FSEccPoint_Read(&s->point, s->curve, (const char**)&b, end, error);
    s->s = (uint8_t*)b;
    *ptr = (const char*)b + FSEccPoint_Size(s->curve);
}
*/

FSCRYPT_EXPORT
bool FSSignature_Sign_ex(FSCrypt* e, FSSignature * s, const FSPrivateKey* key, const uint8_t * digest, const uint8_t * k)
{
    return e->SignatureOps->Sign(e, key, s, digest, k);
}

FSCRYPT_EXPORT
bool FSSignature_Sign(FSCrypt* e, FSSignature * s, const FSPrivateKey* key, const uint8_t * digest)
{
    return e->SignatureOps->Sign(e, key, s, digest, NULL);
}

FSCRYPT_EXPORT
bool FSSignature_Verify(FSCrypt* e, const FSSignature * s, const FSPublicKey* pk, const uint8_t * digest)
{
    return e->SignatureOps->Verify(e, pk, s, digest);
}
static const char * _sym_names[] = {
    "AES128_CCM",
    "SM4_CCM"
};

FSCRYPT_EXPORT
const char * FSSymm_AlgName(FSSymmAlg alg){
    return (alg < arraysize(_sym_names)) ? _sym_names[alg] : "UNKNOWN";
}

FSCRYPT_EXPORT
size_t FSSymm_Encrypt(FSCrypt* e, FSSymmAlg alg,
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* in_buf, size_t in_size,
    uint8_t* out_buf, size_t out_size)
{
#ifdef FSCRYPT_HAVE_ENCRYPTION
    return e->SymmOps->Encrypt(e, alg, key, nonce, in_buf, in_size, out_buf, out_size);
#else
    return 0;
#endif
}

FSCRYPT_EXPORT
size_t FSSymm_Decrypt(FSCrypt* e, FSSymmAlg alg,
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* in_buf, size_t in_size,
    uint8_t* out_buf, size_t out_size)
{
#ifdef FSCRYPT_HAVE_ENCRYPTION
    return e->SymmOps->Decrypt(e, alg, key, nonce, in_buf, in_size, out_buf, out_size);
#else
    return 0;
#endif
}

FSCRYPT_EXPORT
size_t FSCrypt_MAC(FSCrypt* e, FSMAC alg, const uint8_t* data, size_t size, const uint8_t* key, size_t key_len, uint8_t* out)
{
#ifdef FSCRYPT_HAVE_ENCRYPTION
    return e->MACOps->mac(e, alg, data, size, key, key_len, out);
#endif
    return 0;
}

FSCRYPT_EXPORT
size_t FSHash_Calc(FSCrypt* e, FSHashAlg alg, const void* data, size_t len, uint8_t* md)
{
    const FSHashOps* ops = e->HashOps;
    if (ops && ops->Calc) {
        return ops->Calc(e, alg, data, len, md);
    }
    return 0;
}

const uint8_t _h_empty_sha256[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
const uint8_t _h_empty_sha384[] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};
const uint8_t _h_empty_sm3[] = {
    0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F, 0x8E, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
    0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74, 0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B
};
const uint8_t* _h_empty[] = {
    &_h_empty_sha256[0], 
    &_h_empty_sha384[0],
    &_h_empty_sm3[0]
};

FSCRYPT_EXPORT
const uint8_t* FSHash_EmptyString(FSHashAlg alg)
{
    assert(alg < (sizeof(_h_empty) / sizeof(_h_empty[0])));
    return _h_empty[alg];
}
