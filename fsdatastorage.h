#ifndef FSDataStorage_H
#define FSDataStorage_H

#ifndef FSDS_EXPORT
# ifdef _MSC_VER
#  ifdef LIBFSCRYPT_EXPORTS
#   define FSDS_EXPORT __declspec(dllexport)
#  else
#   define FSDS_EXPORT __declspec(dllimport)
#  endif
# else
#  define FSDS_EXPORT
# endif
#endif

#include "cring.h"
#include "ctree.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct FSDataStorage {
        cnode_t* tree;
        cring_t   q;
        const char* name;
        void (*free)(void* const data, void* const user);
        void* user;
    }FSDataStorage;

    typedef struct FSDataItem {
        cnode_t  node;
        cring_t  q;
        uint64_t key;
        uint32_t end;
        size_t   len;
        uint8_t  data[1];
    }FSDataItem;

    FSDS_EXPORT
        FSDataStorage* FSDataStorage_Init(FSDataStorage* ds, const char* name, void* const destructor, void* const user);
    FSDS_EXPORT
        void            FSDataStorage_Clean(FSDataStorage* ds);

    FSDS_EXPORT
        FSDataItem* FSDataItem_New(size_t len);
    FSDS_EXPORT
        void         FSDataItem_Put(FSDataStorage* ds, uint32_t curTime, FSDataItem* d, uint32_t duration);
    FSDS_EXPORT
        FSDataItem* FSDataItem_Get(FSDataStorage* ds, uint32_t curTime, uint64_t key);
    FSDS_EXPORT
        FSDataItem* FSDataItem_Find(FSDataStorage* ds, uint32_t curTime, uint64_t key);
    FSDS_EXPORT
        void         FSDataItem_Del(FSDataStorage* ds, uint32_t curTime, FSDataItem* d);
    FSDS_EXPORT
        void         FSDataItem_Renew(FSDataStorage* ds, uint32_t curTime, FSDataItem* d, uint32_t duration);

#ifdef __cplusplus
}
#endif

#endif