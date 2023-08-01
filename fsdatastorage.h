#ifndef FSDataStorage_H
#define FSDataStorage_H

#include "cring.h"
#include "ctree.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct FSDataStorage {
    cnode_t * tree;
    cring_t   q;
    const char * name;
    void (*free)(void * const data, void * const user);
    void * user;
}FSDataStorage;

typedef struct FSDataItem {
    cnode_t  node;
    cring_t  q;
    uint64_t key;
    uint32_t end;
    size_t   len;
    uint8_t  data[1];
}FSDataItem;

FSDataStorage * FSDataStorage_Init (FSDataStorage * ds, const char * name, void * const destructor, void * const user);
void            FSDataStorage_Clean(FSDataStorage * ds);

FSDataItem * FSDataItem_New  (size_t len);
void         FSDataItem_Put  (FSDataStorage * ds,  uint32_t curTime, FSDataItem * d, uint32_t duration);
FSDataItem * FSDataItem_Get  (FSDataStorage * ds,  uint32_t curTime, uint64_t key);
FSDataItem * FSDataItem_Find (FSDataStorage * ds,  uint32_t curTime, uint64_t key);
void         FSDataItem_Del  (FSDataStorage * ds,  uint32_t curTime, FSDataItem * d);
void         FSDataItem_Renew(FSDataStorage * ds,  uint32_t curTime, FSDataItem * d, uint32_t duration);

#endif