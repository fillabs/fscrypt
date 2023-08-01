#include "fsdatastorage.h"

#include <cmem.h>
#include <cstr.h>

static int _FSDataItem_compare_with_key (const FSDataItem * node, const uint64_t * pkey)
{
    return (node->key - *pkey);
}
static int _FSDataItem_compare_with_node (const FSDataItem * node, const FSDataItem * value)
{
    return (node->key - value->key);
}

static void _FSDataItem_purge(FSDataStorage * storage, uint32_t curTime)
{
    cring_t * r = cring_prev(&storage->q);
    while(r != &storage->q){
        FSDataItem * d = cring_cast(FSDataItem, q, r);
        if(d->end >= curTime)
            break;
#ifdef FS_STOREDDATA_DEBUG
        fprintf(stderr, "%-5.5s [%u] EXP " PrHID8 "(%u):", storage->name, curTime, d->key, d->endTime);
        for(int i=0; i < 8; i++) fputc(d->data[0], stderr);
        fputc('\n', stderr); 
#endif
        ctree_splay_del_node(&storage->tree, &d->node);
        r = cring_erase_left(r);
        storage->free(d, storage->user);
    }
}

static void _do_nothing(void*n) {}

FSDataStorage * FSDataStorage_Init (FSDataStorage * ds, const char * name, void * const destructor, void * const user)
{
    if(ds == NULL) {
        int l = cstrlen(name);
        ds = cnew_ex(FSDataStorage, l + 1);
        ds->name = (const char*)(ds + 1);
        cstrcpy((char*)ds->name, name);
    }else{
        ds->name = name;
    }
    ds->free = destructor ? destructor : _do_nothing;
    ds->tree = NULL;
    cring_init(&ds->q);
    return ds;
}

void FSDataStorage_Clean(FSDataStorage * ds)
{
    ds->tree = NULL;
    cring_foreach(cring_t, r, ds->q){
        ds->free(cring_cast(FSDataItem, q, r), ds->user);
    }
    if(ds->name == (const char*)(ds+1)){
        free(ds);
    }
}

FSDataItem * FSDataItem_New(size_t len)
{
    FSDataItem * d = cnew0_ex(FSDataItem, len);
    d->len = len;
    cring_init(&d->q);
    return d;
}

void FSDataItem_Renew(FSDataStorage * storage, uint32_t curTime, FSDataItem * d, uint32_t duration)
{
#ifdef FS_STOREDDATA_DEBUG
    fprintf(stderr, "%-5.5s [%u] UPD " PrHID8 " (%u)", storage->name, curTime, d->key, d->endTime);
    for(int i=0; i < 8; i++) fprintf(stderr,  "%02X", d->data[i]);
    fputc('\n', stderr); 
#endif
    cring_erase(&d->q);
    if(curTime){
        _FSDataItem_purge(storage, curTime);
    }else{
        duration = 0xFFFFFFFF;
    }
    d->end = curTime + duration;
    cring_enqueue(&storage->q, &d->q);
}
void FSDataItem_Put (FSDataStorage * storage, uint32_t curTime, FSDataItem * d, uint32_t duration)
{
    if(curTime){
        _FSDataItem_purge(storage, curTime);
    }else{
        duration = 0xFFFFFFFF;
    }
    d->end = curTime + duration;
#ifdef FS_STOREDDATA_DEBUG
    fprintf(stderr, "%-5.5s [%u] PUT " PrHID8 " (%u)", storage->name, curTime, d->key, d->endTime);
    for(int i=0; i < 8; i++) fprintf(stderr,  "%02X", d->data[i]);
    fputc('\n', stderr); 
#endif
    cring_erase(&d->q); // erase it in any case to prevent double-free
    FSDataItem * o = (FSDataItem *)ctree_splay_add(&storage->tree, _FSDataItem_compare_with_node, &d->node, true);
    if(d != o){
#ifdef FS_STOREDDATA_DEBUG
        fprintf(stderr, "               RM  OLD " PrHID8 " (%u)", o->key, o->endTime);
        for(int i=0; i < 8; i++) fprintf(stderr,  "%02X", o->data[i]);
        fputc('\n', stderr); 
#endif
        storage->free(o, storage->user);
    }
    cring_enqueue(&storage->q, &d->q);
}

FSDataItem *  FSDataItem_Get (FSDataStorage * storage, uint32_t curTime, uint64_t key)
{
    if(curTime){
        _FSDataItem_purge(storage, curTime);
    }
    FSDataItem * d = (FSDataItem *)ctree_splay_del(&storage->tree, _FSDataItem_compare_with_key, &key);
    if(d){
#ifdef FS_STOREDDATA_DEBUG
        fprintf(stderr, "%-5.5s [%u] GET " PrHID8 " (0x%u)", storage->name, curTime, d->key, d->endTime);
        for(int i=0; i < 8; i++) fprintf(stderr,  "%02X", d->data[i]);
        fputc('\n', stderr); 
#endif
        cring_erase(&d->q);
#ifdef FS_STOREDDATA_DEBUG
    }else{
        fprintf(stderr, "%-5.5s [%u] GET " PrHID8 " (none)\n", storage->name, curTime, key);
#endif
    }
    return d;
}

FSDataItem *  FSDataItem_Find (FSDataStorage * storage, uint32_t curTime, uint64_t key)
{
    if(curTime){
        _FSDataItem_purge(storage, curTime);
    }
    FSDataItem * d = (FSDataItem *)ctree_splay_find(&storage->tree, _FSDataItem_compare_with_key, &key);
#ifdef FS_STOREDDATA_DEBUG
    if(d){
        fprintf(stderr, "%-5.5s [%u] FND " PrHID8 " (%u)", storage->name, curTime, d->key, d->endTime);
        for(int i=0; i < 8; i++) fprintf(stderr,  "%02X", d->data[i]);
        fputc('\n', stderr); 
    }else{
        fprintf(stderr, "%-5.5s [%u] FND " PrHID8 " (none)\n", storage->name, curTime, key);
    }
#endif
    return d;
}

void FSDataItem_Del  (FSDataStorage * storage, uint32_t curTime, FSDataItem * d)
{
#ifdef FS_STOREDDATA_DEBUG
    fprintf(stderr, "%-5.5s [%u] DEL " PrHID8 " (%u)\n", storage->name, curTime, d->key, d->endTime);
    for(int i=0; i < 8; i++) fprintf(stderr,  "%02X", d->data[i]);
    fputc('\n', stderr); 
#endif
    ctree_splay_del_node(&storage->tree, &d->node);
    cring_erase(&d->q);
    storage->free(d, storage->user);
    if(curTime){
        _FSDataItem_purge(storage, curTime);
    }
}
