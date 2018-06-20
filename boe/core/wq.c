// Last Update:2018-06-20 19:04:43
/**
 * @file wq.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-18
 */

#include "common.h"
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include "msg_manager.h"
#include "list.h"

// wait response. 
typedef struct WMessage{
    uint32_t uid;     // unique id.
    uint32_t timeout; // timeout unit us.
    uint64_t sTime;   // timestamp of enter wait list..
    sem_t sem;
    check_response cFunc; // check response is waited.
    uint8_t **rcv_buff;
}WMessage;

// wait list.
typedef struct WaitNode{
    WMessage *wmsg;
    struct list_head list; 
}WaitNode;


// receive msg list.
typedef struct ReadNode{
    struct list_head list; 
}ReadNode;

typedef struct WQ_Handle{
    WaitNode wHead;
    pthread_mutex_t mLock;
    pthread_t thread;
    uint8_t  thFlag; // 1: stop thread, 2: finish exit thread.
}WQ_Handle;


void* loop_func(void *userdata)
{
    WQ_Handle *handle = (WQ_Handle*)userdata;
    WaitNode *head = &handle->wHead;
    WaitNode *pnode = NULL;
    struct list_head *pos, *next; 
    WMessage *m = NULL;

    while(handle->thFlag == 0)
    {
        uint8_t *pdata = NULL;
        uint32_t plen  = 0;
        //Todo : get msg from pool. msg_pool_fetch(&pdata, &plen);
        pthread_mutex_lock(&handle->mLock);
        list_for_each_safe(pos, next, &head->list) 
        { 
            pnode = list_entry(pos, WaitNode, list); 
            m = pnode->wmsg;

            if(plen > 0 && pdata != NULL &&
                    (1 == m->cFunc(pdata, plen, m->uid)))
            {
                *m->rcv_buff = (uint8_t *)malloc(plen);
                memcpy(*m->rcv_buff, pdata, plen);
                sem_post(&m->sem);

                list_del_init(pos);
                free(pnode);
            }else if((m->sTime + m->timeout) <= (get_timestamp_us()))
            {
                // timeout.
                sem_post(&m->sem);
                list_del_init(pos);
                free(pnode);
            }
        } 
        pthread_mutex_unlock(&handle->mLock);
    }
    list_for_each_safe(pos, next, &head->list) 
    { 
        pnode = list_entry(pos, WaitNode, list); 
        m = pnode->wmsg;
        sem_post(&m->sem);
        list_del_init(pos);
        free(pnode);
    } 
    handle->thFlag = 2;

    return NULL;
}

WMessage* WMessageNew(uint32_t uid, check_response cfunc, uint32_t timeout)
{
    WMessage *msg = (WMessage*)malloc(sizeof(WMessage));
    msg->uid = uid;
    msg->cFunc = cfunc;
    msg->timeout = timeout;
    sem_init(&msg->sem, 0, 0);
    msg->rcv_buff = NULL;
    return msg;
}

uint8_t* WMessageWait(WMessage *m)
{
    sem_wait(&m->sem);
    if(m->rcv_buff && *(m->rcv_buff))
        return *(m->rcv_buff);
    return NULL;
}

int WMessageFree(WMessage *m)
{
    sem_destroy(&m->sem);
    if(m->rcv_buff && (*m->rcv_buff))
        free(*(m->rcv_buff));
    free(m);
    return 0;
}

int wq_init(Context_t *ctx)
{
    int ret = 0;
    WQ_Handle *handle = (WQ_Handle*)malloc(sizeof(WQ_Handle));
    if(handle == NULL)
        return 1;
    INIT_LIST_HEAD(&handle->wHead.list);
    pthread_mutex_init(&handle->mLock, NULL);
    handle->thFlag = 0;
    ret = pthread_create(&handle->thread, NULL, loop_func, (void*)handle);
    if(ret != 0)
    {
        pthread_mutex_destroy(&handle->mLock);
        free(handle);
        return 1;
    }
    *ctx = handle;

    return 0;
}

int wq_push(Context_t ctx, WMessage *wmsg)
{
    WQ_Handle *handle = (WQ_Handle*)ctx;
    WaitNode *n = (WaitNode*)malloc(sizeof(WaitNode));
    if(n == NULL)
        return -1;
    wmsg->sTime = get_timestamp_us();
    n->wmsg = wmsg;
    pthread_mutex_lock(&handle->mLock);
    list_add_tail(&(n->list), &(handle->wHead.list));
    pthread_mutex_unlock(&handle->mLock);

    return 0;
}

int wq_final(Context_t *ctx)
{
    WQ_Handle *handle = (WQ_Handle*)(*ctx);
    handle->thFlag = 1;
    while(!(handle->thFlag == 2)) usleep(500);
    pthread_mutex_destroy(&handle->mLock);
    *ctx = NULL;

    return 0;
}
