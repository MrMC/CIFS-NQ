/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#include "cmthread.h"

/* -- Static data -- */
static NQ_UINT16 nextPort;	/* next port number to use */
static NQ_PORT freePort;	/* last released port */
static CMList threads;		/* running threads, not including internal*/
static const NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;	/* local IP in NBO */

/* -- Static functions -- */

/*
 * Callback for thread unlock and disposal:
 */
static NQ_BOOL unlockCallback(CMItem * pItem)
{
	CMThread * pThread = (CMThread *)pItem;

    cmThreadCondRelease(&pThread->syncCond);
    cmThreadCondRelease(&pThread->asyncCond);
    if (NULL != pThread->context)
    {
        cmMemoryFree(pThread->context);
        pThread->context = NULL;
    }
    return FALSE;
}

/* -- API Functions */

NQ_BOOL cmThreadStart(void)
{
    cmListStart(&threads);
	nextPort = UD_NS_INTERNALNSPORT + 10;
	freePort = nextPort;
	return TRUE;
}

void cmThreadShutdown(void)
{
	CMIterator 	iterator;

	cmListIteratorStart(&threads, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMThread * pThread; /* casted pointer */

        pThread = (CMThread *)cmListIteratorNext(&iterator);
		if (pThread->context != NULL)
        { 
        	cmMemoryFree(pThread->context);
        }
        cmThreadCondRelease(&pThread->syncCond);
        cmThreadCondRelease(&pThread->asyncCond);
    }
    cmListIteratorTerminate(&iterator);
	
    cmListShutdown(&threads);
}

NQ_BOOL cmThreadCreateAndRun(CMThread * thread, void (* body)(void), NQ_BOOL background)
{
    cmThreadCondSet(&thread->syncCond);
    cmThreadCondSet(&thread->asyncCond);
	syThreadStart(&thread->thread, body, background);
    return syIsValidThread(thread->thread);
}

void cmThreadStopAndDestroy(CMThread * thread)
{
	syThreadDestroy(thread->thread);
    cmThreadCondRelease(&thread->syncCond);
    cmThreadCondRelease(&thread->asyncCond);
}

CMThread * cmThreadGetCurrent(void)
{
    CMIterator iterator;            /* in the list of threads */
    CMThread * curThread = NULL;    /* the result */
    SYThread sysHandle;             /* system handle for the current one */
    
    sysHandle = syThreadGetCurrent();

    cmListIteratorStart(&threads, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMThread * pThread; /* casted pointer */

        pThread = (CMThread *)cmListIteratorNext(&iterator);
        if (pThread->thread == sysHandle)
        {
            curThread = pThread;
            break;
        }
    }
    cmListIteratorTerminate(&iterator);
    if (NULL == curThread)
    {
        curThread = (CMThread *)cmListItemCreateAndAdd(&threads, sizeof(CMThread), NULL, unlockCallback , FALSE);
        if (NULL == curThread)
            return NULL;
        curThread->thread = sysHandle;
        curThread->context = NULL;
        curThread->element.item.name = NULL;
        curThread->element.thread = curThread;
        cmThreadCondSet(&curThread->syncCond);
        cmThreadCondSet(&curThread->asyncCond);
    }
    return curThread;
}

void cmThreadSubscribe(void)
{
    cmThreadGetCurrent();
}

void cmThreadUnsubscribe(void)
{
    CMIterator iterator;            /* in the list of threads */
    CMThread * curThread = NULL;    /* the result */
    SYThread sysHandle;             /* system handle for the current one */
    
    sysHandle = syThreadGetCurrent();

    cmListIteratorStart(&threads, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMThread * pThread; /* casted pointer */

        pThread = (CMThread *)cmListIteratorNext(&iterator);
        if (pThread->thread == sysHandle)
        {
            curThread = pThread;
            break;
        }
    }
    cmListIteratorTerminate(&iterator);
    if (NULL != curThread)
    {
        cmListItemUnlock((CMItem *)curThread->context);
    	cmMemoryFree(curThread->context);
        curThread->context = NULL;
        cmListItemRemoveAndDispose(&curThread->item);
    }
}

void * cmThreadGetContext(CMThread * pThread, NQ_COUNT size)
{
    cmListItemTake(&pThread->item);
    if (NULL != pThread->context && pThread->contextSize < size)
    {
        cmMemoryFree(pThread->context);
        pThread->context = NULL;
    }
    if (NULL == pThread->context)
    {
        pThread->context = cmMemoryAllocate(size);
        pThread->contextSize = size;
        ((CMItem *)pThread->context)->name = NULL;
        ((CMItem *)pThread->context)->isStatic = TRUE;
    }
    cmListItemGive(&pThread->item);
    return pThread->context;
}

NQ_PORT cmThreadBindPort(SYSocketHandle sock)
{
	NQ_COUNT maxPort = 10000;	/* max number of ports to use */
    NQ_PORT res = 0;            /* the result */

    while(maxPort > 0)
    {
        syMutexTake(&threads.guard);
	    res = freePort;
	    if (freePort == nextPort)
	    {
		    nextPort++;
	    }
	    freePort = nextPort;
        syMutexGive(&threads.guard);
	    if (syBindSocket(sock, &localhost, syHton16(res)) == NQ_SUCCESS)
	    {
    	    return res;
	    }
    }
    return 0;
}

void cmThreadFreePort(NQ_PORT port)
{
	freePort = port;
}


NQ_BOOL cmThreadCondSet(CMThreadCond * cond)
{
#ifdef SY_SEMAPHORE_AVAILABLE

	sySemaphoreCreate(&cond->sem, 0);
	return cond->sem != NULL;
#else
	cond->inSock = syCreateSocket(FALSE, CM_IPADDR_IPV4);
	cond->outSock = syCreateSocket(FALSE, CM_IPADDR_IPV4);
	if (!syIsValidSocket(cond->inSock) || !syIsValidSocket(cond->outSock))
		return FALSE;
    cond->port = cmThreadBindPort(cond->inSock);
    if (0 == cond->port)
    {
        syCloseSocket(cond->inSock);
        syCloseSocket(cond->outSock);
        LOGERR(CM_TRC_LEVEL_ERROR, "error binding a condition socket &d - %d", cond->inSock);
        return FALSE;
    }
	return TRUE;
#endif /*SY_SEMAPHORE_AVAILABLE*/
}

NQ_BOOL cmThreadCondWait(CMThreadCond * cond, NQ_TIME timeout)
{
#ifndef SY_SEMAPHORE_AVAILABLE
    SYSocketSet set;		/* set to wait on */
    NQ_BYTE buf;			/* for receiving one byte */
    NQ_IPADDRESS ip;		/* dummy */
    NQ_PORT port;			/* dummy */
#endif /*SY_SEMAPHORE_AVAILABLE*/ 

#ifdef SY_SEMAPHORE_AVAILABLE
    NQ_INT res;

	res = sySemaphoreTimedTake(cond->sem, timeout);
	return res == NQ_SUCCESS;
#else  /*SY_SEMAPHORE_AVAILABLE*/
    if (!syIsValidSocket(cond->inSock))
    {
	    LOGERR(CM_TRC_LEVEL_ERROR, "illegal internal socket - %d", cond->inSock);
        return FALSE;
    }
    
    /* preparing to receive the response */
    syClearSocketSet(&set);
    syAddSocketToSet(cond->inSock, &set);

    switch (sySelectSocket(&set, timeout)) 
    {
        case 0:    /* timeout */
            return FALSE;

        case -1:   /* error or exit */
            LOGERR(CM_TRC_LEVEL_ERROR, "select error");
            return FALSE;

        default:   /* data arrived */
            syRecvFromSocket(cond->inSock, &buf, sizeof(buf), &ip, &port);
    }
	return TRUE;
#endif /*SY_SEMAPHORE_AVAILABLE*/
}

NQ_BOOL cmThreadCondSignal(CMThreadCond * cond)
{
#ifndef SY_SEMAPHORE_AVAILABLE
	NQ_BYTE buf = 0;	    /* for sending one byte */
#endif /*SY_SEMAPHORE_AVAILABLE*/ 
	NQ_STATUS res;			/* operation status */
	
#ifdef SY_SEMAPHORE_AVAILABLE
	res = sySemaphoreGive(cond->sem);
	return res == NQ_SUCCESS;
#else
    if (!syIsValidSocket(cond->outSock))
    {
	    LOGERR(CM_TRC_LEVEL_ERROR, "illegal internal socket - %d", cond->inSock);
        return FALSE;
    }
    res = sySendToSocket(cond->outSock, &buf, sizeof(buf), &localhost, syHton16(cond->port));
    if (NQ_FAIL == res)
    {
	    LOGERR(CM_TRC_LEVEL_ERROR, "error sending to a condition socket &d - %d", cond->inSock, res);
        return FALSE;
    }
	return TRUE;
#endif /*SY_SEMAPHORE_AVAILABLE*/
}

NQ_BOOL cmThreadCondRelease(CMThreadCond * cond)
{
#ifdef SY_SEMAPHORE_AVAILABLE
	sySemaphoreDelete(cond->sem);
	return TRUE;
#else
	syCloseSocket(cond->inSock);
	syCloseSocket(cond->outSock);
	syMutexTake(&threads.guard);
	cmThreadFreePort(cond->port);
	syMutexGive(&threads.guard);
	return TRUE;
#endif /*SY_SEMAPHORE_AVAILABLE*/
}

void cmThreadCondClear(CMThreadCond * cond)
{
#ifndef SY_SEMAPHORE_AVAILABLE
    SYSocketSet set;		/* set to wait on */
    NQ_BYTE buf;			/* for receiving one byte */
    NQ_IPADDRESS ip;		/* dummy */
    NQ_PORT port;			/* dummy */

	
	syClearSocketSet(&set);
    syAddSocketToSet(cond->inSock, &set);
    /* possible cleanup */
    switch (sySelectSocket(&set, 0)) 
    {
        case 0:    /* timeout */
            break;

        case -1:   /* error or exit */
            break;

        default:   /* data arrived */
            syRecvFromSocket(cond->inSock, &buf, sizeof(buf), &ip, &port);
    }
#endif /*SY_SEMAPHORE_AVAILABLE*/ 
}


