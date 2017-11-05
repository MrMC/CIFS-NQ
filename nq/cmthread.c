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
    cmThreadCondRelease(&pThread->poolCond);
    if (NULL != pThread->context)
    {
        cmMemoryFree(pThread->context);
        pThread->context = NULL;
    }
	if (NULL != pThread->element.item.guard)
	{
		syMutexDelete(pThread->element.item.guard);
		cmMemoryFree(pThread->element.item.guard);
		pThread->element.item.guard = NULL;
	}
    return FALSE;
}

/* -- API Functions */

NQ_BOOL cmThreadStart(void)
{
    cmListStart(&threads);
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
        	pThread->context = NULL;
        }
    	if (pThread->element.item.guard != NULL)
    	{
			syMutexDelete(pThread->element.item.guard);
			cmMemoryFree(pThread->element.item.guard);
			pThread->element.item.guard = NULL;
    	}
        cmThreadCondRelease(&pThread->syncCond);
        cmThreadCondRelease(&pThread->asyncCond);
        cmThreadCondRelease(&pThread->poolCond);
    }

    cmListIteratorTerminate(&iterator);
	
    cmListShutdown(&threads);
}

static void threadBodyEnvelop(void)
{
    CMIterator iterator;            /* in the list of threads */
    SYThread sysHandle;             /* system handle for the current one */

    sysHandle = syThreadGetCurrent();

    cmListIteratorStart(&threads, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMThread * pThread; /* casted pointer */

        pThread = (CMThread *)cmListIteratorNext(&iterator);
        if (pThread->thread == sysHandle)
        {
            cmListIteratorTerminate(&iterator);
#ifdef SY_THREADSET
        	SY_THREADSET(pThread);
#endif /* SY_THREADSET */
        	(pThread->body)();
            return;
        }
    }
    cmListIteratorTerminate(&iterator);
}

NQ_BOOL cmThreadCreateAndRun(CMThread * thread, void (* body)(void), NQ_BOOL background)
{
	NQ_BOOL result = FALSE;

    if(!cmThreadCondSet(&thread->syncCond))
    {
    	goto Exit;
    }
    if(!cmThreadCondSet(&thread->asyncCond))
    {
#ifndef SY_SEMAPHORE_AVAILABLE
    	if (syIsValidSocket(thread->syncCond.inSock))
    		syCloseSocket(thread->syncCond.inSock);
    	if (syIsValidSocket(thread->syncCond.outSock))
    		syCloseSocket(thread->syncCond.outSock);
#else  /* SY_SEMAPHORE_AVAILABLE */
    	cmThreadCondRelease(&thread->syncCond);
#endif /* SY_SEMAPHORE_AVAILABLE */
    	goto Exit;
    }
    if(!cmThreadCondSet(&thread->poolCond))
    {
#ifndef SY_SEMAPHORE_AVAILABLE
    	if (syIsValidSocket(thread->syncCond.inSock))
    		syCloseSocket(thread->syncCond.inSock);
    	if (syIsValidSocket(thread->syncCond.outSock))
    		syCloseSocket(thread->syncCond.outSock);
    	if (syIsValidSocket(thread->asyncCond.inSock))
			syCloseSocket(thread->asyncCond.inSock);
		if (syIsValidSocket(thread->asyncCond.outSock))
			syCloseSocket(thread->asyncCond.outSock);
#else  /* SY_SEMAPHORE_AVAILABLE */
    	cmThreadCondRelease(&thread->syncCond);
    	cmThreadCondRelease(&thread->asyncCond);
#endif /* SY_SEMAPHORE_AVAILABLE */
    	goto Exit;
    }
    thread->body = body;
    thread->context = NULL;
    thread->element.item.name = NULL;
    thread->element.thread = thread;
    thread->cycleParam = NULL;
    cmListItemInit(&thread->item);
    cmListItemInit(&thread->element.item);
    thread->element.item.guard = (SYMutex *)cmMemoryAllocate(sizeof(*thread->element.item.guard));
	if (thread->element.item.guard != NULL) syMutexCreate(thread->element.item.guard);
    thread->item.guard = (SYMutex *)cmMemoryAllocate(sizeof(*thread->item.guard));
    if (thread->item.guard != NULL) syMutexCreate(thread->item.guard);
    cmListItemAdd(&threads, (CMItem *)thread, unlockCallback);
	syThreadStart(&thread->thread, threadBodyEnvelop, background);
	thread->infoFlags = (NQ_UINT16)THREAD_INFO_ISRUNNING; /* init and set bit. */
	result = TRUE;
Exit:
	return result;
}

void cmThreadStopAndDestroy(CMThread * thread, NQ_BOOL doDestroy)
{
	cmListItemRemove((CMItem *)thread);
	if(NULL != thread->item.guard)
	{
		syMutexDelete(thread->item.guard);
		cmMemoryFree(thread->item.guard);
		thread->item.guard = NULL;
	}
	if(NULL != thread->element.item.guard)
	{
		syMutexDelete(thread->element.item.guard);
		cmMemoryFree(thread->element.item.guard);
		thread->element.item.guard = NULL;
	}
	if (thread->context != NULL)
    {
    	cmMemoryFree(thread->context);
    	thread->context = NULL;
    }
	if (doDestroy && (thread->infoFlags & (NQ_UINT16)THREAD_INFO_ISRUNNING))
	{
		syThreadDestroy(thread->thread);
	}
    cmThreadCondRelease(&thread->syncCond);
    cmThreadCondRelease(&thread->asyncCond);
}

CMThread * cmThreadGetCurrent(void)
{
#ifndef SY_THREADGET
    CMIterator iterator;            /* in the list of threads */
#endif /* cmThreadGetCurrent */
    CMThread * curThread = NULL;    /* the result */
    SYThread sysHandle;             /* system handle for the current one */
    
    sysHandle = syThreadGetCurrent();

#ifdef SY_THREADGET

    curThread = SY_THREADGET();

#else /* SY_THREADGET */

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

#endif /* SY_THREADGET */

    if (NULL == curThread)
    {
        curThread = (CMThread *)cmListItemCreateAndAdd(&threads, sizeof(CMThread), NULL, unlockCallback, CM_LISTITEM_NOLOCK);
        if (NULL == curThread)
        {
        	LOGMSG(CM_TRC_LEVEL_ERROR ,"Coudln't allocate memory for new thread.");
            goto Exit;
        }
        curThread->thread = sysHandle;
        curThread->context = NULL;
        cmListItemInit(&curThread->element.item);
        curThread->element.item.guard = (SYMutex *)cmMemoryAllocate(sizeof(*curThread->element.item.guard));
		if (curThread->element.item.guard != NULL) syMutexCreate(curThread->element.item.guard);
        curThread->element.thread = curThread;
        if(!cmThreadCondSet(&curThread->syncCond))
        {
        	if (curThread->element.item.guard != NULL)
        	{
				syMutexDelete(curThread->element.item.guard);
				cmMemoryFree(curThread->element.item.guard);
				curThread->element.item.guard = NULL;
        	}
        	cmListItemRemoveAndDispose((CMItem *)curThread);
        	curThread = NULL;
        	LOGMSG(CM_TRC_LEVEL_ERROR ,"Coudln't set thread sync condition.");
        	goto Exit;
        }
        if(!cmThreadCondSet(&curThread->asyncCond))
        {
        	if (curThread->element.item.guard != NULL)
        	{
				syMutexDelete(curThread->element.item.guard);
				cmMemoryFree(curThread->element.item.guard);
				curThread->element.item.guard = NULL;
        	}
#ifndef SY_SEMAPHORE_AVAILABLE
        	if (syIsValidSocket(curThread->syncCond.inSock))
        		syCloseSocket(curThread->syncCond.inSock);
        	if (syIsValidSocket(curThread->syncCond.outSock))
        		syCloseSocket(curThread->syncCond.outSock);
#else  /* SY_SEMAPHORE_AVAILABLE */
        	cmThreadCondRelease(&curThread->syncCond);
#endif /* SY_SEMAPHORE_AVAILABLE */
        	cmListItemRemoveAndDispose((CMItem *)curThread);
        	LOGMSG(CM_TRC_LEVEL_ERROR ,"Coudln't set thread async condition.");
        	curThread = NULL;
			goto Exit;
        }
        curThread->infoFlags = (NQ_UINT16)THREAD_INFO_ISRUNNING; /* init and set bit */
    }

Exit:
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
        cmListItemUnlock((CMItem *)curThread);
        cmListItemRemoveAndDispose((CMItem *)curThread);
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
        if (NULL != pThread->context)
        {
            pThread->contextSize = size;
            syMemset(pThread->context, 0, size);
        }        
    }
    cmListItemGive(&pThread->item);
    return pThread->context;
}

void * cmThreadGetContextAsStatItem(CMThread * pThread, NQ_COUNT size)
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
        if (NULL != pThread->context)
        {
            pThread->contextSize = size;
            syMemset(pThread->context, 0, size);
            ((CMItem *)pThread->context)->name = NULL;
            ((CMItem *)pThread->context)->isStatic = TRUE;
        }
    }
    cmListItemGive(&pThread->item);
    return pThread->context;
}

NQ_PORT cmThreadBindPort(SYSocketHandle sock)
{
    NQ_PORT res;            /* the result */
	NQ_PORT currPort = 0,loopPort;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    loopPort = res = cmPortManage();
    while(currPort != loopPort && syBindSocket(sock, &localhost, syHton16(res)) != NQ_SUCCESS)
    {
    	currPort = res = cmPortManage();
    }
    if (currPort == loopPort)
    {
		goto Error;
    }
    goto Exit;

Error:
    res = 0;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

void cmThreadFreePort(NQ_PORT port)
{
	cmManageFreePort(port);
}


NQ_BOOL cmThreadCondSet(CMThreadCond * cond)
{
    NQ_BOOL result = FALSE;

#ifdef SY_SEMAPHORE_AVAILABLE
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	result = ( sySemaphoreCreate(&cond->sem, 0) == NQ_SUCCESS );
#pragma GCC diagnostic pop
#else
	cond->inSock = syCreateSocket(FALSE, CM_IPADDR_IPV4);
	cond->outSock = syCreateSocket(FALSE, CM_IPADDR_IPV4);
	if (!syIsValidSocket(cond->inSock) || !syIsValidSocket(cond->outSock))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "syCreateSocket() failed");
		goto Error;
	}
    cond->port = cmThreadBindPort(cond->inSock);
    if (0 == cond->port)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "error binding a condition socket %d", cond->inSock);
        goto Error;
    }
    cond->sentSignal = FALSE;
    syMutexCreate(&cond->condGuard);
	result = TRUE;
	goto Exit;

Error:
	if (syIsValidSocket(cond->inSock))
		syCloseSocket(cond->inSock);
	if (syIsValidSocket(cond->outSock))
		syCloseSocket(cond->outSock);
Exit:
#endif /*SY_SEMAPHORE_AVAILABLE*/
    return result;
}

NQ_BOOL cmThreadCondWait(CMThreadCond * cond, NQ_UINT32 timeout)
{
    NQ_BOOL result = FALSE;

#ifdef SY_SEMAPHORE_AVAILABLE
	result = sySemaphoreTimedTake(&cond->sem, (NQ_INT)timeout) == NQ_SUCCESS;
#else  /*SY_SEMAPHORE_AVAILABLE*/
    NQ_BYTE buf;			/* for receiving one byte */

    if (!syIsValidSocket(cond->inSock))
    {
	    LOGERR(CM_TRC_LEVEL_ERROR, "illegal internal socket - %d", cond->inSock);
        goto Exit;
    }

    switch(syRecvSocketWithTimeout(cond->inSock, &buf, sizeof(buf), timeout))
    {
        case 0:    /* timeout */
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Wait condition timeout.");
            goto Exit;

        case -1:   /* error or exit */
            LOGERR(CM_TRC_LEVEL_ERROR, "select error");
            goto Exit;

        default:   /* data arrived */
            syMutexTake(&cond->condGuard);
            cond->sentSignal = FALSE;
            syMutexGive(&cond->condGuard);
            break;
    }
	result = TRUE;

Exit:

#endif /*SY_SEMAPHORE_AVAILABLE*/

    return result;
}

NQ_BOOL cmThreadCondSignal(CMThreadCond * cond)
{
    NQ_BOOL result = FALSE;

#ifdef SY_SEMAPHORE_AVAILABLE
	result = ( sySemaphoreGive(cond->sem) == NQ_SUCCESS );
#else
	NQ_BYTE buf = 0;	    /* for sending one byte */
	NQ_STATUS res;			/* operation status */

    if (!syIsValidSocket(cond->outSock))
    {
	    LOGERR(CM_TRC_LEVEL_ERROR, "illegal internal socket - %d", cond->inSock);
        goto Exit;
    }
    syMutexTake(&cond->condGuard);
    if(!cond->sentSignal)
    {
		res = sySendToSocket(cond->outSock, &buf, sizeof(buf), &localhost, syHton16(cond->port));
		if (NQ_FAIL == res)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "error sending to a condition socket %d - %d", cond->inSock, res);
			syMutexGive(&cond->condGuard);
			goto Exit;
		}
		cond->sentSignal = TRUE;
    }
    else
    {
    	LOGMSG(CM_TRC_LEVEL_WARNING, "Notice, signal to waiting condition not sent to Avoid double signal.");
    }

    syMutexGive(&cond->condGuard);
	result = TRUE;

Exit:
#endif /*SY_SEMAPHORE_AVAILABLE*/

	return result;
}

NQ_BOOL cmThreadCondRelease(CMThreadCond * cond)
{
#ifdef SY_SEMAPHORE_AVAILABLE
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	sySemaphoreDelete(cond->sem);
#pragma GCC diagnostic pop
#else
	syCloseSocket(cond->inSock);
	syCloseSocket(cond->outSock);
	syMutexTake(&threads.guard);
	cmThreadFreePort(cond->port);
	syMutexGive(&threads.guard);
	syMutexTake(&cond->condGuard);
	syMutexGive(&cond->condGuard);
	syMutexDelete(&cond->condGuard);
#endif /*SY_SEMAPHORE_AVAILABLE*/
    return TRUE;
}

void cmThreadCondClear(CMThreadCond * cond)
{
#ifdef SY_SEMAPHORE_AVAILABLE
	NQ_INT lockCount = 0 , i = 0;

	sySemaphoreGetCount(cond->sem , &lockCount);
	for (i = 0; i < lockCount ; i++)
		sySemaphoreTake(cond->sem);
#else
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

    cond->sentSignal = FALSE;

#endif /*SY_SEMAPHORE_AVAILABLE*/
}


