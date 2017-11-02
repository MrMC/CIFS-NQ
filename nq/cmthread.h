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

#ifndef _CMTREAD_H_
#define _CMTREAD_H_

#include "cmapi.h"

/* -- Typedefs -- */

/* Description
   Condition object.
   
   This object is used to synchronize threads. 
   
   It also provides wait/signal functionality, when
   One thread may wait while another one will signal it.
   
   Two synchronize threads we use UDP sockets.  
*/
typedef struct _cmthreadcond
{
#ifdef SY_SEMAPHORE_AVAILABLE
	SYSemaphore sem; /* Semaphore*/
#else
	SYSocketHandle inSock;	/* Listening socket. */
	SYSocketHandle outSock;	/* Sending socket. */
	NQ_PORT port;			/* Port to listen on. */
#endif /*SY_SEMAPHORE_AVAILABLE*/
} CMThreadCond;	/* Condition */	

/* Description
   Semaphore queue element.
   
   This object is used to queue a thread in a semaphore queue. 
*/
typedef struct _cmthreadelement       /* semaphore queue element */   
{
    CMItem item;                /* Inherited item. */
    void * thread;              /* Thread pointer. */
} 
CMThreadElement;    /* queu element */

/* Description
   Thread object.
   
   This object is used to wrap system threads. 
   
   It also provides wait/signal functionality, when
   One thread may wait while another one will signal it.
   
   Two synchronize threads we use UDP sockets.  
*/
typedef struct _cmthread
{
    CMItem item;                /* Inherited item. */
    SYThread thread;		    /* System thread handle. */
    CMThreadCond syncCond;      /* Condition to synchronize this thread on synchronous operations. */
    CMThreadCond asyncCond;     /* Condition to synchronize this thread on asynchronous operations. */
    void * context;             /* Pointer to thread context which depends on SMB protocol. */
    NQ_COUNT contextSize;       /* Size of the current context */ 
    CMThreadElement element;    /* Sempahore queue item. */
} CMThread; /* Thread wrapper */	

/* -- API Functions */

/* Description
   This function starts this module.
   Returns
   TRUE on success, FALSE on failure.                          */
NQ_BOOL cmThreadStart(void);

/* Description
   This function terminates this module and releases resources.
   Returns
   None */
void cmThreadShutdown(void);

/* Description
   Create thread and start its execution.
   Parameters
   thread :      Pointer to the thread structure.
   body :        The body function.
   background :  <i>TRUE</i> to create a background thread, <i>FALSE</i>
                 to create a normal thread.
   Returns
   TRUE on success, FALSE on error.                                      */
NQ_BOOL cmThreadCreateAndRun(CMThread * thread, void (* body)(void), NQ_BOOL background);

/* Description
   Get current thread.
   Returns
   TRUE on success, FALSE on error.                                      */
CMThread * cmThreadGetCurrent(void);

/* Description
   Register the current system thread.

   This function creates an NQ object describing the current system (application) thread. 
   NQ expects the application to call cmThreadUnsubscribe() to release NQ resources associated with
   this thread. If this thread was alreday registered, nothing will happen. 
   Returns
   None.                                      */
void cmThreadSubscribe(void);

/* Description
   Release the resources associated with the current system thread.

   NQ assumes that the current system (application) thread was registered with a 
   cmThreadSubscribe() call. If this is not true, nothing will happen. 
   Returns
   None.                                      */
void cmThreadUnsubscribe(void);

/* Description
   Get thread context.

   If thread context does not exist - it is created.

   Parameters
   thread :      Pointer to the thread structure.
   size :        Conext size, this value is used if context was not created yet. 
   background :  <i>TRUE</i> to create a background thread, <i>FALSE</i>
                 to create a normal thread.
   Returns
   TRUE on success, FALSE on error.                                      */
void * cmThreadGetContext(CMThread * thread, NQ_COUNT size);

/* Description
   Stop thread and release its resources.
   Parameters
   thread :  Pointer to the thread structure.
   Returns
   None.                                      */
void cmThreadStopAndDestroy(CMThread * thread);

/* Description
   This fucntion binds the given socket on the first available dynamic port.

   The socket is bound on localhost address. 
   Parameters
   sock :  Socket to bind.
   Returns
   The assigned port or zero on error. */
NQ_PORT cmThreadBindPort(SYSocketHandle sock);

/* Description
   This fucntion releases a previous bound local port.

   Parameters
   port :  Port to release.
   Returns
   None. */
void cmThreadFreePort(NQ_PORT port);

/* Description
   Prepare a condition structure.
   Parameters
   cond :  Condition to set.
   Returns
   TRUE on success FALSE on failure. */
NQ_BOOL cmThreadCondSet(CMThreadCond * cond);

/* Description
   Release resources accociated with a condition structure.
   Parameters
   cond :  Condition to release.
   Returns
   TRUE on success FALSE on failure.                        */
NQ_BOOL cmThreadCondRelease(CMThreadCond * cond);

/* Description
   Wait on condition for signal or time out.
   
   To signal this thread call <link cmThreadCondSignal@CMThreadCond *, cmThreadSignal()>.
   Parameters
   cond :     Condition to wait on.
   timeout :  Number of seconds to sleep.
   Returns
   TRUE when thread was signalled or FALSE when timeout.                                  */
NQ_BOOL cmThreadCondWait(CMThreadCond * cond, NQ_TIME timeout);

/* Description
   Signal thread.
   
   If the thread is waiting on <link cmThreadCondWait@CMThreadCond *@NQ_TIME, cmThreadCondWait()>,
   its execution will be continued. If the thread is not
   waiting, nothing will happen.
   Parameters
   cond :  Pointer to the condition to signal.
   Returns
   TRUE on success, FALSE on error.                                                                */
NQ_BOOL cmThreadCondSignal(CMThreadCond * cond);

/* Description
   Clears condition sockets.
   
   Parameters
   cond :  Pointer to the condition to signal.
   Returns
   Nothing.                                                                */
   
void cmThreadCondClear(CMThreadCond * cond);
#endif /* _CMTREAD_H_ */
