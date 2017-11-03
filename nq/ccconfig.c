/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client configuration
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 14-Aug-2001
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmcrypt.h"

#include "ccapi.h"
#include "ccparams.h"
#include "cmthread.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* static data */
static NQ_UINT32 globalTimeout = UD_CC_CLIENTRESPONSETIMEOUT;

void ccConfigInit(void)
{
	sySetRand();
	globalTimeout = UD_CC_CLIENTRESPONSETIMEOUT;
}

void ccConfigShutdown(void)
{
}

void ccConfigSetTimeout(NQ_UINT32 secs)
{
	globalTimeout = secs == 0? UD_CC_CLIENTRESPONSETIMEOUT: secs;
}

NQ_UINT32 ccConfigGetTimeout(void)
{
	return globalTimeout;
}

void ccThreadSubscribe(void)
{
    cmThreadSubscribe();
}

void ccThreadUnsubscribe(void)
{
    cmThreadUnsubscribe();
}

#endif
