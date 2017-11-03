/*********************************************************************
 *
 *           Copyright (c) 2010 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : NETLOGON RPC client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 22-Dec-2010
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CCNETLGN_H_
#define _CCNETLGN_H_

#include "cmapi.h"
#include "cmsdescr.h"
#include "ccdcerpc.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

typedef struct
{
    NQ_BYTE client[8];
    NQ_BYTE server[8];
    NQ_BYTE seed[8];
    NQ_BYTE sessionKey[16];
    NQ_UINT32 negotFlags;
    NQ_UINT32 sequence;    
    NQ_UINT32 time;
}
CCNetlogonCredential;

const CCDcerpcPipeDescriptor * ccNetlogonGetPipe();

NQ_UINT32 ccNetrServerReqChallenge(
    NQ_HANDLE netlogon,
    const NQ_WCHAR *server,
    const NQ_WCHAR *computer,
    CCNetlogonCredential *credential
    );

NQ_UINT32 ccNetrServerAuthenticate2(
    NQ_HANDLE netlogon,
    const NQ_WCHAR *server,
    const NQ_WCHAR *computer,
    CCNetlogonCredential *credential,
    NQ_UINT32 * flags
    );

/* callback function for storing different names during enumeration */
typedef void (*CCNetrEnumerateNamesCallback)(
    const NQ_WCHAR * name,      /* next name (null terminated) */
    void * list                 /* list to add name to */
    );

NQ_UINT32 ccDsrEnumerateDomainTrusts(
    NQ_HANDLE netlogon,
    const NQ_WCHAR *server, 
    CCNetrEnumerateNamesCallback callback,
    CMList * list
    );

#endif /* UD_NQ_INCLUDECIFSCLIENT */

#endif /* _CCNETLGN_H_ */

