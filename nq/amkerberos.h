/*********************************************************************
*
*           Copyright (c) 2016 by Visuality Systems, Ltd.
*
*********************************************************************
* FILE NAME     : $Workfile:$
* ID            : $Header:$
* REVISION      : $Revision:$
*--------------------------------------------------------------------
* DESCRIPTION   : Kerberos authentication module (server)
*--------------------------------------------------------------------
* DEPENDENCIES  : None
*--------------------------------------------------------------------
* CREATION DATE : 10-Feb-2016
* CREATED BY    : Lilia Wasserman
* LAST AUTHOR   : $Author:$
********************************************************************/

#ifndef _AMKERBEROS_H_
#define _AMKERBEROS_H_

#include "cmapi.h"
#include "amspnego.h"
#include "cmgssapi.h"


#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) && defined(UD_NQ_INCLUDEKERBEROS)

/* get this mechanism descriptor */
const AMSpnegoServerMechDescriptor * amKerberosGetServerDescriptor(void);

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) && defined(UD_NQ_INCLUDEKERBEROS) */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) && defined(UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS)
/* Kerberos functions to be set into a client-side SPNEGO descriptor */
NQ_BOOL amKerberosClientInit(void *p);
NQ_BOOL amKerberosClientStop();
NQ_BYTE* amKerberosClientContextCreate(const NQ_CHAR* name, NQ_BOOL restrictCrypt);
NQ_BOOL amKerberosClientSetMechanism(NQ_BYTE* ctx, const NQ_CHAR* name);
NQ_BOOL amKerberosClientGetSessionKey(NQ_BYTE* ctx, NQ_BYTE* buffer, NQ_COUNT* len);
NQ_BOOL amKerberosClientContextIsValid(const NQ_BYTE* ctx);
NQ_BOOL amKerberosClientContextDispose(NQ_BYTE* ctx);
void amKerberosClientContextInvalidate(NQ_BYTE* ctx);
NQ_BOOL amKerberosClientGenerateFirstRequest(NQ_BYTE * ctx, const NQ_CHAR * mechList, NQ_BYTE ** blob, NQ_COUNT * blobLen);
NQ_BOOL amKerberosClientGenerateNextRequest(NQ_BYTE * ctx, const NQ_BYTE * inBlob, NQ_COUNT inBlobLen, NQ_BYTE ** outBlob, NQ_COUNT* outBlobLen, NQ_BYTE* con);
NQ_BOOL amKerberosClientPackNegotBlob(void * ctx, CMBufferWriter * writer, NQ_COUNT mechtokenBlobLen, NQ_COUNT * blobLen);
#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) && defined(UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS) */

#endif /* _AMKERBEROS_H_ */
