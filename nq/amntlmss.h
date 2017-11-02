/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : NTLMSSP authentication machine (server)
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 11-Feb-2007
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSNTLMSS_H_
#define _CSNTLMSS_H_

#include "cmapi.h"
#include "amspnego.h"
#include "cmgssapi.h"


#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)

/* get this mechanism descriptor */
const AMSpnegoServerMechDescriptor * amNtlmsspGetServerDescriptor(void);

/* get NTLM challenge from the blob */
NQ_BYTE * amNtlmsspServerGetChallenge(NQ_BYTE* blob);

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)

/* NTLMSSP functions to be set into a client-side SPNEGO descriptor */ 
NQ_BOOL amNtlmsspClientInit(void *p);
NQ_BOOL amNtlmsspClientStop(void);
NQ_BYTE* amNtlmsspClientContextCreate(const NQ_CHAR* name, NQ_BOOL restrictCrypt);
NQ_BOOL amNtlmsspClientSetMechanism(NQ_BYTE* ctx, const NQ_CHAR* name);
NQ_BOOL amNtlmsspClientGetSessionKey(NQ_BYTE* p, NQ_BYTE* buffer, NQ_COUNT* len);                      
NQ_BOOL amNtlmsspClientContextIsValid(NQ_BYTE* p);
NQ_BOOL amNtlmsspClientContextDispose(NQ_BYTE* ctx);
void amNtlmsspClientContextInvalidate(NQ_BYTE* ctx);
NQ_BOOL amNtlmsspClientGenerateFirstRequest(NQ_BYTE * ctxt, const NQ_CHAR * mechList, NQ_BYTE ** blob, NQ_COUNT * blobLen);
NQ_BOOL amNtlmsspClientGenerateNextRequest(NQ_BYTE * ctxt, const NQ_BYTE * inBlob, NQ_COUNT inBlobLen, NQ_BYTE ** outBlob, NQ_COUNT* outBlobLen, NQ_BYTE* con);
NQ_BOOL amNtlmsspClientPackNegotBlob(void * context, CMBufferWriter * writer, NQ_COUNT mechtokenBlobLen, NQ_COUNT * blobLen); 

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

#endif /* _CSNTLMSS_H_ */
