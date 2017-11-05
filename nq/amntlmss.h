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

#ifndef _AMNTLMSS_H_
#define _AMNTLMSS_H_

#include "cmapi.h"
#include "amspnego.h"
#include "cmgssapi.h"

#if defined(UD_CS_INCLUDEEXTENDEDSECURITY) || defined(UD_CC_INCLUDEEXTENDEDSECURITY)

/* NTLMSSP Negotiate flags: */
#define NTLMSSP_NEGOTIATE_UNICODE               0x00000001
#define NTLMSSP_NEGOTIATE_REQUEST_TARGET        0x00000004
#define NTLMSSP_NEGOTIATE_SIGN                  0x00000010 
#define NTLMSSP_NEGOTIATE_NTLM                  0x00000200 /* NTLM authentication is supported */
#define NTLMSSP_NEGOTIATE_EXTENDED_SECURITY     0x00080000 /* NTLMv1 using the extended session security */
#define NTLMSSP_NEGOTIATE_128                   0x20000000 /* 128-bit encryption */
#define NTLMSSP_NEGOTIATE_56                    0x80000000 /* 56-bit encryption */
#define NTLMSSP_NEGOTIATE_KEY_EXCH              0x40000000 /* client will provide an encrypted master key for calculating session key */
#define NTLMSSP_NEGOTIATE_LAN_MANAGER           0x00000080 /* LM session key*/
#define NTLMSSP_NEGOTIATE_TARGET_INFO           0x00800000 /* target information block is being sent */
#define NTLMSSP_NEGOTIATE_ANONYMOUS             0x00000800 /* connection should be anonymous */
#define NTLMSSP_NEGOTIATE_TARGET_TYPE_DOMAIN    0x00010000 /* authentication target is being sent with the message and represents a domain */
#define NTLMSSP_NEGOTIATE_TARGET_TYPE_SERVER    0x00020000 /* authentication target is being sent with the message and represents a server */
#define NTLMSSP_NEGOTIATE_SIGN                  0x00000010 /* support for message integrity (signing) */
#define NTLMSSP_NEGOTIATE_SEAL                  0x00000020 /* support for message confidentiality (sealing) */
#endif /* defined(UD_CS_INCLUDEEXTENDEDSECURITY) || defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)
/* get this mechanism descriptor */
const AMSpnegoServerMechDescriptor * amNtlmsspGetServerDescriptor(void);

/* get NTLM challenge from the blob */
NQ_BYTE * amNtlmsspServerGetChallenge(NQ_BYTE* blob);

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)

/* get server time stamp from the blob */
NQ_UINT64 amNtlmsspServerGetTimeStamp(const NQ_BYTE* blob);

/* NTLMSSP functions to be set into a client-side SPNEGO descriptor */ 
NQ_BOOL amNtlmsspClientInit(void *p);
NQ_BOOL amNtlmsspClientStop(void);
NQ_BYTE* amNtlmsspClientContextCreate(const NQ_CHAR* name, NQ_BOOL restrictCrypt);
NQ_BOOL amNtlmsspClientSetMechanism(NQ_BYTE* ctx, const NQ_CHAR* name);
NQ_BOOL amNtlmsspClientGetSessionKey(NQ_BYTE* p, NQ_BYTE* buffer, NQ_COUNT* len);                      
NQ_BOOL amNtlmsspClientContextIsValid(const NQ_BYTE* ctx);
NQ_BOOL amNtlmsspClientContextDispose(NQ_BYTE* ctx);
void amNtlmsspClientContextInvalidate(NQ_BYTE* ctx);
NQ_BOOL amNtlmsspClientGenerateFirstRequest(NQ_BYTE * ctxt, const NQ_CHAR * mechList, NQ_BYTE ** blob, NQ_COUNT * blobLen);
NQ_BOOL amNtlmsspClientGenerateNextRequest(NQ_BYTE * ctxt, const NQ_BYTE * inBlob, NQ_COUNT inBlobLen, NQ_BYTE ** outBlob, NQ_COUNT* outBlobLen, NQ_BYTE* con);
NQ_BOOL amNtlmsspClientPackNegotBlob(void * context, CMBufferWriter * writer, NQ_COUNT mechtokenBlobLen, NQ_COUNT * blobLen); 

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

#endif /* _AMNTLMSS_H_ */
