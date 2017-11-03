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

#ifndef _AMSPNEGO_H_ 
#define _AMSPNEGO_H_

#include "amapi.h"
#include "amcredentials.h"
#include "cmasn1.h"
#ifdef UD_NQ_INCLUDECIFSSERVER
#include "csdataba.h"
#include "csauth.h"
#endif /* UD_NQ_INCLUDECIFSSERVER */

/* -- client definitions -- */

#ifdef UD_NQ_INCLUDECIFSCLIENT

void amSpnegoClientSetDefaultLevels();
void amSpnegoClientSetAuthLevel(NQ_INT level);
NQ_INT amSpnegoClientGetAuthLevel();

#ifdef UD_CC_INCLUDEEXTENDEDSECURITY

/* security mechanism */
typedef struct
{
    NQ_UINT32 mask;                 /* mechanism mask as AM_MECH... */
    const CMAsn1Oid *oid;           /* ASN1 OID */
    const CMAsn1Oid *reqOid;        /* ASN1 request OID */
    const NQ_CHAR* name;            /* readable name */
    NQ_BOOL(*init)(void*);
    NQ_BOOL(*stop)();
    NQ_BOOL(*setMechanism)(NQ_BYTE *, const NQ_CHAR *);
    NQ_BYTE*(*contextCreate)(const NQ_CHAR *, NQ_BOOL);
    NQ_BOOL(*generateFirstRequest)(NQ_BYTE *, const NQ_CHAR *, NQ_BYTE **, NQ_COUNT *);
    NQ_BOOL(*generateNextRequest)(NQ_BYTE*, const NQ_BYTE *, NQ_COUNT, NQ_BYTE **, NQ_COUNT *, NQ_BYTE *);
    NQ_BOOL(*getSessionKey)(NQ_BYTE*, NQ_BYTE *, NQ_COUNT *);
    NQ_BOOL(*contextIsValid)(const NQ_BYTE *);
    NQ_BOOL(*contextDispose)(NQ_BYTE *);
    NQ_BOOL(*packNegotBlob)(void *, CMBufferWriter *, NQ_COUNT, NQ_COUNT *);
    NQ_INT type;                    /* future - mechanism type */
} SecurityMechanism;

/*  SPNEGO context */
typedef struct
{
    NQ_INT defAuthLevel;                    /* authentication level to start with */
    NQ_STATUS status;                       /* result of the last operation */
    const SecurityMechanism * mechanism;    /* security mechanism to use */
    NQ_BYTE * extendedContext;              /* extended context per mechanism */
    AMCredentialsW credentials;             /* credentials to use */
    CMBlob * sessionKey;                    /* pointer to session key blob */
    CMBlob * macSessionKey;                 /* pointer to MAC session key blob */
    NQ_UINT level;                          /* required security level as supplied in allocateContext */
} SecurityContext;

/* -- client functions (used in mechanisms) -- */

CMBlob * amSpnegoClientGetSessionKey(void * context);
const AMCredentialsW * amSpnegoClientGetCredentials(void * context);
CMBlob * amSpnegoClientGetMacSessionKey(void * context);
NQ_UINT amSpnegoClientGetCrypter1(void * context);
NQ_UINT amSpnegoClientGetCrypter2(void * context);
NQ_UINT amSpnegoClientGetCryptLevel(void * context);

#endif /* UD_CC_INCLUDEEXTENDEDSECURITY */
#endif /* UD_NQ_INCLUDECIFSCLIENT */

/* -- server definitions -- */

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)

/* mechanism descriptor */
typedef struct
{
    const CMAsn1Oid *oid;           /* mechanism OID */
    const CMAsn1Oid *oidSecondary;  /* alternative mechanism OID */
    NQ_UINT32 (*processor)(
        CMRpcPacketDescriptor * in, 
        CMRpcPacketDescriptor * out, 
        AMNtlmDescriptor * descr, 
        NQ_WCHAR * userName,           
        const NQ_WCHAR ** pDomain,
        const NQ_BYTE ** pSessionKey            
        );
}
AMSpnegoServerMechDescriptor; 


#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) */

#endif /* _AMSPNEGO_H_ */
