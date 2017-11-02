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

/* -- client functions (used in mechanisms) -- */

CMBlob * amSpnegoClientGetSessionKey(void * context);
const AMCredentialsW * amSpnegoClientGetCredentials(void * context);
CMBlob * amSpnegoClientGetMacSessionKey(void * context);
NQ_UINT amSpnegoClientGetCrypter1(void * context);
NQ_UINT amSpnegoClientGetCrypter2(void * context);
NQ_UINT amSpnegoClientGetCryptLevel(void * context);

/* -- server definitions -- */

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)

/* mechanism descriptor */
typedef struct
{
    const CMAsn1Oid *oid;           /* mechanism OID */
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
