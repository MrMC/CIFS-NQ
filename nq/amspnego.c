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

#include "amspnego.h"
#include "amntlmss.h"
#include "amcrypt.h"
#include "cmgssapi.h"
#include "cmapi.h"
#include "cmcrypt.h"
#include "cmbuf.h"
#include "amntlmss.h"
#include "cmgssapi.h"

/* -- Structures and constants -- */

/* SPNEGO message types */
#define SPNEGO_ACCEPTINCOMPLETE 1       /* server response (negResult) */
#define SPNEGO_ACCEPTCOMPLETE   0       /* server response (negResult) */

#define NTLMSSP_MECHANISM_NAME "NTLMSSP"

/* security levels */
typedef struct
{
	NQ_UINT crypter1;	/* first crypter */
	NQ_UINT crypter2;	/* second crypter */
	NQ_UINT32 mask;		/* security mechanism mask */
} LevelDescriptor;

#ifdef UD_NQ_INCLUDECIFSCLIENT

static LevelDescriptor levels[] = {
	{AM_CRYPTER_LM,   AM_CRYPTER_NONE, 0},
	{AM_CRYPTER_LM,   AM_CRYPTER_NTLM, 0},
	{AM_CRYPTER_LM,   AM_CRYPTER_NTLM, AM_MECH_KERBEROS | AM_MECH_NTLMSSP},
	{AM_CRYPTER_LM2,  AM_CRYPTER_NTLM2, AM_MECH_NTLMSSP},
	{AM_CRYPTER_LM2,  AM_CRYPTER_NTLM2, AM_MECH_KERBEROS | AM_MECH_NTLMSSP},
	/* This is a Hidden level used for inside operation of NQ that should not be affected by the user (for example , smb1 tree connect using share security) */
    {AM_CRYPTER_LM2,  AM_CRYPTER_NTLM2, 0},   
};

#endif /* UD_NQ_INCLUDECIFSCLIENT */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)

/* security mechanism */
typedef struct
{
	NQ_UINT32 mask;					/* mechanism mask as AM_MECH... */
    const CMAsn1Oid *oid;           /* ASN1 OID */
    const CMAsn1Oid *reqOid;        /* ASN1 request OID */
    const NQ_CHAR* name;            /* readable name */
    NQ_BOOL (*init)(void*);                          
    NQ_BOOL (*stop)();                      
    NQ_BOOL (*setMechanism)(NQ_BYTE *, const NQ_CHAR *);        
    NQ_BYTE*(*contextCreate)(const NQ_CHAR *, NQ_BOOL);             
    NQ_BOOL (*generateFirstRequest)(NQ_BYTE *, const NQ_CHAR *, NQ_BYTE **, NQ_COUNT *);                    
    NQ_BOOL (*generateNextRequest)(NQ_BYTE*, const NQ_BYTE *, NQ_COUNT, NQ_BYTE **, NQ_COUNT *, NQ_BYTE *);                    
    NQ_BOOL (*getSessionKey)(NQ_BYTE*, NQ_BYTE *, NQ_COUNT *);      
    NQ_BOOL (*contextIsValid)(NQ_BYTE *);
    NQ_BOOL (*contextDispose)(NQ_BYTE *);
    void    (*contextInvalidate)(NQ_BYTE *);
    NQ_BOOL (*packNegotBlob)(void *, CMBufferWriter *, NQ_COUNT, NQ_COUNT *);
    NQ_INT type;                    /* future - mechanism type */
} SecurityMechanism;

/* Description
   This structure describes SPNEGO context. */
typedef struct 
{
	NQ_INT defAuthLevel;	/* authentication level to start with */	
	NQ_STATUS status;		/* result of the last operation */
	const SecurityMechanism * mechanism;	/* security mechanism to use */ 
	NQ_BYTE * extendedContext;	/* extended context per mechanism */
	AMCredentialsW credentials;	/* credentials to use */
	CMBlob * sessionKey;		/* pointer to session key blob */
	CMBlob * macSessionKey;		/* pointer to MAC session key blob */
	NQ_UINT level;				/* required security level as suppplied in allocateContext */
} Context; /* SPNEGO context. */


#ifdef UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS
static NQ_BOOL packNegotBlobKerberos(
    void * context,
    CMBufferWriter * writer,
    NQ_COUNT mechtokenBlobLen,
    NQ_COUNT * blobLen 
    );
static NQ_BYTE* saslContextCreate(const NQ_CHAR * name, NQ_BOOL restrictCrypt)
{
    return sySaslContextCreate(name, FALSE, TRUE); 
}

#endif /* UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS */

/* -- Static data -- */

/* forward definitions */

static SecurityMechanism clientMechanisms[] =
{  
   {
    AM_MECH_NTLMSSP,
	&cmGssApiOidNtlmSsp, 
	&cmGssApiOidNtlmSsp, 
	"NTLMSSP", 
    amNtlmsspClientInit,  
    amNtlmsspClientStop, 
    amNtlmsspClientSetMechanism, 
    amNtlmsspClientContextCreate, 
    amNtlmsspClientGenerateFirstRequest, 
    amNtlmsspClientGenerateNextRequest, 
    amNtlmsspClientGetSessionKey,
    amNtlmsspClientContextIsValid, 
    amNtlmsspClientContextDispose, 
    amNtlmsspClientContextInvalidate, 
    amNtlmsspClientPackNegotBlob,
    0
   },       
#ifdef UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS        
   {
	AM_MECH_KERBEROS,
	&cmGssApiOidMsKerberos, 
	&cmGssApiOidKerberos, 
	"KERBEROS", 
    sySaslClientInit, 
    sySaslClientStop, 
    sySaslClientSetMechanism, 
    saslContextCreate, 
    sySaslClientGenerateFirstRequest, 
    sySaslClientGenerateNextRequest, 
    sySaslGetSessionKey, 
    sySaslContextIsValid, 
    sySaslContextDispose, 
    sySaslContextInvalidate, 
    packNegotBlobKerberos,
    0
   }
#endif /* UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS */
};

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

NQ_BOOL amSpnegoStart(void)
{
	return TRUE;
}

void amSpnegoShutdown(void)
{
	
}


/* -- static functions -- */

#if (defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)) || (defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY))

static void logBadTag(NQ_INT expected, NQ_INT seen)
{
	LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tag in the blob");
	LOGERR(CM_TRC_LEVEL_ERROR, "  expected: %d, seen: %d", expected, seen);
}

#endif /* (defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)) || (defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)) */

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)

/* list of server mechanisms */ 
static const AMSpnegoServerMechDescriptor* (*serverMechanisms[])(void) =
{
    amNtlmsspGetServerDescriptor
};


/* -- server functions -- */

/*
 *====================================================================
 * PURPOSE: call mechanism and compose response 
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to mechanism descriptor
 *          IN  incoming blob descriptor
 *          IN  TRUE if not wrapped by GSSAPI
 *          OUT outgoing blob descriptor
 *          OUT encrypted passwords descriptor
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for session key pointer or NULL if none 
 * 
 * RETURNS: status, icluding:
 *                              0           - was authenticated
 *      AM_STATUS_NOT_AUTHENTICATED          - was parsed but not authenticated yet
 *      AM_STATUS_MORE_PROCESSING_REQUIRED - was recognized but requires more exchange
 *      <any other>                         - parse error
 *
 * NOTES:
 *      Some mechanisms parse passwords and return AM_STATUS_NOT_AUTHENTICATED without 
 *      really autheticating user. Then the user will be authenticated later in 
 *      SessionSetup processing. 
 *====================================================================
 */

static NQ_UINT32 callMechanism(
    const AMSpnegoServerMechDescriptor * pMech,
    CMRpcPacketDescriptor * in,
    NQ_BOOL naked,
    CMRpcPacketDescriptor * out,     
    AMNtlmDescriptor * descr,  
    NQ_WCHAR * userName,             
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE** pSessionKey                 
    )
{
    NQ_UINT32 res;              /* status */
    NQ_COUNT responseConLen = 0;/* length of responseTokenLen CONTEXT */ 
    NQ_COUNT responseLen;       /* length of entire responseTokenLen */ 
    NQ_COUNT mechTokenLen;      /* length of the data generated by the mechanism */
    NQ_COUNT mechConLen = 0;    /* length of the mechanism CONTEXT */ 
    NQ_COUNT mechListLen;       /* length of the entire mechanism */ 
    NQ_COUNT negresultLen = 5;  /* length of negResult */ 
    NQ_COUNT nettokenSeqLen;    /* length of netTokenTarg SEQUENCE */
    NQ_COUNT nettokenConLen;    /* length of netTokenTarg CONTEXT */
    const NQ_BYTE* pSrc;        /* source pointer for moving data in the memory */
    NQ_BYTE* pDst;              /* source pointer for moving data in the memory */
    NQ_COUNT i;                 /* just an index */
#if SY_DEBUGMODE
	NQ_BYTE * pDump;            /* temporary */
#endif /* SY_DEBUGMODE */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

#if SY_DEBUGMODE
    pDump = out->current;
#endif /* SY_DEBUGMODE */
    /*TRCDUMP("before NTLMSSP", pDump, 40);*/
    res = (*pMech->processor)(in, out, descr, userName, pDomain, pSessionKey);
    /*TRCDUMP("after NTLMSSP", pDump, 40);*/
    
    /* calculate lengths */
    mechTokenLen = (NQ_COUNT)(out->current - out->origin);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "mechTokenLen = %d", mechTokenLen);

    if (naked)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "no SPNEGO wrapping needed");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return res;
    }

    if (0 == mechTokenLen) 
    {
        responseLen = 0;
        mechListLen = 0;
    }
    else
    {
        responseConLen = 1 + cmAsn1PackLen(mechTokenLen) + mechTokenLen;
        responseLen = 1 + cmAsn1PackLen(responseConLen) + responseConLen;
        mechConLen = 1 + cmAsn1PackLen(pMech->oid->size) + pMech->oid->size;
        mechListLen = 1 + cmAsn1PackLen(mechConLen) + mechConLen;
    }
    nettokenSeqLen = negresultLen + mechListLen + responseLen;
    nettokenConLen = 1 + cmAsn1PackLen(nettokenSeqLen) + nettokenSeqLen;

    /* shift mechanism blob, we cannot use syMemcpy because of overlaping areas, we
     * move backwards from the end */
    if (0 != mechTokenLen) 
    {
        for ( i = mechTokenLen, 
              pSrc = out->current, 
              pDst = out->current 
                + 1 + cmAsn1PackLen(nettokenConLen) 
                + 1 + cmAsn1PackLen(nettokenSeqLen) 
                + negresultLen + mechListLen + responseLen 
                - mechTokenLen; 
              i>0; i--)
        {
            *--pDst = *--pSrc;
        }
    }
    
    /*TRCDUMP("after shift", pDump, 40);*/
    /* generate SPNEGO */
    out->current = out->origin; /* start from the beginning */
    cmAsn1PackTag(out, CM_ASN1_CONTEXT + 1, nettokenConLen); 
    cmAsn1PackTag(out, CM_ASN1_SEQUENCE, nettokenSeqLen);
    cmAsn1PackTag(out, CM_ASN1_CONTEXT, 3);
    cmAsn1PackTag(out, CM_ASN1_ENUMERATED, 1);
    cmRpcPackByte(out, res == AM_STATUS_NOT_AUTHENTICATED? 
        SPNEGO_ACCEPTCOMPLETE :  SPNEGO_ACCEPTINCOMPLETE);    
    if (0 != mechTokenLen)
    {
        cmAsn1PackTag(out, CM_ASN1_CONTEXT + 1, mechConLen);
        cmAsn1PackOid(out, pMech->oid);
        cmAsn1PackTag(out, CM_ASN1_CONTEXT + 2, responseConLen); 
        cmAsn1PackTag(out, CM_ASN1_BINARY, mechTokenLen);
        /* mech token follows - already generated and shifted */

        /* advance output blob pointer */
        out->current += mechTokenLen;
    }     
    
    /*TRCDUMP("after callMechanism()", pDump, 40);*/
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}   

/*
 *====================================================================
 * PURPOSE: continue parsing netTokenInit SPNEGO message 
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT session structure
 *          IN  incoming blob descriptor
 *          OUT outgoing blob descriptor
 *          OUT encrypted passwords descriptor
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for session key pointer or NULL if none
 *
 * RETURNS: status, icluding:
 *                              0           - was authetiucated
 *      AM_STATUS_NOT_AUTHENTICATED         - was parsed but not autheticated yet
 *      AM_STATUS_MORE_PROCESSING_REQUIRED  - was recognized but requires more exchange
 *      <any other>                         - parse error
 *
 * NOTES:
 *      Some mechanisms parse passwords and return AM_STATUS_NOT_AUTHENTICATED without 
 *      really autheticating user. Then the user will be authenticated later in 
 *      SessionSetup processing. 
 *====================================================================
 */

static NQ_UINT32 doNegTokenInit(
    const AMSpnegoServerMechDescriptor ** pMechBuf,
    CMRpcPacketDescriptor * in, 
    CMRpcPacketDescriptor * out, 
    AMNtlmDescriptor * descr, 
    NQ_WCHAR * userName,           
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE ** pSessionKey            
    )
{   
    CMAsn1Len dataLen;          /* data length for the next tag */
    CMAsn1Tag tag;              /* ASN1 r=tag code */
    NQ_BYTE* mechData;          /* pointer to the mechanism-specific blob */
    NQ_INDEX i;                 /* just a counter */
    NQ_UINT32 res;              /* status */
    const AMSpnegoServerMechDescriptor * pMech = NULL;   /* next mechanism descriptor */
     
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    if (!cmAsn1ParseCompareOid(in, &cmGssApiOidSpnego))   /* SPNEGO OID */
    {
        LOGERR(CM_TRC_LEVEL_ERROR,  "unexpected OID");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    tag = cmAsn1ParseTag(in, &dataLen);                    /* SPNEGO */      
    if (CM_ASN1_CONTEXT != tag)
    {
        logBadTag(CM_ASN1_CONTEXT, tag);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    tag = cmAsn1ParseTag(in, &dataLen);                    /* SPNEGO cont */
    if (CM_ASN1_SEQUENCE != tag)
    {
        logBadTag(CM_ASN1_SEQUENCE, tag);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    tag = cmAsn1ParseTag(in, &dataLen);                    /* netTokenInit */
    if (CM_ASN1_CONTEXT != tag)
    {
        logBadTag(CM_ASN1_CONTEXT, tag);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    tag = cmAsn1ParseTag(in, &dataLen);                    /* netTokenInit cont */
    if (CM_ASN1_SEQUENCE != tag)
    {
        logBadTag(CM_ASN1_SEQUENCE, tag);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    mechData = in->current + dataLen;
    tag = cmAsn1ParseTag(in, &dataLen);
    if (CM_ASN1_OID != tag)                         /* first mech OID */
    {
        logBadTag(CM_ASN1_OID, tag);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    for (i = 0; i < sizeof(serverMechanisms)/sizeof(serverMechanisms[0]); i++)
    {
        pMech = (*serverMechanisms[i])();
        if (0 == syMemcmp(pMech->oid->data, in->current, dataLen))
            break;
    }
    if (i == sizeof(serverMechanisms)/sizeof(serverMechanisms[0]))
    {
        LOGERR(CM_TRC_LEVEL_ERROR,  "mechanism is not supported");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    *pMechBuf = pMech;
    in->current = mechData;
    tag = cmAsn1ParseTag(in, &dataLen);         /* mechToken */
    if (CM_ASN1_CONTEXT + 2 != tag)
    {
        logBadTag(CM_ASN1_CONTEXT + 2, tag);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    tag = cmAsn1ParseTag(in, &dataLen);         /* mechToken cont */
    if (CM_ASN1_BINARY != tag)
    {
        logBadTag(CM_ASN1_BINARY, tag);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    res = callMechanism(pMech, in, FALSE, out, descr, userName, pDomain, pSessionKey);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}
    
/*
 *====================================================================
 * PURPOSE: continue parsing netTokenTarg SPNEGO message 
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT session structure
 *          IN  incoming blob descriptor
 *          OUT outgoing blob descriptor
 *          OUT encrypted passwords descriptor
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for session key pointer or NULL if none
 *
 * RETURNS: status, icluding:
 *                              0           - was authetiucated
 *      AM_STATUS_NOT_AUTENTICATED          - was parsed but not autheticated yet
 *      AM_STATUS_MORE_PROCESSING_REQUIRED  - was recognized but requires more exchange
 *      <any other>                         - parse error
 *
 * NOTES:
 *      Some mechanisms parse passwords and return AM_STATUS_NOT_AUTHENTICATED without 
 *      really autheticating user. Then the user will be authenticated later in 
 *      SessionSetup processing. 
 *====================================================================
 */

static NQ_UINT32 doNegTokenTarg(
    const AMSpnegoServerMechDescriptor * pMech,
    CMRpcPacketDescriptor * in, 
    CMRpcPacketDescriptor * out, 
    AMNtlmDescriptor * descr, 
    NQ_WCHAR * userName,           
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE ** pSessionKey            
    )
{   
    CMAsn1Len dataLen;          /* data length for the next tag */
    CMAsn1Tag tag;              /* ASN1 r=tag code */
    NQ_UINT32 res;              /* status */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
     
    tag = cmAsn1ParseTag(in, &dataLen);                    /* SPNEGO */
    if (CM_ASN1_SEQUENCE != tag)  
    {
        logBadTag(CM_ASN1_SEQUENCE, tag);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    tag = cmAsn1ParseTag(in, &dataLen);         /* mechToken */
    switch (tag)
    {
        case (CM_ASN1_CONTEXT): 
            tag = cmAsn1ParseTag(in, &dataLen);         /* mechToken cont */
            if (CM_ASN1_ENUMERATED != tag)      
            {
                logBadTag(CM_ASN1_ENUMERATED, tag);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return AM_STATUS_BAD_FORMAT;
            }
            cmRpcParseSkip(in, dataLen);
            tag = cmAsn1ParseTag(in, &dataLen);         /* mechToken cont */
            if (CM_ASN1_CONTEXT + 2 != tag)      
            {
                logBadTag(CM_ASN1_CONTEXT + 2, tag);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return AM_STATUS_BAD_FORMAT;
            }
        case (CM_ASN1_CONTEXT + 2):
            tag = cmAsn1ParseTag(in, &dataLen);         /* mechToken cont */
            if (CM_ASN1_BINARY != tag)     
            {
                logBadTag(CM_ASN1_BINARY, tag);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return AM_STATUS_BAD_FORMAT;
            }
            break;
        default:
            LOGERR(CM_TRC_LEVEL_ERROR,  "unexpected tag");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " expected either 0x%x or 0x%x", CM_ASN1_CONTEXT + 2, CM_ASN1_CONTEXT);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return AM_STATUS_BAD_FORMAT;
    }
  
    res = callMechanism(pMech, in, FALSE, out, descr, userName, pDomain, pSessionKey);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}
    

/*
 *====================================================================
 * PURPOSE: generate list of mechanisms in Negotiate Response
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT double pointer to the response buffer
 *          IN/OUT pointer to list length
 *
 * RETURNS: zero on success, error code on failure
 *
 * NOTES:
 *====================================================================
 */

CMBlob amSpnegoServerGenerateMechList(void)
{ 
    NQ_INT i;                               /* just a pointer */
    NQ_COUNT listLen;                       /* mechanism list length */
    NQ_COUNT principalConLen;               /* principal context length */
    NQ_COUNT principalStrLen;               /* principal string length */
    NQ_COUNT spnegoConLen;                  /* SPNEGO context tag data length */
    NQ_COUNT spnegoSeqLen;                  /* SPNEGO sequence tag data length */
    NQ_COUNT negtokinitConLen;              /* negTokenInit context tag data length */
    NQ_COUNT negtokinitSeqLen;              /* negTokenInit sequence tag data length */
    NQ_COUNT micConLen;                     /* mecListMIC context tag data length */
    NQ_COUNT micSeqLen;                     /* mecListMIC sequence tag data length */
    NQ_COUNT totalLen;                      /* total length of the root tag data */ 
    AMSpnegoServerMechDescriptor * pDescr;  /* next mechanism descriptor */
    CMRpcPacketDescriptor ds;               /* packet descriptor for ASN1 packing */
    const NQ_CHAR * principal = "not_defined_in_RFC4178@please_ignore";    /* principal name */
    CMBlob blob;                            /* resulted blob */
      
    /* calculate total length of security mechanism OIDs */
    listLen = 0;
    for (i = 0; i < sizeof(serverMechanisms)/sizeof(serverMechanisms[0]); i++)
    {
        pDescr = (AMSpnegoServerMechDescriptor*)(*serverMechanisms[0])();
        listLen += 1 + cmAsn1PackLen(pDescr->oid->size) + pDescr->oid->size;
    }
    
    /* calculate total length */
    principalStrLen = (NQ_COUNT)syStrlen(principal);
    principalConLen = 1 + cmAsn1PackLen(principalStrLen) + principalStrLen;
    micSeqLen = 1 + cmAsn1PackLen(principalConLen) + principalConLen;
    micConLen = 1 + cmAsn1PackLen(micSeqLen) + micSeqLen;
    negtokinitSeqLen =   listLen;
    negtokinitConLen =  1 + cmAsn1PackLen(negtokinitSeqLen) + negtokinitSeqLen;
    spnegoSeqLen =      1 + cmAsn1PackLen(negtokinitConLen) + negtokinitConLen + 1 + cmAsn1PackLen(micConLen) + micConLen;  
    spnegoConLen =      1 + cmAsn1PackLen(spnegoSeqLen) + spnegoSeqLen;  
    totalLen =    1 + cmAsn1PackLen(cmGssApiOidSpnego.size) + cmGssApiOidSpnego.size     
                + 1 + cmAsn1PackLen(spnegoConLen) + spnegoConLen;
                
    /* compose blob */
    blob.data = cmMemoryAllocate(totalLen + 2);
    if (NULL == blob.data)
    {
        blob.len = 0;
        return blob;
    }
    blob.len = totalLen + 2;
    cmRpcSetDescriptor(&ds, blob.data, FALSE);         
    cmAsn1PackTag(&ds, CM_ASN1_APPLICATION, totalLen);      /* GSSAPI */
    cmAsn1PackOid(&ds, &cmGssApiOidSpnego);                 /* SPNEGO OID */
    cmAsn1PackTag(&ds, CM_ASN1_CONTEXT, spnegoConLen);      /* SPNEGO */
    cmAsn1PackTag(&ds, CM_ASN1_SEQUENCE, spnegoSeqLen);     /* SPNEGO */
    cmAsn1PackTag(&ds, CM_ASN1_CONTEXT, negtokinitConLen);  /* negTokenInit */
    cmAsn1PackTag(&ds, CM_ASN1_SEQUENCE, negtokinitSeqLen); /* negTokenInit */
    for (i = 0; i < sizeof(serverMechanisms)/sizeof(serverMechanisms[0]); i++)
    {
        pDescr = (AMSpnegoServerMechDescriptor*)(*serverMechanisms[i])();
        cmAsn1PackOid(&ds, pDescr->oid);
    }
    
    cmAsn1PackTag(&ds, CM_ASN1_CONTEXT + 3, micConLen);     /* mechListMIC */
    cmAsn1PackTag(&ds, CM_ASN1_SEQUENCE, micSeqLen);        /* mechListMIC */
    cmAsn1PackTag(&ds, CM_ASN1_CONTEXT, principalConLen);   /* principal */
    cmAsn1PackTag(&ds, CM_ASN1_STRING, principalStrLen);    /* principal */
    cmRpcPackAscii(&ds, principal, 0);                      /* text */
       
    /* finalize */
    return blob;
}

/*
 *====================================================================
 * PURPOSE: parse a blob and generate a response blob
 *--------------------------------------------------------------------
 * PARAMS:	IN  session structure  
 *          IN  incoming blob
 *          OUT outgoing blob buffer
 *          OUT buffer for outgoing blob length
 *          OUT encrypted passwords descriptor
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for session key pointer or NULL if none
 *
 * RETURNS: status, icluding:
 *                              0           - was authetiucated
 *      AM_STATUS_NOT_AUTHENTICATED         - was parsed but not autheticated yet
 *      AM_STATUS_MORE_PROCESSING_REQUIRED  - was recognized but requires more exchange
 *      <any other>                         - parse error
 *
 * NOTES:
 *      Some mechanisms parse passwords and return AM_STATUS_NOT_AUTHENTICATED without 
 *      really autheticating user. Then the user will be authenticated later in 
 *      SessionSetup processing. 
 *====================================================================
 */

NQ_UINT32 amSpnegoServerAcceptBlobA(
    const void ** pMechBuf,
    CMBlob * inBlob,      
    CMBlob * outBlob,            
    NQ_CHAR * userName,  
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE ** pSessionKey,
    AMNtlmDescriptor * ntlmDescr
    )   
{
    NQ_WCHAR * userNameW;       /* user name in unicode */
    NQ_STATUS status;           /* Unicode operation result */
    
    userNameW = cmMemoryAllocate(CM_USERNAMELENGTH);
    if (NULL == userNameW)
    {
        return AM_STATUS_INSUFFICIENT_RESOURCES;
    }
    status = (NQ_STATUS)amSpnegoServerAcceptBlobW(pMechBuf, inBlob, outBlob, userNameW, pDomain, pSessionKey, ntlmDescr);
    cmUnicodeToAnsi(userName, userNameW);
    cmMemoryFree(userNameW);
    return (NQ_UINT32)status;
}

/*
 *====================================================================
 * PURPOSE: parse a blob and generate a response blob
 *--------------------------------------------------------------------
 * PARAMS:	IN  session structure  
 *          IN  incoming blob
 *          OUT outgoing blob buffer
 *          OUT buffer for outgoing blob length
 *          OUT encrypted passwords descriptor
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for session key pointer or NULL if none
 *
 * RETURNS: status, icluding:
 *                              0           - was authetiucated
 *      AM_STATUS_NOT_AUTHENTICATED         - was parsed but not autheticated yet
 *      AM_STATUS_MORE_PROCESSING_REQUIRED  - was recognized but requires more exchange
 *      <any other>                         - parse error
 *
 * NOTES:
 *      Some mechanisms parse passwords and return AM_STATUS_NOT_AUTHENTICATED without 
 *      really autheticating user. Then the user will be authenticated later in 
 *      SessionSetup processing. 
 *====================================================================
 */

NQ_UINT32 amSpnegoServerAcceptBlobW(
    const void ** pMechBuf,
    CMBlob * inBlob,      
    CMBlob * outBlob,            
    NQ_WCHAR * userName,  
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE ** pSessionKey,
    AMNtlmDescriptor * ntlmDescr
    )   
{
    CMRpcPacketDescriptor in;   /* packet descriptor for ASN1 parsing */
    CMRpcPacketDescriptor out;  /* packet descriptor for ASN1 packing */
    CMAsn1Tag tag;              /* ASN1 r=tag code */
    NQ_UINT32 res = 0;          /* status */ 
    NQ_INDEX i;                 /* index */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	*pDomain = NULL;
    cmRpcSetDescriptor(&in, inBlob->data, FALSE);
    cmRpcSetDescriptor(&out, outBlob->data, FALSE);
    out.length = UD_NS_BUFFERSIZE - 200;

    /* parse blob */
    tag = cmAsn1ParseTag(&in, &in.length);
    switch(tag)
    {
    case CM_ASN1_APPLICATION:
        res = doNegTokenInit((const AMSpnegoServerMechDescriptor **)pMechBuf, &in, &out, ntlmDescr, userName, pDomain, pSessionKey);
        break;
    case CM_ASN1_CONTEXT + 1:
        res = doNegTokenTarg(*(const AMSpnegoServerMechDescriptor **)pMechBuf, &in, &out, ntlmDescr, userName, pDomain, pSessionKey);
        break;    
    default:
        LOGERR(CM_TRC_LEVEL_ERROR,  "unexpected tag: 0x%x", tag);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "trying supported mechanisms");
        /* try supported mechanisms */
        for (i = 0; i < sizeof(serverMechanisms)/sizeof(serverMechanisms[0]); i++)
        {
            const AMSpnegoServerMechDescriptor * mech = (*serverMechanisms[0])();
            cmRpcSetDescriptor(&in, inBlob->data, FALSE);
            res = callMechanism(mech, &in, TRUE, &out, ntlmDescr, userName, pDomain, pSessionKey);
        }        
    }
    outBlob->len = (NQ_COUNT)(out.current - out.origin);
    inBlob->data = in.current;
    inBlob->len -= (NQ_COUNT)(in.current - in.origin);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "blob length = %d, res = 0x%x", outBlob->len, res);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}   

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) */

/* -- client functions -- */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)

#ifdef UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS
static NQ_BOOL packNegotBlobKerberos(
    void * context,
    CMBufferWriter * writer,
    NQ_COUNT mechtokenBlobLen,
    NQ_COUNT * blobLen 
    )
{
    NQ_COUNT gssapiLen;         /* tag length */
    NQ_COUNT spnegoLen;         /* tag length */
    NQ_COUNT negtokenLen;       /* tag length */
    NQ_COUNT mechtypesLen;      /* tag length */
    NQ_COUNT mechtypesSeqLen;   /* tag length */
    NQ_COUNT mechtokenBinLen;   /* tag length */
    NQ_COUNT mechtokenAppLen;   /* tag length */
    NQ_COUNT mechtokenLen;      /* tag length */ 
    NQ_COUNT len;               /* tag length */
    Context * pContext;         /* context    */
    NQ_COUNT totalLen;          /* total packed blob length */

    pContext = (Context *)context;

    /* calculate field lengths - backwards */
    len = pContext->mechanism->oid->size;
    mechtypesSeqLen = 1 + cmAsn1PackLen(len) + len + 1 + cmAsn1PackLen(cmGssApiOidNtlmSsp.size) + cmGssApiOidNtlmSsp.size;
    mechtypesLen = 1 + cmAsn1PackLen(mechtypesSeqLen) + mechtypesSeqLen;
    mechtokenAppLen = 1 + cmAsn1PackLen(len) + pContext->mechanism->reqOid->size + 2 + mechtokenBlobLen;
    mechtokenBinLen = 1 + cmAsn1PackLen(mechtokenAppLen) + mechtokenAppLen;
    mechtokenLen = 1 + cmAsn1PackLen(mechtokenBinLen) + mechtokenBinLen;
    negtokenLen = 1 + cmAsn1PackLen(mechtypesLen) + mechtypesLen + 1 + cmAsn1PackLen(mechtokenLen) + mechtokenLen;
    spnegoLen = 1 +  cmAsn1PackLen(negtokenLen) + negtokenLen;
    gssapiLen = 1 + cmAsn1PackLen(spnegoLen) + spnegoLen + 1 + cmAsn1PackLen(cmGssApiOidSpnego.size) + cmGssApiOidSpnego.size;
    totalLen = 1 + cmAsn1PackLen(gssapiLen) + gssapiLen;
    if (*blobLen < totalLen)
    {
         LOGERR(CM_TRC_LEVEL_ERROR, "supplied %d, required %d", *blobLen, totalLen);
         *blobLen = totalLen;
         return FALSE; 
    }
    *blobLen = totalLen;

    cmAsn1PackTag(writer, CM_ASN1_APPLICATION, gssapiLen);
    cmAsn1PackOid(writer, &cmGssApiOidSpnego);
    cmAsn1PackTag(writer, CM_ASN1_CONTEXT, spnegoLen);
    cmAsn1PackTag(writer, CM_ASN1_SEQUENCE, negtokenLen);
    cmAsn1PackTag(writer, CM_ASN1_CONTEXT, mechtypesLen);
    cmAsn1PackTag(writer, CM_ASN1_SEQUENCE, mechtypesSeqLen);
    cmAsn1PackOid(writer, pContext->mechanism->oid);
    cmAsn1PackOid(writer, &cmGssApiOidNtlmSsp);
    cmAsn1PackTag(writer, CM_ASN1_CONTEXT + 2, mechtokenLen);
    cmAsn1PackTag(writer, CM_ASN1_BINARY, mechtokenBinLen);
    cmAsn1PackTag(writer, CM_ASN1_APPLICATION, mechtokenAppLen);
    cmAsn1PackOid(writer, pContext->mechanism->reqOid);
    cmBufferWriteUint16(writer, 1);        /* KRB5_APP_REQ */
    return TRUE;
}

#endif /* UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS */


CMBlob * amSpnegoClientGetSessionKey(void * context)
{
    Context * pContext = (Context *)context;

    return pContext->sessionKey;
}

const AMCredentialsW * amSpnegoClientGetCredentials(void * context)
{
    Context * pContext = (Context *)context;

    return &pContext->credentials;
}

CMBlob * amSpnegoClientGetMacSessionKey(void * context)
{
    Context * pContext = (Context *)context;

    return pContext->macSessionKey;
}

NQ_UINT amSpnegoClientGetCrypter1(void * context)
{
    Context * pContext = (Context *)context;

    return levels[pContext->level].crypter1;
}

NQ_UINT amSpnegoClientGetCrypter2(void * context)
{
    Context * pContext = (Context *)context;

    return levels[pContext->level].crypter2;
}

NQ_UINT amSpnegoClientGetCryptLevel(void * context)
{
    Context * pContext = (Context *)context;

    return pContext->level;
}


/* Description
   This function allocates SPNEGO context and defines its
   \parameters. The contexts of this structure is hidden.
   Application should call freeContext()
   to release this context.
   Parameters
   credentials :       Credentials to use for logon.
   level :             Security level. This value should be
                       greater or equal to zero and it should not
                       exceed the maximum security level as
                       defined in <link AM_MAXSECURITYLEVEL>. An
                       illegal value is replaced with <link AM_MAXSECURITYLEVEL>.
   Returns
   Pointer to the abstract context structure or NULL on error.                                                                                     */
static void * allocateContext(const AMCredentialsW * credentials, NQ_UINT level)
{
	Context * pContext; /* casted pointer */
	pContext = (Context *) cmMemoryAllocate(sizeof(Context));
    if (NULL != pContext)
    {
	    pContext->extendedContext = NULL;
	    pContext->credentials = *credentials;
	    pContext->status = AM_SPNEGO_NONE;
	    pContext->level = level > AM_MAXSECURITYLEVEL ? AM_MAXSECURITYLEVEL : level;
    }
    return pContext;
}

/* Description
   This function frees memory of a previously allocated SPNEGO
   context.
   Parameters
   context :  Pointer to a previously allocated context
              structure. This value can be NULL.
   Returns
   None.*/
static void freeContext(void * context)
{
	Context * pContext = (Context*)context;	/* casted pointer */

	if (NULL == pContext)
		return;
	if (NULL != pContext->extendedContext && NULL != pContext->mechanism)
	{
		pContext->mechanism->contextDispose(pContext->extendedContext);
	}
	cmMemoryFree(context);
}

/* Description
   For extended security this function analyses a list of
   mechanisms and chooses one for further exchange.
   
   When extended security was not negotiated, this function
   always returns <i>TRUE</i>.
   Parameters
   context :        Pointer to allocated SPNEGO context. It will
                    be initialized.
   blob :           Pointer to server's blob with a list of
                    mechanisms.
   restrictCrypt :  TRUE to restrict the list of encryptions to
                    the minimum.
   hostName :       Pointer to the server host name.
   sessionKey :     Pointer to the blob where a pointer to
                    session key will be set. This value may be
                    NULL. 
   macSessionKey:   Pointer to the blob where a pointer to
                    MAC session key will be set. This value may
                    be NULL.
   Returns
   TRUE on success and FALSE on failure.                         */
static NQ_BOOL clientNegotiateSecurity(
		void * context, 
		const CMBlob * blob, 
		NQ_BOOL restrictCrypt,
		const NQ_WCHAR * hostName,
		CMBlob * sessionKey,
		CMBlob * macSessionKey
		)
{
	Context * pContext = (Context*)context;	/* casted pointer */
    CMBufferReader reader;   	/* to parse the blob */
    CMAsn1Len len;              /* object length */
    CMAsn1Tag tag;              /* next ASN1 tag */
    NQ_BYTE* listStart;         /* first address in the list of OIDs */
    NQ_BYTE* listEnd;           /* last address after the list of OIDs */
    NQ_INT i;                   /* index in security mechanisms */
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pContext->sessionKey = sessionKey;
	pContext->macSessionKey = macSessionKey;
	pContext->status = AM_SPNEGO_FAILED;	/* unless we change this later on */
	
	/* extended security was negotiated */
    if (NULL == blob || blob->len <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Security blob is missing, NTLMSSP will be used");
        pContext->mechanism = &clientMechanisms[0];
        pContext->extendedContext = (NQ_BYTE *)clientMechanisms[0].contextCreate(NULL, restrictCrypt);
      	pContext->status = AM_SPNEGO_NONE;	
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return pContext->extendedContext != NULL;      
    }

    cmBufferReaderInit(&reader, blob->data, blob->len);
    /* server GUID should be already set in the session */    
    tag = cmAsn1ParseTag(&reader, &len);
    if (CM_ASN1_APPLICATION != tag)
    {
        return NQ_ERR_BADFORMAT;
    }
    if (!cmAsn1ParseCompareOid(&reader, &cmGssApiOidSpnego)) /* SPNEGO IOD */
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected OID");
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_BADFORMAT;
    }
    tag = cmAsn1ParseTag(&reader, &len);    /* SPNEGO blob */
    if (CM_ASN1_CONTEXT != tag)
    {
    	logBadTag(CM_ASN1_CONTEXT, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_BADFORMAT;
    }
    tag = cmAsn1ParseTag(&reader, &len);    /* SPNEGO list */
    if (CM_ASN1_SEQUENCE != tag)
    {
    	logBadTag(CM_ASN1_CONTEXT, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_BADFORMAT;
    }
    tag = cmAsn1ParseTag(&reader, &len);    /* negTokenInit */
    if (CM_ASN1_CONTEXT != tag)
    {
    	logBadTag(CM_ASN1_CONTEXT, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_BADFORMAT;
    }
    tag = cmAsn1ParseTag(&reader, &len);    /* negTokenInit list */
    if (CM_ASN1_SEQUENCE != tag)
    {
    	logBadTag( CM_ASN1_CONTEXT, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_BADFORMAT;
    }
    listStart = cmBufferReaderGetPosition(&reader);
    listEnd = listStart + len;  
    for (i = sizeof(clientMechanisms)/sizeof(clientMechanisms[0]) - 1;
         i >= 0; 
         i--
        )
    {         
        for(cmBufferReaderSetPosition(&reader, listStart); cmBufferReaderGetPosition(&reader) < listEnd; )
        {
            if (cmAsn1ParseCompareOid(&reader, clientMechanisms[i].oid) &&
                (clientMechanisms[i].mask & levels[pContext->level].mask) 
               ) 
            {
                if (!clientMechanisms[i].setMechanism(pContext->extendedContext, clientMechanisms[i].name
                        )
                   )
                {
                	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to start security mechanism %s", clientMechanisms[i].name);
                	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NQ_ERR_BADFORMAT;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "received mechanism %s", clientMechanisms[i].name);
                
                pContext->mechanism = &clientMechanisms[i];
               
                if (syStrcmp(clientMechanisms[i].name, NTLMSSP_MECHANISM_NAME) == 0)
                {
                    /* for NTLMSSP no more data expected */
                    pContext->extendedContext = (NQ_BYTE *)clientMechanisms[i].contextCreate(NULL, restrictCrypt);
                }               
#ifdef UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS
                else
                {
                    cmBufferReaderSetPosition(&reader, (NQ_BYTE*)listEnd);
                    tag = cmAsn1ParseTag(&reader, &len);
                    if (CM_ASN1_CONTEXT + 3 != tag)
                    {
                    	logBadTag(CM_ASN1_CONTEXT + 3, tag);
                    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_ERR_BADFORMAT;
                    }
                    tag = cmAsn1ParseTag(&reader, &len);
                    if (CM_ASN1_SEQUENCE != tag)
                    {
                    	logBadTag(CM_ASN1_SEQUENCE, tag);
                    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_ERR_BADFORMAT;
                    }
                    tag = cmAsn1ParseTag(&reader, &len);
                    if (CM_ASN1_CONTEXT != tag)
                    {
                    	logBadTag(CM_ASN1_CONTEXT, tag);
                    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_ERR_BADFORMAT;
                    }
                    tag = cmAsn1ParseTag(&reader, &len);
                    if (CM_ASN1_STRING != tag)
                    {
                    	logBadTag(CM_ASN1_STRING, tag);
                    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return NQ_ERR_BADFORMAT;
                    }
                    if (len > 0)
                    {
                        NQ_CHAR *principalString, *ps;

                        principalString = cmMemoryAllocate(sizeof(NQ_CHAR) * (len + 1));
                        if (NULL == principalString)
                        {
                        	LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        	return FALSE;
                        }
                        
                        cmBufferReadBytes(&reader, (NQ_BYTE *)principalString, len);
                        principalString[len] = '\0';
                        ps = syStrchr(principalString, '@');
                        if (NULL == ps)
                            ps = principalString;
                        else
                            ps++;
                            
                        if (0 == syStrcmp(ps, "please_ignore"))
                        {
                            NQ_CHAR * principalName;	/* principal name */
                            NQ_CHAR * hostNameA;	/* host name in ASCII */
                            
                            principalName = cmMemoryAllocate(300 * sizeof(NQ_CHAR));
                            if (NULL == principalName)
                            {
                                cmMemoryFree(principalString);
                            	LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                            	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            	return FALSE;
                            }
                            if (NULL != hostName)
                                hostNameA = cmMemoryCloneWStringAsAscii(hostName);
                            else
                            {
                                hostNameA = cmMemoryAllocate(1);
                                *hostNameA = '\0';
                            }
                            if (NULL == hostNameA)
                            {
                                cmMemoryFree(principalString);
                                cmMemoryFree(principalName);
                            	LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                            	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            	return FALSE;
                            }
                            /* construct principal name */
                            if ('\0' != *hostNameA)
                            {
                                if (syStrlen(hostNameA) > 15)
                                {
                                    syStrcpy(principalName, "cifs/");
                                    syStrcat(principalName, hostNameA);
                                }
                                else
                                {
                                    syStrcpy(principalName, hostNameA);
                                    syStrcat(principalName, "$");
                                }
                            }  
                            pContext->extendedContext = (NQ_BYTE *)clientMechanisms[i].contextCreate(
                                principalName, restrictCrypt
                                );
                            cmMemoryFree(principalName);
                            cmMemoryFree(hostNameA);
                        }
                        else
                        {
                        	pContext->extendedContext = (NQ_BYTE *)clientMechanisms[i].contextCreate(
                        		principalString, restrictCrypt);
                        }   
                        cmMemoryFree(principalString);
                    }
                }
#endif /* UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS */
                if (pContext->extendedContext != NULL)
                {                   
                	pContext->status = AM_SPNEGO_NONE;	
                	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return TRUE;
                }
            }
        }
    }
    
    LOGERR(CM_TRC_LEVEL_ERROR, "SPNEGO does not contain supported OID or not extended security level was required");
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return FALSE;
}

/* Description
   This function generates first client's response. When
   extended security was negotiated, it generates SPNEGO
   response. Otherwise, it generates a blob using the first
   encryption algorithm.
   Parameters
   context :  Pointer to SPNEGO context.
   Returns
   Generated blob or invalid blob on error.
*/
static CMBlob clientGenerateFirstBlob(void * context)
{
	Context * pContext = (Context*)context;	/* casted pointer */
	CMBlob blob; 							/* the result */
	const CMBlob nullBlob = { NULL, 0};		/* for error response */
    CMBufferWriter writer;   				/* for packing */
    CMBlob mechTokenBlob;  					/* mach-specific part of the blob */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pContext->status = AM_SPNEGO_FAILED;	/* unless we change this later on */
    if (!pContext->mechanism->contextIsValid(pContext->extendedContext))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Security context does not exist");
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }

    if (!pContext->mechanism->generateFirstRequest(
                pContext->extendedContext,
                pContext->mechanism->name,
                &mechTokenBlob.data,
                &mechTokenBlob.len
                )
           )   
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate first blob");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return nullBlob;
	}
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "mech blob length %d", mechTokenBlob.len);

    /* get total packed blob length (asn + mech blob) */
    blob.len = 0;
    pContext->mechanism->packNegotBlob(pContext, &writer, mechTokenBlob.len, &blob.len);
    blob.data = cmMemoryAllocate(blob.len);
    if (NULL == blob.data)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }
    cmBufferWriterInit(&writer, blob.data, blob.len);
    if (!pContext->mechanism->packNegotBlob(pContext, &writer, mechTokenBlob.len, &blob.len))
	{
	    cmMemoryFreeBlob(&blob);
		LOGERR(CM_TRC_LEVEL_ERROR, "Generated blob too big");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return nullBlob;
	}
	cmBufferWriteBytes(&writer, mechTokenBlob.data, mechTokenBlob.len);

    pContext->status = AM_SPNEGO_CONTINUE;
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return blob;
}

/* Description
   This function accepts server challenge/response and
   optionally generates another client's response. When extended
   security was negotiated, it generates SPNEGO response.
   Otherwise, it generates a blob using the second encryption
   algorithm.
   Parameters
   context :  Pointer to SPNEGO context.
   blob :     Pointer to server's blob with a challenge/response.
              When extended security was not negotiated, this
              parameter is ignored.
   Returns
   Generated blob or invalid blob on error.
*/
static CMBlob clientAcceptNextBlob(void * context, const CMBlob * inBlob)
{
	CMBlob newBlob; 						/* the result */
	CMBlob mechBlob;						/* mechanism-specific portion of the incoming/outgoing blob */ 
	Context * pContext = (Context*)context;	/* casted pointer */
	const CMBlob nullBlob = { NULL, 0};		/* for error response */
    CMBufferReader reader;   				/* for parsing */
    CMBufferWriter writer;   				/* for packing */
    CMAsn1Len len;                          /* length of the current field */
    CMAsn1Tag tag;                          /* next tag */
    NQ_BYTE b;                              /* byte value */
    NQ_BOOL complete;                       /* TRUE for the last blob */
    NQ_COUNT gssapiLen;                     /* tag length */
    NQ_COUNT negtokenLen;                   /* tag length */
    NQ_COUNT mechtokenLen;                  /* tag length */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "blob length %d", inBlob->len);
	newBlob.len = 0;
	newBlob.data = NULL;
    
	pContext->status = AM_SPNEGO_FAILED;	/* unless we change this later on */
    if (!pContext->mechanism->contextIsValid(pContext->extendedContext))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Security context does not exist");
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }
	
	if (inBlob->len == 0)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, "Zero Length blob");
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }
 
    cmBufferReaderInit(&reader, inBlob->data, inBlob->len);

    tag = cmAsn1ParseTag(&reader, &len);            /* GSSAPI/SPNEGO */
    if (CM_ASN1_CONTEXT + 1 != tag)
    {
    	logBadTag(CM_ASN1_CONTEXT + 1, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }
    tag = cmAsn1ParseTag(&reader, &len);            /* negTokenTag */
    if (CM_ASN1_SEQUENCE != tag)
    {
        logBadTag(CM_ASN1_SEQUENCE, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }
    tag = cmAsn1ParseTag(&reader, &len);            /* negResult */
    if (CM_ASN1_CONTEXT != tag)
    {
        logBadTag(CM_ASN1_CONTEXT, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }
    tag = cmAsn1ParseTag(&reader, &len);            /* negResult */
    if (CM_ASN1_ENUMERATED != tag || len != 1)
    {
        logBadTag(CM_ASN1_ENUMERATED, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }
    cmBufferReadByte(&reader, &b);
    switch(b)
    {
        case SPNEGO_ACCEPTINCOMPLETE:
            complete = FALSE;
            break;
        case SPNEGO_ACCEPTCOMPLETE:
            complete = TRUE;
            break;
        default:
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected negResult, expected %d, seen %d", SPNEGO_ACCEPTINCOMPLETE, b);
        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return nullBlob;
    }
    if (complete)
    {
        /* get session key for regular user if not yet (true for Kerberos) */
        if (NULL == pContext->macSessionKey->data && cmWStrlen(pContext->credentials.user) != 0)
        {
            pContext->macSessionKey->data = cmMemoryAllocate(sizeof(NQ_BYTE) * 32);
            if (NULL == pContext->macSessionKey->data)
            {
            	LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            	return nullBlob;
            }
            pContext->macSessionKey->len = 32;
            pContext->mechanism->getSessionKey(pContext->extendedContext, pContext->macSessionKey->data, &pContext->macSessionKey->len);
        }
    	pContext->status = AM_SPNEGO_SUCCESS;	
      	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;		 
    }
    tag = cmAsn1ParseTag(&reader, &len);            /* supported mech */
    if (CM_ASN1_CONTEXT + 1 != tag)
    {
        logBadTag(CM_ASN1_CONTEXT + 1, tag);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }
    if (!cmAsn1ParseCompareOid(&reader, pContext->mechanism->oid))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected mechanism in server response");
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return nullBlob;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "mechanism in server response = %s", pContext->mechanism->name);
    
    if (inBlob->data + inBlob->len > cmBufferReaderGetPosition(&reader))
    {
        tag = cmAsn1ParseTag(&reader, &len);            /* response token */
        if (CM_ASN1_CONTEXT + 2 != tag)
        {
            logBadTag(CM_ASN1_CONTEXT + 2, tag);
        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return nullBlob;
        }
        tag = cmAsn1ParseTag(&reader, &len);            /* response token */
        if (CM_ASN1_BINARY != tag)
        {
            logBadTag(CM_ASN1_BINARY, tag);
        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return nullBlob;
        }

        mechBlob.data = cmBufferReaderGetPosition(&reader);
        mechBlob.len = len;
        if (!pContext->mechanism->generateNextRequest(
                pContext->extendedContext, 
                mechBlob.data,
                mechBlob.len,
                &mechBlob.data,
                &mechBlob.len, 
                (NQ_BYTE*)pContext
                )
           )
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate next blob");
        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return nullBlob;
        }
        
        newBlob.len = 30 + mechBlob.len;
        newBlob.data = cmMemoryAllocate(newBlob.len);
        if (newBlob.data == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR,  "Out of memory");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return nullBlob;
        }
        mechtokenLen = 1 + cmAsn1PackLen(mechBlob.len) + mechBlob.len;
        negtokenLen = 1 + cmAsn1PackLen(mechtokenLen) + mechtokenLen;
        gssapiLen = 1 +  cmAsn1PackLen(negtokenLen) + negtokenLen;
        if (newBlob.len < 1 + cmAsn1PackLen(gssapiLen) + gssapiLen)
        {
            LOGERR(CM_TRC_LEVEL_ERROR,  "Generated blob too big");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return nullBlob;
        }
        newBlob.len = 1 + cmAsn1PackLen(gssapiLen) + gssapiLen;

        /* pack fields */
        cmBufferWriterInit(&writer, newBlob.data, newBlob.len);
        cmAsn1PackTag(&writer, CM_ASN1_CONTEXT + 1, gssapiLen);
        cmAsn1PackTag(&writer, CM_ASN1_SEQUENCE, negtokenLen);
        cmAsn1PackTag(&writer, CM_ASN1_CONTEXT + 2, mechtokenLen);
        cmAsn1PackTag(&writer, CM_ASN1_BINARY, mechBlob.len);
        cmBufferWriteBytes(&writer, mechBlob.data, mechBlob.len);
    }
    pContext->status = AM_SPNEGO_CONTINUE;
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return newBlob;
}

/* Description
   This function checks results of the next security exchange.
   Parameters
   context :  Pointer to SPNEGO context.
   Returns
   One of the constants defined in this module.                */
static NQ_STATUS checkStatus(void * context)
{
	Context * pContext = (Context*)context;	/* casted pointer */
	
	return pContext->status;
}

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

#if defined(UD_NQ_INCLUDECIFSCLIENT)

void amSpnegoDefineLevel(NQ_UINT level, NQ_UINT crypter1, NQ_UINT crypter2, NQ_UINT32 mehanisms)
{
	if (level > AM_MAXSECURITYLEVEL + 1) 
		return;
	levels[level].crypter1 = crypter1;
	levels[level].crypter2 = crypter2;
	levels[level].mask = mehanisms;
}

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)

NQ_STATUS amSpnegoClientLogon(
    void * callingContext,                            
    const NQ_WCHAR * serverName,
    const AMCredentialsW * credentials, 
    NQ_BOOL restrictCrypters, 
    const CMBlob * firstSecurityBlob, 
    CMBlob * sessionKey, 
    CMBlob * macKey, 
    AMSpnegoClientExchange exchange
    )
{
	NQ_STATUS status;	            /* SPNEGO status */
    CMBlob outBlob = {NULL, 0};	    /* SPNEGO outgoing blob */
    CMBlob inBlob = {NULL, 0};      /* SPNEGO incoming blob */
	NQ_INT level;		            /* security level */
    void * securityContext = NULL;  /* security context */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	for (level = AM_MAXSECURITYLEVEL; level >= 0; level--)
	{
		if (NULL != securityContext)	
		{
			freeContext(securityContext);
            securityContext = NULL;
            if (sessionKey != NULL)
                cmMemoryFreeBlob(sessionKey);
            if (macKey != NULL)
                cmMemoryFreeBlob(macKey);
		}
		securityContext = allocateContext(credentials, (NQ_UINT)level);
		/* start SPNEGO */
		if (!clientNegotiateSecurity(
				securityContext, 
				firstSecurityBlob, 
				restrictCrypters, 
				serverName, 
				sessionKey, 
				macKey
				)
			)
		{
			freeContext(securityContext);
            securityContext = NULL;
			amSpnegoFreeKey(sessionKey);
			continue;
		}
	
		/* cycle up with Session setup(s) */
		inBlob.data = NULL;
		for(;;)
		{
            status = checkStatus(securityContext);
			switch (status)
			{
			case AM_SPNEGO_NONE:
				outBlob = clientGenerateFirstBlob(securityContext);
				break;
			case AM_SPNEGO_CONTINUE:
				outBlob = clientAcceptNextBlob(securityContext, &inBlob);
				break;
			case AM_SPNEGO_DENIED:
				cmMemoryFreeBlob(&inBlob);
				break;
			case AM_SPNEGO_FAILED:
				cmMemoryFreeBlob(&inBlob);
				break;
			case AM_SPNEGO_SUCCESS:
				cmMemoryFreeBlob(&inBlob);
				freeContext(securityContext);
				LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
				return AM_SPNEGO_SUCCESS;
			}
			cmMemoryFreeBlob(&inBlob);	/* may be NULL here for the 1st blob */
			if (NULL == outBlob.data)
			{
				if (AM_SPNEGO_SUCCESS == checkStatus(securityContext))
				{
				    freeContext(securityContext);
					LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
					return AM_SPNEGO_SUCCESS;
				}
				sySetLastError(NQ_ERR_BADPARAM);
				break;
			}
			status = (*exchange)(callingContext, &outBlob, &inBlob);
			cmMemoryFreeBlob(&outBlob);
			if (NQ_SUCCESS != status)
			{
				if (status == NQ_ERR_TIMEOUT)
				{
					cmMemoryFreeBlob(&inBlob);
					freeContext(securityContext);
					securityContext = NULL;
		            if (sessionKey != NULL)
		                cmMemoryFreeBlob(sessionKey);
		            if (macKey != NULL)
		                cmMemoryFreeBlob(macKey);
					LOGERR(CM_TRC_LEVEL_ERROR , " Session Setup failed with timeout");
				    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
					return AM_SPNEGO_FAILED;
					
				}
				cmMemoryFreeBlob(&inBlob);
				break;
			}
		}
	}
	freeContext(securityContext);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return AM_SPNEGO_FAILED;
}

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

#ifdef UD_NQ_INCLUDECIFSCLIENT

NQ_STATUS amSpnegoGeneratePasswordBlobs(const AMCredentialsW * credentials, NQ_INT level, CMBlob *pass1, CMBlob * pass2, CMBlob * sessionKey, CMBlob * macSessionKey)
{
    AMCrypt crypt;			/* encrypted passwords and keys */
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (levels[level].crypter1 == AM_CRYPTER_NONE || levels[level].crypter2 == AM_CRYPTER_NONE)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_SPNEGO_FAILED;
    }

	/* get blobs */
    if (!amCryptEncrypt(
    		credentials, 
    		levels[level].crypter1,
    		levels[level].crypter2,
    		sessionKey->data, 
    		NULL,	/* no names */ 
    		&crypt
    		)
    	)
    {
     	LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return AM_SPNEGO_FAILED;
    }
    *pass1 = cmMemoryCloneBlob(&crypt.pass1);
    *pass2 = cmMemoryCloneBlob(&crypt.pass2);
    
    if (NULL != crypt.macKey.data && NULL != macSessionKey)
    {
        amSpnegoFreeKey(macSessionKey);
    	*macSessionKey = cmMemoryCloneBlob(&crypt.macKey);
    }
    if (NULL != crypt.response.data && NULL != sessionKey)
    {
        amSpnegoFreeKey(sessionKey);
        *sessionKey = cmMemoryCloneBlob(&crypt.response);
    }

    LOGMSG(CM_TRC_LEVEL_MESS_SOME, "LMv2 response length = %d", crypt.pass1.len);
    LOGMSG(CM_TRC_LEVEL_MESS_SOME, "NTLMv2 response length = %d", crypt.pass2.len);
    
    amCryptDispose(&crypt);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return AM_SPNEGO_SUCCESS;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */

void amSpnegoFreeKey(CMBlob * key)
{
	if (NULL != key->data)
		cmMemoryFree(key->data);
    key->data = NULL;
}
