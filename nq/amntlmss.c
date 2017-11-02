/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : NTLMSSP authentication machine (server and client)
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 11-Feb-2007
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"  
#include "amntlmss.h"
#include "amspnego.h"
#include "amcrypt.h"
#include "cmcrypt.h"

/*
 * NTLMSPP protocol definitions 
 * 
 */

#define MECHANISM_NAME  "NTLMSSP"

/* message types */
#define NTLMSSP_NEGOTIATE 1
#define NTLMSSP_CHALLENGE 2
#define NTLMSSP_AUTH      3
#define NTLMSSP_SIGNATURE 4

/* NTLMSSP flags: */
#define NTLMSSP_NEGOTIATE_UNICODE               0x00000001
#define NTLMSSP_NEGOTIATE_REQUEST_TARGET        0x00000004
#define NTLMSSP_NEGOTIATE_SIGN                  0x00000010 
#define NTLMSSP_NEGOTIATE_NTLM                  0x00000200 /* NTLM authentication is supported */
#define NTLMSSP_NEGOTIATE_NTLM2                 0x00080000 /* NTLM2 session key */
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


#define NTLMSSP_SERVER_NEGOTIATE_FLAGS     (  NTLMSSP_NEGOTIATE_UNICODE \
                                            | NTLMSSP_NEGOTIATE_NTLM \
                                            | NTLMSSP_NEGOTIATE_TARGET_INFO \
                                            | NTLMSSP_NEGOTIATE_TARGET_TYPE_DOMAIN \
                                            | NTLMSSP_NEGOTIATE_128 \
                                            | NTLMSSP_NEGOTIATE_56 \
                                            | NTLMSSP_NEGOTIATE_SIGN \
                                            | NTLMSSP_NEGOTIATE_SEAL \
                                            | NTLMSSP_NEGOTIATE_KEY_EXCH \
                                            | NTLMSSP_NEGOTIATE_NTLM2 \
                                           )
#define NTLMSSP_CLIENT_NEGOTIATE_FLAGS     ( NTLMSSP_NEGOTIATE_128 \
                                            | NTLMSSP_NEGOTIATE_NTLM \
                                            | NTLMSSP_NEGOTIATE_NTLM2 \
                                            | NTLMSSP_NEGOTIATE_SIGN \
                                            | NTLMSSP_NEGOTIATE_REQUEST_TARGET \
                                            | NTLMSSP_NEGOTIATE_UNICODE \
                                           )     
/* address list items */
#define ITEMTYPE_TERMINATOR     0
#define ITEMTYPE_NETBIOSHOST    1
#define ITEMTYPE_NETBIOSDOMAIN  2
#define ITEMTYPE_DNSHOST        3
#define ITEMTYPE_DNSDOMAIN      4

/*
 * static data and definitions
 */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)

typedef struct
{
    NQ_BYTE data[CM_CRYPT_MAX_NTLMV2NTLMSSPRESPONSESIZE];
} NtlmsspClientContext; /* NTLMSSP-specific client-side context */

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */

#if (defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)) || (defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY))

/* place a block of referenced data */
static void
packRefData(
    CMRpcPacketDescriptor * out,    /* outgoing packet descriptor */     
    NQ_BYTE * pBase,                /* base for calculating offsets */
    NQ_BYTE * pRef,                 /* pointer to the reference */
    NQ_BYTE * pStart,               /* pointer to the start of the block */ 
    NQ_BYTE * pEnd                  /* pointer to the end of the block */
    ); 

#endif /* (defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)) || (defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)) */

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)

/* process incoming blob and compose response blob */ 
static NQ_UINT32                    /* error code or zero */
ntlmsspProcessor(
    CMRpcPacketDescriptor * in,     /* incoming blob descriptor */ 
    CMRpcPacketDescriptor * out,    /* outgoing blob descriptor */
    AMNtlmDescriptor * descr,       /* passwords descriptor */
    NQ_WCHAR * userName,            /* buffer for user name */
    const NQ_WCHAR ** pDomain,      /* buffer for domain name pointer */
    const NQ_BYTE ** pSessionKey    /* buffer for session key pointer or NULL if none */                     
    );
 
/* process incoming NTLMSSP NEGOTIATE */ 
static NQ_UINT32                    /* error code or zero */
ntlmsspNegotiate(
    const NQ_BYTE * inBase,         /* base address for calculating offsets */
    CMRpcPacketDescriptor * in,     /* incoming blob descriptor */ 
    CMRpcPacketDescriptor * out     /* outgoing blob descriptor */
    );
 
/* process incoming NTLMSSP AUTH */ 
static NQ_UINT32                    /* error code or zero */
ntlmsspAuth(
    const NQ_BYTE * inBase,         /* base address for calculating offsets */
    CMRpcPacketDescriptor * in,     /* incoming blob descriptor */ 
    CMRpcPacketDescriptor * out,    /* outgoing blob descriptor */
    AMNtlmDescriptor * descr,       /* passwords descriptor */
    NQ_WCHAR * userName,            /* buffer for user name */
    const NQ_WCHAR ** pDomain,      /* buffer for domain name pointer */
    const NQ_BYTE** pSessionKey     /* buffer for session key pointer or NULL if none */                     
    );
    
 
/* place an address list item */
static void
packAddressListItem( 
    CMRpcPacketDescriptor * out,    /* outgoing packet descriptor */
    NQ_UINT16 type,                 /* item type */     
    const NQ_CHAR * name            /* item name */
    ); 
 
static AMSpnegoServerMechDescriptor mechDescriptor = 
{
    &cmGssApiOidNtlmSsp,
    ntlmsspProcessor
};

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) */

#if (defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)) || (defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY))

/*
 *====================================================================
 * PURPOSE: place a block of referenced data 
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN  base for calculating offsets
 *          OUT pointer to the reference
 *          IN  pointer to the start of the block
 *          IN  OUT pointer to the end of the block
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
packRefData(
    CMRpcPacketDescriptor* out,     
    NQ_BYTE* pBase,                 
    NQ_BYTE* pRef,                  
    NQ_BYTE* pStart,                 
    NQ_BYTE* pEnd                   
    )
{
    NQ_UINT16 len = (NQ_UINT16)(pEnd - pStart);      /* block length */
    NQ_BYTE* savedCurrent;              /* saved pointer in the packet */
    
    savedCurrent = out->current;
    out->current = pRef;
    cmRpcPackUint16(out, len);
    cmRpcPackUint16(out, len);
    cmRpcPackUint32(out, (NQ_UINT32)(pStart - pBase));
    out->current = savedCurrent;   
}

#endif /* (defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)) || (defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)) */

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)

/*
 *====================================================================
 * PURPOSE: get this mechanism descriptor
 *--------------------------------------------------------------------
 * PARAMS:  none
 *
 * RETURNS: mechnism descriptor
 *
 * NOTES:
 *====================================================================
 */

const AMSpnegoServerMechDescriptor*        
amNtlmsspGetServerDescriptor(
    void
    )
{
    return &mechDescriptor;
}


/*
 *====================================================================
 * PURPOSE: process incoming blob and compose response blob 
 *--------------------------------------------------------------------
 * PARAMS:  IN  incoming blob descriptor
 *          OUT outgoing blob descriptor
 *          OUT encrypted passwords descriptor
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for session key pointer or NULL if none 
 *
 * RETURNS: status, icluding:
 *      AM_STATUS_NOT_AUTHENTICATED          - was parsed but not autheticated yet
 *      AM_STATUS_MORE_PROCESSING_REQUIRED - was recognized but requires more exchange
 *      <any other>                         - parse error
 *
 * NOTES:
 *      this function never retruns zero
 *====================================================================
 */

static NQ_UINT32                    
ntlmsspProcessor(
    CMRpcPacketDescriptor * in,       
    CMRpcPacketDescriptor * out,     
    AMNtlmDescriptor * descr, 
    NQ_WCHAR * userName,             
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE** pSessionKey                 
    )
{
    NQ_UINT32 msgType;          /* NTLM message type */
    const NQ_BYTE* base;        /* base address for calculating offsets */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    base = in->current;
    /* parse request */
    if (0 != syStrncmp((const NQ_CHAR*)in->current, MECHANISM_NAME, syStrlen(MECHANISM_NAME)))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected mechanism name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " expected: %s was: %s", MECHANISM_NAME, in->current);
        TRCDUMP("name", in->current, (NQ_UINT)syStrlen(MECHANISM_NAME));
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    in->current += syStrlen(MECHANISM_NAME) + 1;
    cmRpcParseUint32(in, &msgType);
    switch(msgType)
    {
    case NTLMSSP_NEGOTIATE:
        msgType = ntlmsspNegotiate(base, in, out);        
        break;
    case NTLMSSP_AUTH:
        msgType = ntlmsspAuth(base, in, out, descr, userName, pDomain, pSessionKey);        
        break;
    default:
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected message type:");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " 0x%x", msgType);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_BAD_FORMAT;
    }
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return msgType;
}

/*
 *====================================================================
 * PURPOSE: process incoming NTLMSSP NEGOTIATE 
 *--------------------------------------------------------------------
 * PARAMS:  IN  base address for calculating offsets 
 *          IN  incoming blob descriptor
 *          OUT outgoing blob descriptor
 *
 * RETURNS: status, including:
 *      AM_STATUS_MORE_PROCESSING_REQUIRED - was recognized but requires more exchange
 *      <any other>                        - parse error
 *
 * NOTES:
 *      this function never returns zero
 *====================================================================
 */

static NQ_UINT32                    
ntlmsspNegotiate(
    const NQ_BYTE* inBase,
    CMRpcPacketDescriptor* in,       
    CMRpcPacketDescriptor* out     
    )
{
    NQ_UINT32 flags;        /* request flags */
    NQ_BYTE* pDomain;       /* pointer to the domain name */
    NQ_BYTE* pList;         /* pointer to address list block */
    NQ_BYTE* pRefDomain;    /* pointer to the domain descriptor place */
    NQ_BYTE* pRefList;      /* pointer to address list descriptor place */
    CSSession* session;     /* session structure */
    NQ_BYTE* base;          /* base address for calculating offsets */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    session = csGetSessionBySocket();    
    if (session == NULL)       /* malformed command or there was no Negotiate yet */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown session by socket");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return AM_STATUS_GENERIC;
    }
    
    /* parse request */
    cmRpcParseUint32(in, &flags);
    
    /* generate NTLMSSP */
    base = out->current;
    cmRpcPackBytes(out, (const NQ_BYTE*)MECHANISM_NAME, sizeof(MECHANISM_NAME));
    cmRpcPackUint32(out, NTLMSSP_CHALLENGE);    /* message type */
    pRefDomain = out->current;
    cmRpcPackSkip(out, 2 + 2 + 4);  /* domain */ 
    cmRpcPackUint32(out, NTLMSSP_SERVER_NEGOTIATE_FLAGS);  /* flags */
    cmRpcPackBytes(out, session->encryptionKey, sizeof(session->encryptionKey));    /* challenge */
    TRCDUMP("server challenge (encryption key)", session->encryptionKey, 8);
    cmRpcPackUint32(out, 0);    /* reserved */ 
    cmRpcPackUint32(out, 0);    /* reserved */
    pRefList = out->current;
    cmRpcPackSkip(out, 2 + 2 + 4);  /* address list */
    
    /* generate referenced data for the 1st NTLMSSP */ 
    /* 1) domain */
    pDomain = out->current;
    cmRpcPackAsciiAsUnicode(out, cmNetBiosGetDomainAuth()->name, 0);
    packRefData(out, base, pRefDomain, pDomain, out->current);
    
    /* 2) Address list */
    pList = out->current;
    packAddressListItem(out, ITEMTYPE_NETBIOSDOMAIN, cmNetBiosGetDomainAuth()->name);
    packAddressListItem(out, ITEMTYPE_NETBIOSHOST, cmNetBiosGetHostNameZeroed());
    packAddressListItem(out, ITEMTYPE_DNSDOMAIN, cmGetFullDomainName());
    packAddressListItem(out, ITEMTYPE_DNSHOST, cmNetBiosGetHostNameZeroed());
    packAddressListItem(out, ITEMTYPE_TERMINATOR, NULL);
    packRefData(out, base, pRefList, pList, out->current);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return AM_STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 *====================================================================
 * PURPOSE: process incoming NTLMSSP AUTH 
 *--------------------------------------------------------------------
 * PARAMS:  IN  base address for calculating offsets 
 *          IN  incoming blob descriptor
 *          OUT outgoing blob descriptor
 *          OUT encrypted passwords descriptor
 *          OUT buffer for user name
 *          OUT buffer for domain name pointer
 *          OUT buffer for session key pointer or NULL if none 
 *
 * RETURNS: status, including:
 *      AM_STATUS_NOT_AUTHENTICATED        - was parsed but not authenticated yet
 *      AM_STATUS_MORE_PROCESSING_REQUIRED - was recognized but requires more exchange
 *      <any other>                        - parse error
 *
 * NOTES:
 *      this function never returns zero
 *====================================================================
 */

static NQ_UINT32                    
ntlmsspAuth(
    const NQ_BYTE * inBase,
    CMRpcPacketDescriptor * in,       
    CMRpcPacketDescriptor * out,     
    AMNtlmDescriptor * descr, 
    NQ_WCHAR * userName,             
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE ** pSessionKey                 
    )
{
    NQ_UINT32 offset;           /* offset from the base */
    NQ_UINT16 len;              /* block length */
    NQ_UINT32 flags;            /* NTLMSSP flags */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    /* parse LM */
    cmRpcParseUint16(in, &len);
    cmRpcParseSkip(in, 2);   /* maxlen */
    cmRpcParseUint32(in, &offset);
    descr->pLm = inBase + offset;
    descr->lmLen = len;
    
    /* parse NTLM */ 
    cmRpcParseUint16(in, &len);
    cmRpcParseSkip(in, 2);   /* maxlen */
    cmRpcParseUint32(in, &offset);
    descr->pNtlm = inBase + offset;
    descr->ntlmLen = len;
    
    /* parse domain */
    cmRpcParseUint16(in, &len);
    cmRpcParseSkip(in, 2);   /* maxlen */
    cmRpcParseUint32(in, &offset);
    *pDomain = cmMemoryAllocate((NQ_UINT)(len + sizeof(NQ_WCHAR)));
    if (NULL != *pDomain)
    {    
        syMemcpy(*pDomain, inBase + offset, len);
        ((NQ_WCHAR *)(*pDomain))[len/sizeof(NQ_WCHAR)] = 0;
    }

    /* parse user name */
    cmRpcParseUint16(in, &len);
    cmRpcParseSkip(in, 2);   /* maxlen */
    cmRpcParseUint32(in, &offset);
    syMemcpy((NQ_BYTE *)userName, inBase + offset, len);
    userName[len/sizeof(NQ_WCHAR)] = 0;
    len /= sizeof(NQ_WCHAR);
    
    /* parse host name*/
    cmRpcParseSkip(in, 2 * 2 + 4);   /* len, maxlen, offset, flags */
    
    /* parse session key */
    cmRpcParseUint16(in, &len);
    cmRpcParseSkip(in, 2);   /* maxlen */
    cmRpcParseUint32(in, &offset);
    if (len > 0)
    {
        *pSessionKey = inBase + offset;
    }   

    /* parse flags */
    cmRpcParseUint32(in, &flags);
    descr->flags = flags;

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Client set flag: %s",flags & NTLMSSP_NEGOTIATE_KEY_EXCH ? "NTLMSSP_NEGOTIATE_KEY_EXCH" : "not NTLMSSP_NEGOTIATE_KEY_EXCH");
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Client set flag: %s",flags & NTLMSSP_NEGOTIATE_NTLM ? "NTLMSSP_NEGOTIATE_NTLM (NTLM auth.)" : "not NTLMSSP_NEGOTIATE_NTLM (NTLM auth.)");
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Client set flag: %s",flags & NTLMSSP_NEGOTIATE_NTLM2 ? "NTLMSSP_NEGOTIATE_NTLM2 (NTLM2 session key)" : "not NTLMSSP_NEGOTIATE_NTLM2 (NTLM2 session key)");
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Client set flag: %s",flags & NTLMSSP_NEGOTIATE_LAN_MANAGER ? "NTLMSSP_NEGOTIATE_LAN_MANAGER (LM session key)" : "not NTLMSSP_NEGOTIATE_LAN_MANAGER (LM session key)");
    
    /* If the effective response is NTLM we need to generate new encryption key from
     * the old one + 8 bytes of LM response all transferred through MD5.
     * This should not be done for NTLMv2 response. v2 response is encountered by the
     * NTLM response length (>24) and not only by flags (an MS bug or feature?). 
     * LM&NTLM without NTLMSSP_NEGOTIATE_NTLM2 - meaning usual LM&NTLM.
     */
 
    if (0 != (flags & NTLMSSP_NEGOTIATE_NTLM2) && descr->lmLen == 24 && descr->ntlmLen == 24) 
    {
        NQ_BYTE buffer[16];     /* for MD5 */
        CSSession* session;     /* session structure */
    
        session = csGetSessionBySocket();    
        if (session == NULL)       /* mulformed command or there was no Negotiate yet */
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unknown session by socket");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return AM_STATUS_GENERIC;
        }
#if defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY)
        syMemcpy(session->sessionNonce, session->encryptionKey, sizeof(session->encryptionKey));
        syMemcpy(&session->sessionNonce[8], descr->pLm, 8);
#endif /* defined(UD_CS_INCLUDELOCALUSERMANAGEMENT) || defined(UD_CS_MESSAGESIGNINGPOLICY) */       
        syMemcpy(buffer, session->encryptionKey, sizeof(session->encryptionKey));
        syMemcpy(buffer + sizeof(session->encryptionKey), descr->pLm, sizeof(session->encryptionKey));
        cmMD5(buffer, buffer, 16);
        syMemcpy(session->encryptionKey, buffer, sizeof(session->encryptionKey));
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Generated new encryption key");
    }

#if 0 
    /* todo: meanwhile seen in SMB2 WINDOWS captures only (NTLMSSP embedded in SPNEGO) */
    /* WINDOWS against NQ and SAMBA doesn't expect this message type */
    /* this is NTLMSSP_MESSAGE_SIGNATURE, see 2.2.1.4 */
    NQ_BYTE checksum[8];
    
    cmRpcPackUint32(out, 0x00000001);  /* version, always 0x00000001 */
    syMemset(checksum, 0, 8); 
    cmRpcPackBytes(out, checksum, 8);  /* checksum, should be properly calculated */
    cmRpcPackUint32(out, 0);           /* sequence, here always zero */
#endif    
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return AM_STATUS_NOT_AUTHENTICATED;
}

 
/*
 *====================================================================
 * PURPOSE: place an address list item 
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN  item type
 *          IN  item name
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
packAddressListItem( 
    CMRpcPacketDescriptor* out,
    NQ_UINT16 type,                 
    const NQ_CHAR* name              
    )
{ 
    cmRpcPackUint16(out, type);
    if (NULL != name)
    {
        cmRpcPackUint16(out, (NQ_UINT16)(sizeof(NQ_WCHAR)* syStrlen(name)));
        cmRpcPackAsciiAsUnicode(out, name, 0);
    }
    else
    {
        cmRpcPackUint16(out, 0);
    }
}



/*
 *====================================================================
 * PURPOSE: find NTLM challenge in blob 
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to blob
 *
 * RETURNS: pointer to the start of NTLM challenge
 *
 * NOTES:   blob can be wrapped in gss api or raw
 *====================================================================
 */

NQ_BYTE*
amNtlmsspServerGetChallenge(
    NQ_BYTE* pBlob
    )
{
    CMRpcPacketDescriptor ds;   /* packet descriptor */
    CMAsn1Len len;              /* length of the current field */
    CMAsn1Tag tag;              /* next tag */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    cmRpcSetDescriptor(&ds, pBlob, FALSE);

    tag = cmAsn1ParseTag(&ds, &len);           
    if (CM_ASN1_CONTEXT + 1 == tag)                 /* GSSAPI/SPNEGO */
    {
        tag = cmAsn1ParseTag(&ds, &len);            /* negTokenTag */
        if (CM_ASN1_SEQUENCE != tag)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tag in server response");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Expected %d, seen %d", CM_ASN1_SEQUENCE, tag);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        tag = cmAsn1ParseTag(&ds, &len);            /* negResult */
        if (CM_ASN1_CONTEXT != tag)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tag in server response");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Expected %d, seen %d", CM_ASN1_CONTEXT, tag);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        tag = cmAsn1ParseTag(&ds, &len);            /* negResult */
        if (CM_ASN1_ENUMERATED != tag || len != 1)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tag or length in server response");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Expected %d, seen %d, length: %d", CM_ASN1_ENUMERATED, tag, len);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        cmRpcParseSkip(&ds, 1);
        tag = cmAsn1ParseTag(&ds, &len);            /* supported mech */
        if (CM_ASN1_CONTEXT + 1 != tag)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tag in server response");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Expected %d, seen %d", CM_ASN1_CONTEXT + 1, tag);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        if (!cmAsn1ParseCompareOid(&ds, &cmGssApiOidNtlmSsp))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected mechanism in server response");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        tag = cmAsn1ParseTag(&ds, &len);            /* response token */
        if (CM_ASN1_CONTEXT + 2 != tag)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tag in server response");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Expected %d, seen %d", CM_ASN1_CONTEXT + 2, tag);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        tag = cmAsn1ParseTag(&ds, &len);            /* response token */
        if (CM_ASN1_BINARY != tag)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tag in server response");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Expected %d, seen %d", CM_ASN1_BINARY, tag);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }     
    }
    else
    {
        /* raw blob */
        cmRpcResetDescriptor(&ds);
    }
    
    cmRpcParseSkip(&ds, 24);  /* 8bytes(NTLM ident.) + 4bytes(mess. type) + 8bytes(domain) + 4bytes(flags) */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);   
    return ds.current;
}
#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) */


#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY)

/* -- Client-side functions -- */

NQ_BOOL amNtlmsspClientInit(void * p)
{
    return TRUE;
}

NQ_BOOL amNtlmsspClientStop(void)
{
    return TRUE;
}

NQ_BYTE* amNtlmsspClientContextCreate(const NQ_CHAR * name, NQ_BOOL restrictCrypt)
{
    return cmMemoryAllocate(sizeof(NtlmsspClientContext));
}

NQ_BOOL amNtlmsspClientSetMechanism(NQ_BYTE * ctx, const NQ_CHAR* name)
{
    return TRUE;
}

NQ_BOOL amNtlmsspClientGetSessionKey(NQ_BYTE * p, NQ_BYTE* buffer, NQ_COUNT* len)
{
    return TRUE;
}

NQ_BOOL amNtlmsspClientContextIsValid(NQ_BYTE * p)
{
    return p != NULL;
}

NQ_BOOL amNtlmsspClientContextDispose(NQ_BYTE * ctx)
{
    cmMemoryFree(ctx);
    return TRUE;
}

void amNtlmsspClientContextInvalidate(NQ_BYTE * ctx)
{
    ctx = NULL;
}

NQ_BOOL amNtlmsspClientGenerateFirstRequest(NQ_BYTE * ctxt, const NQ_CHAR* mechList, NQ_BYTE ** blob, NQ_COUNT * blobLen)
{    
    NtlmsspClientContext * context = (NtlmsspClientContext *)ctxt;
    CMBufferWriter out;		/* outgoing blob writer */
    NQ_BYTE * base;
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmBufferWriterInit(&out, context->data, sizeof(context->data));
    base = cmBufferWriterGetPosition(&out);
    cmBufferWriteBytes(&out, (const NQ_BYTE *)MECHANISM_NAME, sizeof(MECHANISM_NAME));
    cmBufferWriteUint32(&out, NTLMSSP_NEGOTIATE);     
    cmBufferWriteUint32(&out, NTLMSSP_CLIENT_NEGOTIATE_FLAGS);        
    cmBufferWriteUint32(&out, 0); /* null workstation domain */
    cmBufferWriteUint32(&out, 0);
    cmBufferWriteUint32(&out, 0); /* null workstation name   */
    cmBufferWriteUint32(&out, 0);
    
    *blobLen = (NQ_COUNT)(cmBufferWriterGetPosition(&out) - base);
    *blob = context->data;

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}


NQ_BOOL amNtlmsspClientGenerateNextRequest(
    NQ_BYTE * ctxt,
    const NQ_BYTE * inBlob,
    NQ_COUNT inBlobLen,
    NQ_BYTE ** outBlob,
    NQ_COUNT * outBlobLen, 
    NQ_BYTE * spnegoContext
    )
{
    NQ_BYTE *p, *base, *pRefDomain, *pRefUser, *pRefHost, *pRefLM, *pRefNTLM, *pRefSession;
    CMBufferReader in;		                /* incoming blob parser */
    CMBufferWriter out;		                /* outgoing blob writer */
    NQ_BYTE ntlmChallenge[8];	            /* challenge sent by server */
    NQ_UINT16 targetInfoLength;	            /* target info length in server response */ 	
    NQ_UINT32 targetInfoOffset;	            /* target info offset in server response */
    CMBlob namesBlob;		                /* names from the server challenge */
    AMCrypt crypt;			                /* encrypted passwords and keys */
    NQ_WCHAR * hostName;	                /* client host name */
    NQ_BOOL userIsAnonymous = FALSE;        /* will be TRUE for Anonymous */
    CMBlob * pSessionKey;                   /* pointer to caller's session key blob */
    CMBlob * pMacSessionKey;                /* pointer to caller's MAC key blob */
    const AMCredentialsW * pCredentials;    /* pointer to caller's credentials */
    static const NQ_BYTE zero1[] = {0};     /* to write zero LM */
    NtlmsspClientContext * ntlmContext = (NtlmsspClientContext *)ctxt;	/* pe-mech context */
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* extract server ntlm challenge */ 
	cmBufferReaderInit(&in, (NQ_BYTE*)inBlob, inBlobLen);
	base = cmBufferReaderGetPosition(&in);
	cmBufferReaderSkip(&in, 24);
	cmBufferReadBytes(&in, ntlmChallenge, sizeof(ntlmChallenge));
    pSessionKey = amSpnegoClientGetSessionKey(spnegoContext);
	if (NULL != pSessionKey)
	{
	    amSpnegoFreeKey(pSessionKey);
		pSessionKey->data = cmMemoryAllocate(sizeof(ntlmChallenge));
		if (NULL == pSessionKey->data)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
			LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			return FALSE;
		}
		syMemcpy(pSessionKey->data, ntlmChallenge, sizeof(ntlmChallenge));
		pSessionKey->len =  sizeof(ntlmChallenge);
	}
	cmBufferReaderSkip(&in, 8);
	cmBufferReadUint16(&in, &targetInfoLength);
	cmBufferReaderSkip(&in, 2);
	cmBufferReadUint32(&in, &targetInfoOffset);
	if (targetInfoLength > 0)
	{          
		namesBlob.data = base + targetInfoOffset;
		namesBlob.len = targetInfoLength;
	} 
	else
	{
		namesBlob.data = NULL;
	}
    
    pCredentials = amSpnegoClientGetCredentials(spnegoContext);
    userIsAnonymous = cmWStrlen(pCredentials->user) == 0;
    LOGMSG(CM_TRC_LEVEL_MESS_SOME, "level: %d %s", amSpnegoClientGetCryptLevel(spnegoContext), userIsAnonymous ? ", anonymous" : "");
	/* get blobs */
	syMemset(&crypt, 0, sizeof(crypt));
    if (!userIsAnonymous && !amCryptEncrypt(
    		pCredentials, 
    		amSpnegoClientGetCrypter1(spnegoContext),
    		amSpnegoClientGetCrypter2(spnegoContext),
    		pSessionKey->data, 
    		&namesBlob, 
    		&crypt
    		)
    	)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }

    /* the next section (used only when using LM & NTLMv1 && NTLMSSP will encode a new NTLM password and a after that a new mac key to use for signing*/
    if (!userIsAnonymous && amSpnegoClientGetCrypter1(spnegoContext) == AM_CRYPTER_LM && amSpnegoClientGetCrypter2(spnegoContext) == AM_CRYPTER_NTLM )
    {
        NQ_BYTE keyBuf[16];
        AMCrypt oldCrypt;
        CMBlob  newMac;
        
        newMac = cmMemoryCloneBlob(&crypt.macKey);
        oldCrypt.pass1 = cmMemoryCloneBlob(&crypt.pass1);
        
        syMemcpy(keyBuf , pSessionKey->data , pSessionKey->len);
        syMemcpy(keyBuf+pSessionKey->len , crypt.pass1.data , pSessionKey->len);
        
        syMemcpy(newMac.data , keyBuf , 16);
        newMac.len = 16;

        cmMD5(keyBuf , keyBuf, 16);
        syMemcpy(pSessionKey->data , keyBuf , pSessionKey->len);
        
        amCryptDispose(&crypt);
        amCryptEncrypt(
        	pCredentials, 
        	amSpnegoClientGetCrypter1(spnegoContext),
        	amSpnegoClientGetCrypter2(spnegoContext),
        	pSessionKey->data, 
        	&namesBlob, 
        	&crypt
        	);
        
        cmMemoryFreeBlob(&crypt.pass1);
        crypt.pass1 = cmMemoryCloneBlob(&oldCrypt.pass1);

        cmGenerateNTLMv2SessionKey(crypt.macKey.data, newMac.data, crypt.macKey.data);
        
        cmMemoryFreeBlob(&oldCrypt.pass1);
        cmMemoryFreeBlob(&newMac);
    }
    /* return MacSessionKey only if not available yet through previous logins within same connection */
    if (!userIsAnonymous)
    {
        pMacSessionKey = amSpnegoClientGetMacSessionKey(spnegoContext);
        if (NULL != pMacSessionKey && NULL == pMacSessionKey->data && NULL != crypt.macKey.data)
        {
        	*pMacSessionKey = cmMemoryCloneBlob(&crypt.macKey);
        	TRCDUMP("mac key", pMacSessionKey->data, pMacSessionKey->len);
        }
    }
    LOGMSG(CM_TRC_LEVEL_MESS_SOME, "LMv2 resp length = %d, NTLMv2 resp length = %d", crypt.pass1.len, crypt.pass2.len);
    
    /* build authenticate message request */
    cmBufferWriterInit(&out, ntlmContext->data, sizeof(ntlmContext->data));
    base = cmBufferWriterGetPosition(&out);
    cmBufferWriteBytes(&out, (const NQ_BYTE *)MECHANISM_NAME, sizeof(MECHANISM_NAME));
    cmBufferWriteUint32(&out, NTLMSSP_AUTH);    
    /* LMv2 response */
    pRefLM = cmBufferWriterGetPosition(&out);
    cmBufferWriterSkip(&out, 2 + 2 + 4);
    /* NTLMv2 response */
    pRefNTLM = cmBufferWriterGetPosition(&out);
    cmBufferWriterSkip(&out, 2 + 2 + 4);
    /* domain */
    pRefDomain = cmBufferWriterGetPosition(&out);
    cmBufferWriterSkip(&out, 2 + 2 + 4);   
    /* user */
    pRefUser = cmBufferWriterGetPosition(&out);
    cmBufferWriterSkip(&out, 2 + 2 + 4);  
    /* host */
    pRefHost = cmBufferWriterGetPosition(&out);
    cmBufferWriterSkip(&out, 2 + 2 + 4); 
    /* session key exchange */
    pRefSession = cmBufferWriterGetPosition(&out);
    cmBufferWriterSkip(&out, 2 + 2 + 4); 
    /* flags */
    cmBufferWriteUint32(&out, userIsAnonymous? 
            NTLMSSP_CLIENT_NEGOTIATE_FLAGS | NTLMSSP_NEGOTIATE_ANONYMOUS : 
            NTLMSSP_CLIENT_NEGOTIATE_FLAGS);
    
    /* pack referenced data */
    p = out.current;

    /* domain */    
    if (cmWStrchr(pCredentials->user, cmWChar('@')) == NULL)
        cmBufferWriteUnicodeNoNull(&out, (const NQ_WCHAR *)pCredentials->domain.name);
    packRefData(&out, base, pRefDomain, p, cmBufferWriterGetPosition(&out));  
    /* username */    
    p = cmBufferWriterGetPosition(&out);
    cmBufferWriteUnicodeNoNull(&out, (const NQ_WCHAR *)pCredentials->user);
    packRefData(&out, base, pRefUser, p, cmBufferWriterGetPosition(&out));
    /* hostname */    
    hostName = cmMemoryCloneAString(cmNetBiosGetHostNameZeroed());
    if (NULL == hostName)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }    	
    p = cmBufferWriterGetPosition(&out);
    cmBufferWriteUnicodeNoNull(&out, hostName);
    packRefData(&out, base, pRefHost, p, cmBufferWriterGetPosition(&out));
    cmMemoryFree(hostName);  
    /* LM */
    p = cmBufferWriterGetPosition(&out);
    if (!userIsAnonymous)
        cmBufferWriteBytes(&out, crypt.pass1.data, crypt.pass1.len);
    else
        cmBufferWriteBytes(&out, zero1, sizeof(zero1));
    packRefData(&out, base, pRefLM, p, cmBufferReaderGetPosition(&out)); 
    /* NTLM */
    p = cmBufferWriterGetPosition(&out);
    if (!userIsAnonymous)
        cmBufferWriteBytes(&out, crypt.pass2.data, crypt.pass2.len);
    packRefData(&out, base, pRefNTLM, p, cmBufferWriterGetPosition(&out));      
    if (!userIsAnonymous)
        amCryptDispose(&crypt); 
    /* session key */    
    p = cmBufferWriterGetPosition(&out);
    packRefData(&out, base, pRefSession, p, cmBufferWriterGetPosition(&out));
    
    *outBlob = ntlmContext->data;
    *outBlobLen = (NQ_COUNT)(cmBufferWriterGetPosition(&out) - base);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_BOOL amNtlmsspClientPackNegotBlob(
    void * context,
    CMBufferWriter * writer,
    NQ_COUNT mechtokenBlobLen,
    NQ_COUNT * blobLen 
    )
{
    NQ_COUNT gssapiLen;         /* tag length */
    NQ_COUNT spnegoLen;         /* tag length */
    NQ_COUNT negtokenLen;       /* tag length */
    NQ_COUNT mechtypesSeqLen;   /* tag length */
    NQ_COUNT mechtokenBinLen;   /* tag length */
    NQ_COUNT mechtokenLen;      /* tag length */ 
    NQ_COUNT oidLen;            /* oid length */
    NQ_COUNT totalLen;          /* total packed blob lenght */

    /* calculate field lengths - backwards */

    mechtokenBinLen = 1 + cmAsn1PackLen(mechtokenBlobLen) + mechtokenBlobLen; 
    mechtokenLen = 1 + cmAsn1PackLen(mechtokenBinLen) + mechtokenBinLen;      
    oidLen = 1 + cmAsn1PackLen(cmGssApiOidNtlmSsp.size) + cmGssApiOidNtlmSsp.size;        
    mechtypesSeqLen = 1 + cmAsn1PackLen(oidLen) + oidLen;      
    negtokenLen = 1 + cmAsn1PackLen(mechtypesSeqLen) + mechtypesSeqLen + mechtokenLen;
    spnegoLen = 1 + cmAsn1PackLen(negtokenLen) + negtokenLen;
    gssapiLen = 1 + cmAsn1PackLen(cmGssApiOidSpnego.size) + cmGssApiOidSpnego.size + 1 + cmAsn1PackLen(sizeof(spnegoLen)) + spnegoLen;
    totalLen = 1 + cmAsn1PackLen(gssapiLen) + gssapiLen;
    if (*blobLen < totalLen)
    {
         LOGERR(CM_TRC_LEVEL_ERROR, "supplied %d, required %d", *blobLen, totalLen);
         *blobLen = (NQ_UINT16)totalLen;
         return FALSE;
    }
    *blobLen = (NQ_UINT16)totalLen;

    cmAsn1PackTag(writer, CM_ASN1_APPLICATION, gssapiLen);
    cmAsn1PackOid(writer, &cmGssApiOidSpnego);
    cmAsn1PackTag(writer, CM_ASN1_CONTEXT, spnegoLen);
    cmAsn1PackTag(writer, CM_ASN1_SEQUENCE, negtokenLen);
    cmAsn1PackTag(writer, CM_ASN1_CONTEXT, mechtypesSeqLen);    
    cmAsn1PackTag(writer, CM_ASN1_SEQUENCE, oidLen);           
    cmAsn1PackOid(writer, &cmGssApiOidNtlmSsp);     
    cmAsn1PackTag(writer, CM_ASN1_CONTEXT + 2, mechtokenBinLen);
    cmAsn1PackTag(writer, CM_ASN1_BINARY, mechtokenBlobLen); 
    return TRUE;
}

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) */
