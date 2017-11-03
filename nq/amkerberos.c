/*********************************************************************
*
*           Copyright (c) 2016 by Visuality Systems, Ltd.
*
*********************************************************************
* FILE NAME     : $Workfile:$
* ID            : $Header:$
* REVISION      : $Revision:$
*--------------------------------------------------------------------
* DESCRIPTION   : Kerberos authentication module (client and server)
*--------------------------------------------------------------------
* DEPENDENCIES  : None
*--------------------------------------------------------------------
* CREATION DATE : 10-Feb-2016
* CREATED BY    : Lilia Wasserman
* LAST AUTHOR   : $Author:$
********************************************************************/

#include "amkerberos.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) && defined(UD_NQ_INCLUDEKERBEROS)

/*
* KERBEROS protocol definitions
*/

#define MECHANISM_NAME  "MS KRB5"

#define SERVICE_NAME    "cifs"

#define KRB5_AP_REQ     0x0001
#define KRB5_AP_REP     0x0002

/*  KRB context */
typedef struct
{
    NQ_BYTE *ctx;           /* underlying SASL Kerberos context */
    const CMAsn1Oid *oid;   /* oid used */
    CMBlob out;             /* outgoing blob if requested */
} KrbContext;


/* process incoming blob and compose response blob */
static NQ_UINT32                    /* error code or zero */
kerberosProcessor(
    CMRpcPacketDescriptor * in,     /* incoming blob descriptor */
    CMRpcPacketDescriptor * out,    /* outgoing blob descriptor */
    AMNtlmDescriptor * descr,       /* passwords descriptor */
    NQ_WCHAR * userName,            /* buffer for user name */
    const NQ_WCHAR ** pDomain,      /* buffer for domain name pointer */
    const NQ_BYTE ** pSessionKey    /* buffer for session key pointer or NULL if none */
)
{
    NQ_UINT32 status = AM_STATUS_GENERIC;
    KrbContext krbContext;
    NQ_COUNT sessionKeyLen = SMB_SESSIONKEY_LENGTH;
    NQ_UINT16 token;
    CMAsn1Tag tag;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "in:%p out:%p descr:%p user:%p domain:%p key:%p", in, out, descr, userName, pDomain, pSessionKey);

    out->length = 0;

    tag = cmAsn1ParseTag(in, &in->length);
    if (CM_ASN1_APPLICATION != tag)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tag");
        goto Exit;
    }

    if (cmAsn1ParseCompareOid(in, amKerberosGetServerDescriptor()->oid, TRUE))
    {
        krbContext.oid = amKerberosGetServerDescriptor()->oid;
    }
    else if (cmAsn1ParseCompareOid(in, amKerberosGetServerDescriptor()->oidSecondary, TRUE))
    {
        krbContext.oid = amKerberosGetServerDescriptor()->oidSecondary;
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not Kerberos OID");
        goto Exit;
    }

    cmBufferReadUint16(in, &token);
    if (token != KRB5_AP_REQ)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected Kerberos token");
        goto Exit;
    }

    krbContext.ctx = sySaslServerContextCreate(SERVICE_NAME);
    if (NULL == krbContext.ctx)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to create context");
        goto Exit;
    }

    *pDomain = cmMemoryAllocate(UD_NQ_HOSTNAMESIZE * sizeof(NQ_WCHAR));
    if (NULL == *pDomain)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Memory failure");
        goto Exit;
    }
    krbContext.out.len = 0;
    if (!sySaslServerAuthenticate(krbContext.ctx, in->current, in->length, userName, (NQ_WCHAR *)*pDomain, &krbContext.out.data, &krbContext.out.len))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to authenticate");
        goto Exit;
    }

    *pSessionKey = cmMemoryAllocate(sessionKeyLen);
    if (NULL == *pSessionKey)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Memory failure");
        goto Exit;
    }

    if (!sySaslGetSessionKey(krbContext.ctx, (NQ_BYTE *)*pSessionKey, &sessionKeyLen))
    {
        cmMemoryFree(*pSessionKey);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to get session key");
        goto Exit;
    }

    /* pack outgoing blob */
    if (krbContext.out.len > 0)
    {
        NQ_COUNT mechToken = krbContext.out.len + 2 + cmAsn1PackLen(krbContext.oid->size) + 1 + krbContext.oid->size;

        cmAsn1PackTag(out, CM_ASN1_APPLICATION, mechToken);
        cmAsn1PackOid(out, krbContext.oid);
        cmRpcPackUint16(out, KRB5_AP_REP);
        cmRpcPackBytes(out, (const NQ_BYTE *)krbContext.out.data, krbContext.out.len);
        out->length = cmBufferWriterGetDataCount(out);
    }

    status = AM_STATUS_NOT_AUTHENTICATED; /* means authentication done */
    descr->isKrbAuthenticated = TRUE;

Exit:
    if (NULL != krbContext.ctx)
        sySaslContextDispose(krbContext.ctx);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", status);
    return status;
}

static AMSpnegoServerMechDescriptor mechKerberosServerDescriptor =
{
    &cmGssApiOidKerberos,
    &cmGssApiOidMsKerberos,
    kerberosProcessor
};

const AMSpnegoServerMechDescriptor * amKerberosGetServerDescriptor()
{
    return &mechKerberosServerDescriptor;
}


NQ_BOOL
amKerberosGetSessionKey(
    NQ_BYTE* context,
    NQ_BYTE* buffer,
    NQ_COUNT* len
)
{
    return sySaslGetSessionKey(context, buffer, len);
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_INCLUDEEXTENDEDSECURITY) && defined(UD_NQ_INCLUDEKERBEROS) */

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) && defined(UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS)

NQ_BOOL amKerberosClientInit(void *p)
{
    return sySaslClientInit(p);
}

NQ_BOOL amKerberosClientStop()
{
    return sySaslClientStop();
}

NQ_BOOL amKerberosClientSetMechanism(NQ_BYTE* ctx, const NQ_CHAR* name)
{
    return sySaslClientSetMechanism(ctx, name);
}

NQ_BYTE* amKerberosClientContextCreate(const NQ_CHAR* name, NQ_BOOL restrictCrypt)
{
    return sySaslContextCreate(name, FALSE, TRUE);
}

NQ_BOOL amKerberosClientGetSessionKey(NQ_BYTE* ctx, NQ_BYTE* buffer, NQ_COUNT* len)
{
    return sySaslGetSessionKey(ctx, buffer, len);
}

NQ_BOOL amKerberosClientContextIsValid(const NQ_BYTE* ctx)
{
    return sySaslContextIsValid(ctx);
}

NQ_BOOL amKerberosClientContextDispose(NQ_BYTE* ctx)
{
    return sySaslContextDispose(ctx);
}

NQ_BOOL amKerberosClientGenerateFirstRequest(NQ_BYTE * ctx, const NQ_CHAR * mechList, NQ_BYTE ** blob, NQ_COUNT * blobLen)
{
    return sySaslClientGenerateFirstRequest(ctx, mechList, blob, blobLen);
}

NQ_BOOL amKerberosClientGenerateNextRequest(NQ_BYTE * ctx, const NQ_BYTE * inBlob, NQ_COUNT inBlobLen, NQ_BYTE ** outBlob, NQ_COUNT* outBlobLen, NQ_BYTE* con)
{
    return sySaslClientGenerateNextRequest(ctx, inBlob, inBlobLen, outBlob, outBlobLen, con);
}

NQ_BOOL amKerberosClientPackNegotBlob(void * context, CMBufferWriter * writer, NQ_COUNT mechtokenBlobLen, NQ_COUNT * blobLen)
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
    NQ_COUNT totalLen;          /* total packed blob length */
    NQ_BOOL res = FALSE;        /* return value */
    SecurityContext * pContext = (SecurityContext *)context;

    /* calculate field lengths - backwards */
    len = pContext->mechanism->oid->size;
    mechtypesSeqLen = 1 + cmAsn1PackLen(len) + len + 1 + cmAsn1PackLen(cmGssApiOidNtlmSsp.size) + cmGssApiOidNtlmSsp.size;
    mechtypesLen = 1 + cmAsn1PackLen(mechtypesSeqLen) + mechtypesSeqLen;
    mechtokenAppLen = 1 + cmAsn1PackLen(len) + pContext->mechanism->oid->size + 2 + mechtokenBlobLen;
    mechtokenBinLen = 1 + cmAsn1PackLen(mechtokenAppLen) + mechtokenAppLen;
    mechtokenLen = 1 + cmAsn1PackLen(mechtokenBinLen) + mechtokenBinLen;
    negtokenLen = 1 + cmAsn1PackLen(mechtypesLen) + mechtypesLen + 1 + cmAsn1PackLen(mechtokenLen) + mechtokenLen;
    spnegoLen = 1 + cmAsn1PackLen(negtokenLen) + negtokenLen;
    gssapiLen = 1 + cmAsn1PackLen(spnegoLen) + spnegoLen + 1 + cmAsn1PackLen(cmGssApiOidSpnego.size) + cmGssApiOidSpnego.size;
    totalLen = 1 + cmAsn1PackLen(gssapiLen) + gssapiLen;
    if (*blobLen < totalLen)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "supplied %d, required %d", *blobLen, totalLen);
        goto Exit;
    }

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
    res = TRUE;

Exit:
    *blobLen = totalLen;
    return res;
}

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEEXTENDEDSECURITY) && defined(UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS) */
