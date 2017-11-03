/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : GSSAPI
 *--------------------------------------------------------------------
 * MODULE        : CM
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 11-Dec-2008
 ********************************************************************/
#include "cmapi.h"
#include "cmgssapi.h"

#if defined(UD_CC_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_INCLUDEEXTENDEDSECURITY)

static NQ_BYTE _spnego[]     = {CM_ASN1_1_3, 0x06, 0x01, 0x05, 0x05, 0x02 };
static NQ_BYTE _mskerberos[] = {CM_ASN1_1_2, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02 }; /* 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5)*/
static NQ_BYTE _kerberos[] =   {CM_ASN1_1_2, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 }; /* 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5) */
static NQ_BYTE _kerberosutu[] = {CM_ASN1_1_2, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03};
static NQ_BYTE _ntlmssp[]    = {CM_ASN1_1_3, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};

const CMAsn1Oid cmGssApiOidSpnego = {_spnego, sizeof(_spnego)};
const CMAsn1Oid cmGssApiOidMsKerberos = {_mskerberos, sizeof(_mskerberos)};
const CMAsn1Oid cmGssApiOidKerberos = {_kerberos, sizeof(_kerberos)};
const CMAsn1Oid cmGssApiOidKerberosUserToUser = {_kerberosutu, sizeof(_kerberosutu)};
const CMAsn1Oid cmGssApiOidNtlmSsp = {_ntlmssp, sizeof(_ntlmssp)};



/*
 *====================================================================
 * PURPOSE: check whether blob has required mechanism oid 
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to SPNEGO security blob start 
 *          IN  blob length
 *          IN  required oid
 *
 * RETURNS: TRUE or FALSE
 *
 * NOTES:  
 *====================================================================
 */
NQ_BOOL
cmGssDoesBlobHaveMechType(
    NQ_BYTE* blob,
    NQ_COUNT blobLen,
    const CMAsn1Oid *oid
    )
{
    CMRpcPacketDescriptor ds;   /* blob as an incoming packet */
    CMAsn1Len len;              /* object length */
    CMAsn1Tag tag;              /* next ASN1 tag */
    NQ_BYTE* listEnd;           /* last address after the list of OIDs */
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "blob:%p blobLen:%d oid:%p", blob, blobLen, oid);

    if (blobLen == 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Empty blob");
        goto Exit;
    }
    
    cmRpcSetDescriptor(&ds, (NQ_BYTE*)blob, TRUE);
    ds.length = blobLen; 
    
    tag = cmAsn1ParseTag(&ds, &len);
    if (CM_ASN1_APPLICATION != tag)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Unexpected tag in the blob, expected: %d, seen: %d", CM_ASN1_APPLICATION, tag);
        goto Exit;
    }
    if (!cmAsn1ParseCompareOid(&ds, &cmGssApiOidSpnego, TRUE)) /* SPNEGO IOD */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected OID");
        goto Exit;
    }
    tag = cmAsn1ParseTag(&ds, &len);    /* SPNEGO blob */
    if (CM_ASN1_CONTEXT != tag)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Unexpected tag in the blob, expected: %d, seen: %d", CM_ASN1_CONTEXT, tag);
        goto Exit;
    }
    tag = cmAsn1ParseTag(&ds, &len);    /* SPNEGO list */
    if (CM_ASN1_SEQUENCE != tag)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Unexpected tag in the blob, expected: %d, seen: %d", CM_ASN1_SEQUENCE, tag);
        goto Exit;
    }
    tag = cmAsn1ParseTag(&ds, &len);    /* negTokenInit */
    if (CM_ASN1_CONTEXT != tag)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Unexpected tag in the blob, expected: %d, seen: %d", CM_ASN1_CONTEXT, tag);
        goto Exit;
    }
    tag = cmAsn1ParseTag(&ds, &len);    /* negTokenInit list */
    if (CM_ASN1_SEQUENCE != tag)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Unexpected tag in the blob, expected: %d, seen: %d", CM_ASN1_CONTEXT, tag);
        goto Exit;
    }            
    for (listEnd = ds.current + len; ds.current < listEnd;  )
    {
        if (cmAsn1ParseCompareOid(&ds, oid, FALSE))
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "SPNEGO contains required OID");  
            result = TRUE;
            goto Exit;
        }
    }
    LOGERR(CM_TRC_LEVEL_ERROR, "SPNEGO does not contain required OID");

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

#endif /* defined(UD_CC_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_INCLUDEEXTENDEDSECURITY) */
