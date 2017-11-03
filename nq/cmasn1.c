/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Abstract GSASL interface
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 11-Feb-2007
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmasn1.h"

#if defined(UD_CC_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_INCLUDEEXTENDEDSECURITY)

/*
 *====================================================================
 * PURPOSE: parse OID and compare it with another one
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet descriptor
 *          IN     OID data to compare
 *          IN     whether to revert descriptor on error or no match
 *
 * RETURNS: TRUE on match, FAIL otherwise
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
cmAsn1ParseCompareOid(
    CMBufferReader * ds,
    const CMAsn1Oid *oid,
    NQ_BOOL toRevertOnMismatch
    )
{
    NQ_BYTE* savedCurrent = ds->current; /* saved position in the packet */
    CMAsn1Len dataLen;                   /* OID data length */
    NQ_BOOL res = FALSE;                 /* result */

    if (CM_ASN1_OID != cmAsn1ParseTag(ds, &dataLen))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Tag is not OID");
        goto Exit;
    }
    if (dataLen == oid->size)
    {
        res = (0 == syMemcmp(ds->current, oid->data, oid->size));
    }
    else
    {
        res = FALSE;
    }
    if (cmBufferReaderGetRemaining(ds) < dataLen)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Tag data exceeds packet limits");
        res = FALSE;
        goto Exit;
    }
    cmBufferReaderSkip(ds, dataLen);

Exit:
    if (FALSE == res && toRevertOnMismatch)
        cmBufferReaderSetPosition(ds, savedCurrent);

    return res;
}

/*
 *====================================================================
 * PURPOSE: parse tag and tag length and continue to tag data
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet descriptor
 *          IN buffer for OID data length
 *
 * RETURNS: parsed tag
 *
 * NOTES:
 *====================================================================
 */

CMAsn1Tag
cmAsn1ParseTag(
	CMBufferReader * ds,
    CMAsn1Len* dataLen
    )
{
    CMAsn1Tag tag;      /* parsed tag */
    NQ_BYTE next;       /* next byte of the length */

    cmBufferReadByte(ds, &next);
    tag = next;
    cmBufferReadByte(ds, &next);
    if (0 == (next & 0x80))
    {
        *dataLen = (CMAsn1Len)next;
    }
    else
    {
        NQ_INDEX i; /* just and index */

        *dataLen = 0;
        for (i = next & 0x7f; i > 0; i--)
        {
        	cmBufferReadByte(ds, &next);
            *dataLen = *dataLen * 256 + (NQ_UINT)next;
        }
    }
    return tag;
}

/*
 *====================================================================
 * PURPOSE: calculate length of the tag data length field
 *--------------------------------------------------------------------
 * PARAMS:  IN data length
 *
 * RETURNS: number of bytes in the tag length area
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
cmAsn1PackLen(
    CMAsn1Len dataLen
    )
{
    NQ_COUNT res;    /* the result */

    if (dataLen > 0x7f)
    {
        for (res = 1; dataLen > 0; res++)
        {
            dataLen /= 256;
        }
    }
    else
    {
        res = 1;
    }
    return res;
}

/*
 *====================================================================
 * PURPOSE: calculate length of ASN1 element
 *--------------------------------------------------------------------
 * PARAMS:  IN data length
 *
 * RETURNS: actual number of bytes in the element
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT cmAsn1GetElementLength(NQ_UINT length)
{
    /* param type + bytes required for length + length */
    return 1 + cmAsn1PackLen(length) + length;
}

/*
 *====================================================================
 * PURPOSE: pack tag
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet descriptor
 *          IN tag
 *          IN data length
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
cmAsn1PackTag(
    CMBufferWriter * ds,
    CMAsn1Tag tag,
    CMAsn1Len dataLen
    )
{
    cmRpcPackByte(ds, (NQ_BYTE)tag);
    if (dataLen > 0x7f)
    {
        NQ_BYTE lenBuf[5];  /* buffer for data length in ASN1 */
        NQ_INT i;           /* number of bytes in length */

        for (i = 4; i >=0 && dataLen > 0; i--)
        {
            lenBuf[i] = dataLen % 256;
            dataLen /= 256;
        }
        cmBufferWriteByte(ds, (NQ_BYTE)(0x80 | (5 - i - 1)));
        cmBufferWriteBytes(ds, lenBuf + i + 1, (NQ_COUNT)(5 - i - 1));
    }
    else
    {
    	cmBufferWriteByte(ds, (NQ_BYTE)dataLen);
    }
}

/*
 *====================================================================
 * PURPOSE: pack OID
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet descriptor
 *          IN OID data
 *
 * RETURNS: NONE
 *
 *====================================================================
 */

void
cmAsn1PackOid(
    CMBufferWriter * ds,
    const CMAsn1Oid *oid
    )
{
    if (NULL != oid)
    {
        cmAsn1PackTag(ds, CM_ASN1_OID, oid->size);
        cmBufferWriteBytes(ds, oid->data, oid->size);
    }
}

#endif /* defined(UD_CC_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_INCLUDEEXTENDEDSECURITY) */

