/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RPC packet parsing and creation
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 2005-11-13
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "cmrpcdef.h"

/*====================================================================
 * PURPOSE: attach data to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  pointer to data
 *          IN  byte order indicator (TRUE if network)
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcSetDescriptor(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE *pData,
    NQ_BOOL nbo
    )
{
    pDesc->origin = pData;
    pDesc->nbo = nbo;
    pDesc->token = NULL;
    cmRpcResetDescriptor(pDesc);
}

/*====================================================================
 * PURPOSE: attach data and user token to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  pointer to data
 *          IN  byte order indicator (TRUE if network)
 *          IN  pointer to user token
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcSetTokenDescriptor(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE *pData,
    NQ_BOOL nbo,
    NQ_BYTE *token
    )
{
    pDesc->origin = pData;
    pDesc->nbo = nbo;
    pDesc->token = token;
    cmRpcResetDescriptor(pDesc);
}

/*====================================================================
 * PURPOSE: copy descriptor fields to another descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the source descriptor
 *          IN  pointer to the destination descriptor
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcCloneDescriptor(
    CMRpcPacketDescriptor *pSrc,
    CMRpcPacketDescriptor *pDst
    )
{
    pDst->origin = pSrc->origin;
    pDst->current = pSrc->current;
    pDst->length = pSrc->length;
    pDst->token = pSrc->token;
    pDst->nbo = pSrc->nbo;
}

/*====================================================================
 * PURPOSE: reset descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcResetDescriptor(
    CMRpcPacketDescriptor *pDesc
    )
{
    pDesc->current = pDesc->origin;
}

/*====================================================================
 * PURPOSE: read one byte from a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  address to place a byte in
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcParseByte(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE *pRes
    )
{
    *pRes = *pDesc->current++;
}

/*====================================================================
 * PURPOSE: read UINT16 from a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  address to place UINT16 value in
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcParseUint16(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT16 *pRes
    )
{
    NQ_UINT16 temp = cmGetUint16(pDesc->current);
    *pRes = (NQ_UINT16)((pDesc->nbo)? syNtoh16(temp) : cmLtoh16(temp));
    pDesc->current += 2;
}

/*====================================================================
 * PURPOSE: read UINT32 from a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  address to place UINT32 value in
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcParseUint32(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 *pRes
    )
{
    NQ_UINT32 temp = cmGetUint32(pDesc->current);
    *pRes = (NQ_UINT32)((pDesc->nbo)? syNtoh32((NQ_UINT)temp) : cmLtoh32(temp));
    pDesc->current += 4;
}

/*====================================================================
 * PURPOSE: read unicode string from a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  address to place the unicode string in
 *          IN  flags
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcParseUnicode(
    CMRpcPacketDescriptor *pDesc,
    CMRpcUnicodeString *pRes,
    NQ_UINT16 flags
    )
{
    NQ_BOOL calculateSize = FALSE;

    if (flags & CM_RP_SIZE32)
    {
        cmRpcParseUint32(pDesc, &pRes->size);
    }
    else
    {
        calculateSize = TRUE;
    }

    if (flags & CM_RP_FRAGMENT32)
    {
        cmRpcParseUint32(pDesc, &pRes->offset);
        cmRpcParseUint32(pDesc, &pRes->length);
    }
    else
    {
        pRes->offset = 0;
        pRes->length = pRes->size;
    }

    if (calculateSize)
    {
        pRes->size = cmWStrlen((NQ_WCHAR*)pDesc->current) + 1;
    }

    pRes->text = (NQ_WCHAR*)pDesc->current;
    pDesc->current += pRes->length * sizeof(NQ_WCHAR);

    if ((pRes->length % 2) == 1)
        pDesc->current += sizeof(NQ_WCHAR);  /* undocumented */
}

/*====================================================================
 * PURPOSE: read ascii string from a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  address to place the ascii string in
 *          IN  flags
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcParseAscii(
    CMRpcPacketDescriptor *pDesc,
    CMRpcAsciiString *pRes,
    NQ_UINT16 flags
    )
{
    NQ_BOOL calculateSize = FALSE;

    if (flags & CM_RP_SIZE32)
    {
        cmRpcParseUint32(pDesc, &pRes->size);
    }
    else
    {
        if (flags & CM_RP_SIZE16)
        {
            NQ_UINT16 temp;

            cmRpcParseUint16(pDesc, &temp);
            pRes->size = (NQ_UINT32)temp;
        }
        else
        {
            calculateSize = TRUE;
        }
    }

    if (flags & CM_RP_FRAGMENT32)
    {
        cmRpcParseUint32(pDesc, &pRes->offset);
        cmRpcParseUint32(pDesc, &pRes->length);
    }
    else
    {
        pRes->offset = 0;
        pRes->length = pRes->size;
    }

    if (calculateSize)
    {
        pRes->size = (NQ_UINT32)syStrlen((NQ_CHAR *)pDesc->current);
    }

    pRes->text = (NQ_CHAR *)pDesc->current;
    pDesc->current += pRes->size;
}

/*====================================================================
 * PURPOSE: read bytes from a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  address to place the bytes in
 *          IN  number of bytes to read
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcParseBytes(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE *pRes,
    NQ_UINT32 num
    )
{
    syMemcpy(pRes, pDesc->current, num);
    pDesc->current += num;
}

/*====================================================================
 * PURPOSE: skip bytes in a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  number of bytes to skip
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcParseSkip(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 num
    )
{
    pDesc->current += num;
}

/*====================================================================
 * PURPOSE: make alignment in a descriptor's buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  number of bytes to align to
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcAllign(
    CMRpcPacketDescriptor *pDesc,
    NQ_INT align
    )
{
    NQ_INT offset = (NQ_INT)(pDesc->current - pDesc->origin);
    NQ_INT mod = (NQ_INT)((offset + align) % align);
    NQ_INT add = (NQ_INT)((align - mod) % align);

    pDesc->current += add;
}

/*====================================================================
 * PURPOSE: read UUID from a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  pointer to UUID structure
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcParseUuid(
    CMRpcPacketDescriptor *pDesc,
    CMRpcUuid *pUuid
    )
{
    NQ_UINT32 temp32;
    NQ_UINT16 temp16;

    cmRpcParseUint32(pDesc, &temp32);
    cmPutSUint32(pUuid->timeLow, temp32);
    cmRpcParseUint16(pDesc, &temp16);
    cmPutSUint16(pUuid->timeMid, temp16);
    cmRpcParseUint16(pDesc, &temp16);
    cmPutSUint16(pUuid->timeHiVersion, temp16);
    cmRpcParseBytes(pDesc, pUuid->clockSeq, sizeof(pUuid->clockSeq));
    cmRpcParseBytes(pDesc, pUuid->node, sizeof(pUuid->node));
}

/*====================================================================
 * PURPOSE: write a byte to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  value to write
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcPackByte(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE src
    )
{
    *pDesc->current++ = src;
}

/*====================================================================
 * PURPOSE: write a UINT16 value to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  value to write
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcPackUint16(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT16 src
    )
{
    NQ_UINT16 temp = (NQ_UINT16)((pDesc->nbo)? syHton16(src) : cmHtol16(src));

    cmPutUint16(pDesc->current, temp);
    pDesc->current += 2;
}

/*====================================================================
 * PURPOSE: write a UINT32 value to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  value to write
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmRpcPackUint32(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 src
    )
{
    NQ_UINT32 temp = (NQ_UINT32)((pDesc->nbo)? syHton32((NQ_UINT)src) : cmHtol32(src));

    cmPutUint32(pDesc->current, temp);
    pDesc->current += 4;
}

/*====================================================================
 * PURPOSE: write a 64-bit value to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  low 32 bits of the value to write
 *          IN  high 32 bits of the value to write
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmRpcPackUint64(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 low,
    NQ_UINT32 high
    )
{
    if (pDesc->nbo)
    {
        cmRpcPackUint32(pDesc, high);
        cmRpcPackUint32(pDesc, low);
    }
    else
    {
        cmRpcPackUint32(pDesc, low);
        cmRpcPackUint32(pDesc, high);
    }
}

/*====================================================================
 * PURPOSE: write a 32-bit time value as 64-bit UTC time
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  time to write
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void cmRpcPackTimeAsUTC(
    CMRpcPacketDescriptor *pDesc,
    NQ_TIME time
    )
{
        NQ_UINT32 timeLow;     /* low part of UTC time */
        NQ_UINT32 timeHigh;    /* high part of UTC time */

        cmCifsTimeToUTC(time, &timeLow, &timeHigh);
        cmRpcPackUint64(pDesc, timeLow, timeHigh);
}

/*====================================================================
 * PURPOSE: write a unicode string to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  pointer to the unicode string to write
 *          IN  flags
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcPackUnicode(
    CMRpcPacketDescriptor *pDesc,
    const NQ_WCHAR *str,
    NQ_UINT16 flags
    )
{
    NQ_UINT32 size = cmWStrlen(str),
              fullSize = (flags & CM_RP_NULLTERM)? size + 1 : size;
    
    if (flags & CM_RP_SIZE32)
    {
        NQ_UINT32 m = (flags & CM_RP_INCMAXCOUNT)? fullSize + 1 : fullSize;
        cmRpcPackUint32(pDesc, m);
    }

    if (flags & CM_RP_FRAGMENT32)
    {
        cmRpcPackUint32(pDesc, 0);
        cmRpcPackUint32(pDesc,  (flags & CM_RP_DECACTCOUNT)? fullSize - 1 : fullSize);
    }

    if (pDesc->nbo) 
    {
        NQ_COUNT i;
        for (i = 0; i < size; i++)
        {
#ifdef SY_LITTLEENDIANHOST  
            cmRpcPackUint16(pDesc, str[i]);
#else
            NQ_UINT16 temp = cmLtoh16(str[i]);
            cmPutUint16(pDesc->current, temp);
            pDesc->current += 2;
#endif
        }
    }
    else
    {
        syMemcpy(pDesc->current, str, size * sizeof(NQ_WCHAR));
        pDesc->current += size * sizeof(NQ_WCHAR);
    }
    
    if (flags & CM_RP_NULLTERM)
    {
        *(pDesc->current)++ = 0;
        *(pDesc->current)++ = 0;
    }

    if (flags & CM_RP_SIZE32)
    {
        cmRpcAllignZero(pDesc, 4);
    }
}

/*====================================================================
 * PURPOSE: write an ascii string to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  pointer to the ascii string to write
 *          IN  flags
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcPackAscii(
    CMRpcPacketDescriptor *pDesc,
    const NQ_CHAR *str,
    NQ_UINT16 flags
    )
{
    NQ_UINT32 size = (NQ_UINT32)syStrlen(str),
              fullSize = (flags & CM_RP_NULLTERM)? size + 1 : size;

    if (flags & CM_RP_SIZE32)
    {
        cmRpcPackUint32(pDesc, fullSize);
    }
    else
    {
        if (flags & CM_RP_SIZE16)
        {
            cmRpcPackUint16(pDesc, (NQ_UINT16)fullSize);
        }
    }

    if (flags & CM_RP_FRAGMENT32)
    {
        cmRpcPackUint32(pDesc, 0);
        cmRpcPackUint32(pDesc, fullSize);
    }

    syMemcpy(pDesc->current, str, size);
    pDesc->current += size;

    if (flags & CM_RP_NULLTERM)
    {
        *(pDesc->current)++ = 0;
    }
}

/*====================================================================
 * PURPOSE: write bytes to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  pointer to the bytes to write
 *          IN  number of bytes to write
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcPackBytes(
    CMRpcPacketDescriptor *pDesc,
    const NQ_BYTE *pRes,
    NQ_UINT32 num
    )
{
    syMemcpy(pDesc->current, pRes, num);
    pDesc->current += num;
}

/*====================================================================
 * PURPOSE: skip bytes in a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  nuber of bytes to skip
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcPackSkip(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 num
    )
{
    pDesc->current += num;
}


/*====================================================================
 * PURPOSE: align and write zeros
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  number of bytes to align to
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcAllignZero(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT16 align
    )
{
    NQ_INT offset = (NQ_INT)(pDesc->current - pDesc->origin);
    NQ_INT mod = (offset + align) % align;
    NQ_INT add = (align - mod) % align;
    NQ_INT i;

    for (i = 0; i < add; i++)
    {
        *(pDesc->current)++ = 0;
    }
}

/*====================================================================
 * PURPOSE: write UUID to a descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to the descriptor
 *          IN  pointer to the UUID to write
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
cmRpcPackUuid(
    CMRpcPacketDescriptor *pDesc,
    const CMRpcUuid *pUuid
    )
{
    cmRpcPackUint32(pDesc, cmGetSUint32(pUuid->timeLow));
    cmRpcPackUint16(pDesc, cmGetSUint16(pUuid->timeMid));
    cmRpcPackUint16(pDesc, cmGetSUint16(pUuid->timeHiVersion));
    cmRpcPackBytes(pDesc, pUuid->clockSeq, sizeof(pUuid->clockSeq));
    cmRpcPackBytes(pDesc, pUuid->node, sizeof(pUuid->node));
}

NQ_UINT32 cmRpcSpace(CMRpcPacketDescriptor *pDesc)
{
    return (NQ_UINT32)(pDesc->length - (NQ_UINT)(pDesc->current - pDesc->origin));
}

/*====================================================================
 * PURPOSE: pack ascii string as Unicode string
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet descriptor to use
 *          IN string to pack
 *          IN pack flags ad required by cmRpcPackUnicode()
 *
 * RETURNS: 0 or error code on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32 cmRpcPackAsciiAsUnicode(
    CMRpcPacketDescriptor * desc,
    const NQ_CHAR * source,
    NQ_INT flags
    )
{
    NQ_WCHAR * temp = cmMemoryCloneAString(source);

    if (NULL == temp)
    {
        return (NQ_UINT32)NQ_FAIL;
    }
    cmRpcPackUnicode(desc, temp, (NQ_UINT16)flags);
    cmMemoryFree(temp);
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: pack TCHAR string as Unicode string
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet descriptor to use
 *          IN string to pack
 *          IN pack flags ad required by cmRpcPackUnicode()
 *
 * RETURNS: 0 or error code on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32 cmRpcPackTcharAsUnicode(
    CMRpcPacketDescriptor * desc,
    const NQ_TCHAR * source,
    NQ_INT flags
    )
{
    NQ_WCHAR * temp;

    if (source != NULL)
    {
        temp = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + cmTStrlen(source))));
        if (NULL == temp)
        {
            return (NQ_UINT32)NQ_FAIL;
        }
        cmTcharToUnicode(temp, source);
        cmRpcPackUnicode(desc, temp, (NQ_UINT16)flags);
        cmMemoryFree(temp);
    }
    else
    {
        static NQ_WCHAR nullStr[] = {0};
        temp = nullStr;
        cmRpcPackUnicode(desc, temp, (NQ_UINT16)flags);
    }
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: get length of TCHAR string in Unicode characters
 *--------------------------------------------------------------------
 * PARAMS:  IN string to measure
 *
 * RETURNS: string length in Unicode characters
 *
 * NOTES:   as after conversion to Unicode
 *====================================================================
 */

NQ_UINT32 cmRpcTcharAsUnicodeLength(
    const NQ_TCHAR* source
    )
{
    NQ_UINT32 len;
    NQ_WCHAR *temp = cmMemoryAllocate((NQ_UINT)(8 * (cmTStrlen(source) + 1)));   

    if (NULL == temp)
        return (NQ_UINT32)NQ_FAIL;
    cmTcharToUnicode(temp, source);    
    len = cmWStrlen(temp);
    cmMemoryFree(temp);
    return len;
}

