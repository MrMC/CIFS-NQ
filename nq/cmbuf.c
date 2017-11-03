/*********************************************************************
*
*           Copyright (c) 2008 by Visuality Systems, Ltd.
*
*********************************************************************
* FILE NAME     : $Workfile:$
* ID            : $Header:$
* REVISION      : $Revision:$
*--------------------------------------------------------------------
* DESCRIPTION   : Buffer manipulation
*--------------------------------------------------------------------
* MODULE        : CM
* DEPENDENCIES  :
*--------------------------------------------------------------------
* CREATION DATE : 03-Dec-2008
* CREATED BY    : Igor Gokhman
* LAST AUTHOR   : $Author:$
********************************************************************/

#include "cmbuf.h"

/* Static functions */

static NQ_UINT32 align(NQ_UINT32 what, NQ_UINT32 alignment)
{
    --alignment;

    return (what + alignment) & ~alignment;
}

/* Buffer reader */

void cmBufferReaderInit(CMBufferReader *reader, const NQ_BYTE *buffer, NQ_COUNT size)
{
    cmRpcSetDescriptor(reader, (NQ_BYTE *)buffer, FALSE);

    reader->length = size;
}

void cmBufferReaderReset(CMBufferReader *reader)
{
    reader->current = reader->origin;
}

void cmBufferReaderStart(CMBufferReader *reader)
{
    reader->length -= cmBufferReaderGetDataCount(reader);
    reader->origin = reader->current;
}

void cmBufferReaderSetByteOrder(CMBufferReader *reader, NQ_BOOL le)
{
    reader->nbo = !le;
}

NQ_BYTE *cmBufferReaderGetStart(const CMBufferReader *reader)
{
    return reader->origin;
}

NQ_BYTE *cmBufferReaderGetPosition(const CMBufferReader *reader)
{
    return reader->current;
}

void cmBufferReaderSetPosition(CMBufferReader *reader, NQ_BYTE *position)
{
    reader->current = position;
}

void cmBufferReaderSetOffset(CMBufferReader *reader, NQ_UINT32 offset)
{
    reader->current = reader->origin + offset;
}

NQ_COUNT cmBufferReaderGetDataCount(const CMBufferReader *reader)
{
    return (NQ_COUNT)(reader->current - reader->origin);
}

NQ_COUNT cmBufferReaderGetRemaining(const CMBufferReader *reader)
{
    return reader->length - cmBufferReaderGetDataCount(reader);
}

void cmBufferReaderAlign(CMBufferReader *reader, NQ_BYTE *anchor, NQ_UINT alignment)
{
    /* assert: reader->current >= anchor */
    reader->current = anchor + align((NQ_UINT32)(reader->current - anchor), (NQ_UINT32)alignment);
}

void cmBufferReaderSkip(CMBufferReader *reader, NQ_UINT bytes)
{
    reader->current += bytes;
}

void cmBufferReadByte(CMBufferReader *reader, NQ_BYTE *to)
{
    cmRpcParseByte(reader, to);
}

void cmBufferReadBytes(CMBufferReader *reader, NQ_BYTE *to, NQ_COUNT size)
{
    cmRpcParseBytes(reader, to, size);
}

void cmBufferReadUint16(CMBufferReader *reader, NQ_UINT16 *to)
{
    cmRpcParseUint16(reader, to);
}

void cmBufferReadUint32(CMBufferReader *reader, NQ_UINT32 *to)
{
    cmRpcParseUint32(reader, to);
}

void cmBufferReadUint64(CMBufferReader *reader, NQ_UINT64 *to)
{
    cmBufferReadUint32(reader, &to->low);
    cmBufferReadUint32(reader, &to->high);
}

/* Buffer writer */

void cmBufferWriterInit(CMBufferWriter *writer, NQ_BYTE *buffer, NQ_COUNT capacity)
{
    cmRpcSetDescriptor(writer, buffer, FALSE);

    writer->length = capacity;
}

void cmBufferWriterStart(CMBufferWriter *writer)
{
    writer->length -= cmBufferWriterGetDataCount(writer);
    writer->origin = writer->current;
}

void cmBufferWriterReset(CMBufferWriter *writer)
{
    writer->current = writer->origin;
}

void cmBufferWriterSetByteOrder(CMBufferWriter *writer, NQ_BOOL le)
{
    writer->nbo = !le;
}

void cmBufferWriterClone(const CMBufferWriter *what, CMBufferWriter *to, NQ_UINT offset)
{
    to->origin = what->origin;
    to->current = what->current + offset;
    to->nbo = what->nbo;
    to->length = what->length;
}

void cmBufferWriterCloneAndSkip(CMBufferWriter *what, CMBufferWriter *to, NQ_UINT offset)
{
    cmBufferWriterClone(what, to, 0);
    cmBufferWriterSkip(what, offset);
}

void cmBufferWriterBranch(const CMBufferWriter *what, CMBufferWriter *to, NQ_UINT offset)
{
    to->origin = to->current = what->current + offset;
    to->length = what->length - cmBufferWriterGetDataCount(what);
    to->nbo = what->nbo;
}

void cmBufferWriterSync(CMBufferWriter *what, const CMBufferWriter *with)
{
    what->current = with->current;
}

NQ_BYTE *cmBufferWriterGetStart(const CMBufferWriter *writer)
{
    return writer->origin;
}

NQ_BYTE *cmBufferWriterGetPosition(const CMBufferWriter *writer)
{
    return writer->current;
}

void cmBufferWriterSetPosition(CMBufferWriter *writer, NQ_BYTE *position)
{
    writer->current = position;
}

#if 0
void cmBufferWriterSetOffset(CMBufferWriter *writer, NQ_UINT offset)
{
    writer->current = writer->origin + offset;
}
#endif

NQ_COUNT cmBufferWriterGetDataCount(const CMBufferWriter *writer)
{
    return (NQ_COUNT)(writer->current - writer->origin);
}

NQ_COUNT cmBufferWriterGetRemaining(const CMBufferWriter *writer)
{
    return writer->length - cmBufferWriterGetDataCount(writer);
}

NQ_UINT32 cmBufferWriterAlign(CMBufferWriter *writer, NQ_BYTE *anchor, NQ_UINT alignment)
{
    /* assert: writer->current >= anchor */
    NQ_UINT32 diff = (NQ_UINT32)(writer->current - anchor);
    NQ_UINT32 aligned = align(diff, alignment);

    syMemset(writer->current, 0, (aligned - diff));
    writer->current = anchor + aligned;
    return (aligned - diff);
}

void cmBufferWriterSkip(CMBufferWriter *writer, NQ_UINT bytes)
{
    writer->current += bytes;
}

void cmBufferWriteByte(CMBufferWriter *writer, NQ_BYTE value)
{
    cmRpcPackByte(writer, value);
}

void cmBufferWriteBytes(CMBufferWriter *writer, const NQ_BYTE *bytes, NQ_COUNT size)
{
    cmRpcPackBytes(writer, bytes, size);
}

void cmBufferWriteZeroes(CMBufferWriter *writer, NQ_COUNT size)
{
    for (; size > 0; --size)
        cmBufferWriteByte(writer, 0);
}

void cmBufferWriteUint16(CMBufferWriter *writer, NQ_UINT16 value)
{
    cmRpcPackUint16(writer, value);
}

void cmBufferWriteUint32(CMBufferWriter *writer, NQ_UINT32 value)
{
    cmRpcPackUint32(writer, value);
}

void cmBufferWriteUint64(CMBufferWriter *writer, const NQ_UINT64 *value)
{
    if (writer->nbo)
    {
        cmRpcPackUint32(writer, value->high);
        cmRpcPackUint32(writer, value->low);
    }
    else
    {
        cmRpcPackUint32(writer, value->low);
        cmRpcPackUint32(writer, value->high);
    }
}

void cmBufferWriteUuid(CMBufferWriter * writer, const NQ_Uuid * pUuid)
{
    cmBufferWriteUint32(writer, (NQ_UINT32)cmGetSUint32(pUuid->timeLow));
    cmBufferWriteUint16(writer, (NQ_UINT16)cmGetSUint16(pUuid->timeMid));
    cmBufferWriteUint16(writer, (NQ_UINT16)cmGetSUint16(pUuid->timeHiVersion));
    cmBufferWriteBytes(writer, pUuid->clockSeq, sizeof(pUuid->clockSeq));
    cmBufferWriteBytes(writer, pUuid->node, sizeof(pUuid->node));
}


void cmBufferWriteAsciiAsUnicodeN(CMBufferWriter *writer, const NQ_CHAR *string, NQ_UINT length, CMBufferStringFlags flags)
{
    cmAnsiToUnicodeN((NQ_WCHAR *)cmBufferWriterGetPosition(writer), string, length);
    cmBufferWriterSkip(writer, (NQ_UINT)(syStrlen(string) * sizeof(NQ_WCHAR)));
    /* if target string should be null terminated write trailing 2 zero bytes */
    if (flags & CM_BSF_WRITENULLTERM)
        cmBufferWriteUint16(writer, 0);
}

void cmBufferWriteUnicode(CMBufferWriter *writer, const NQ_WCHAR *string)
{
    NQ_UINT length;

    length = (NQ_UINT)cmWStrlen(string);
    cmWStrncpy((NQ_WCHAR *)cmBufferWriterGetPosition(writer), string, length);
    cmBufferWriterSkip(writer, (NQ_UINT)(length * sizeof(NQ_WCHAR)));
    cmBufferWriteUint16(writer, 0);
}

void cmBufferWriteUnicodeNoNull(CMBufferWriter *writer, const NQ_WCHAR *string)
{
    NQ_UINT length;

    length = (NQ_UINT)cmWStrlen(string);
    cmBufferWriteBytes(writer, (NQ_BYTE*)string, (NQ_COUNT)(length * sizeof(NQ_WCHAR)));
}

void cmBufferWriteRandomBytes(CMBufferWriter *writer, NQ_COUNT size)
{
    for (; size > 0; --size)
        cmBufferWriteByte(writer, (NQ_BYTE)syRand());
}

void cmBufferWriteString(CMBufferWriter *writer, NQ_BOOL outAscii, const NQ_BYTE *string, NQ_BOOL inUnicode, CMBufferStringFlags flags)
{
    if (inUnicode)
    {
        if (outAscii)
        {
            NQ_UINT length;
            NQ_CHAR * strA = (NQ_CHAR *)cmBufferWriterGetPosition(writer);

            cmUnicodeToAnsi(strA, (NQ_WCHAR *)string);
            length = (NQ_UINT)syStrlen((const NQ_CHAR*)strA);
            cmBufferWriterSkip(writer, length);
            if (flags & CM_BSF_WRITENULLTERM)
                cmBufferWriteByte(writer, 0);
        }
        else
        {
            cmBufferWriteUnicodeNoNull(writer, (const NQ_WCHAR *)string);
            if (flags & CM_BSF_WRITENULLTERM)
                cmBufferWriteUint16(writer, 0);
        }
    }
    else
    {
        NQ_UINT length = (NQ_UINT)syStrlen((const NQ_CHAR*)string);

        if (outAscii)
        {
            cmBufferWriteBytes(writer, string, length);
            if (flags & CM_BSF_WRITENULLTERM)
                cmBufferWriteByte(writer, 0);
        }
        else
        {
            cmBufferWriteAsciiAsUnicodeN(writer, (const NQ_CHAR *)string, length, flags);
        }
    }
}
