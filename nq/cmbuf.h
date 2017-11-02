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

#ifndef _CMBUF_H
#define _CMBUF_H

/*
  todo: replace CMRpcPacketDescriptor with the following structure -

  typedef struct {
      NQ_BYTE *start;
      NQ_BYTE *current;
      NQ_UINT size;
      NQ_BOOL le;
  } 
  CMBufferReader,
  CMBufferWriter;

  todo: remove cmRpcParse... and cmRpcPack... functions
  todo: make CMRpcPacketDescriptor to contain buffer reader and/or writer
*/

#include "cmapi.h"

/* String flags */
typedef enum 
{
    CM_BSF_NOFLAGS       = 0, 
    CM_BSF_WRITENULLTERM = 1
}
CMBufferStringFlags;

/* Buffer reader */
typedef CMRpcPacketDescriptor CMBufferReader;

/* Initialize buffer reader (byte order set to LE by default) */
void cmBufferReaderInit(CMBufferReader *reader, const NQ_BYTE *buffer, NQ_COUNT size);
/* Set reader start position to its current buffer position and recalculates remaining length */
void cmBufferReaderStart(CMBufferReader *reader);
/* Set reader byte order */
void cmBufferReaderSetByteOrder(CMBufferReader *reader, NQ_BOOL le);

/* Get reader start position */
NQ_BYTE *cmBufferReaderGetStart(const CMBufferReader *reader);
/* Get reader current position */
NQ_BYTE *cmBufferReaderGetPosition(const CMBufferReader *reader);
/* Set reader current position (must be inside the buffer) */
void cmBufferReaderSetPosition(CMBufferReader *reader, NQ_BYTE *position);
/* Set reader current offset relative to buffer start */
void cmBufferReaderSetOffset(CMBufferReader *reader, NQ_UINT32 offset);
/* Get read data count in bytes */
NQ_COUNT cmBufferReaderGetDataCount(const CMBufferReader *reader);
/* Get remaining data count */
NQ_COUNT cmBufferReaderGetRemaining(const CMBufferReader *reader);

/* Align current position (anchor must be inside the buffer), possible alignments: 2, 4, 8, 16, ... */
void cmBufferReaderAlign(CMBufferReader *reader, NQ_BYTE *anchor, NQ_UINT alignment);
/* Move data pointer forward */
void cmBufferReaderSkip(CMBufferReader *reader, NQ_UINT bytes);

/* Read 1 byte */
void cmBufferReadByte(CMBufferReader *reader, NQ_BYTE *to);
/* Read bytes */
void cmBufferReadBytes(CMBufferReader *reader, NQ_BYTE *to, NQ_COUNT size);
/* Read unsigned 16 bit value */
void cmBufferReadUint16(CMBufferReader *reader, NQ_UINT16 *to);
/* Read unsigned 32 bit value */
void cmBufferReadUint32(CMBufferReader *reader, NQ_UINT32 *to);
/* Read unsigned 64 bit value */
void cmBufferReadUint64(CMBufferReader *reader, NQ_UINT64 *to);
/* Read 'length' Unicode characters converting it to a sequence of NQ_TCHARS (use CM_BSF_WRITENULLTERM to null terminate it) */
void cmBufferReadUnicodeAsTStringN(CMBufferReader *reader, NQ_UINT length, CMBufferStringFlags flags, NQ_TCHAR *string);

/* Buffer writer */
typedef CMRpcPacketDescriptor CMBufferWriter;

/* Initialize buffer writer (byte order set to LE by default) */
void cmBufferWriterInit(CMBufferWriter *writer, NQ_BYTE *buffer, NQ_COUNT capacity);
/* Set writer start position to its current buffer position and recalculates remaining length */
void cmBufferWriterStart(CMBufferWriter *writer);
/* Reset writer current position to its start */
void cmBufferWriterReset(CMBufferWriter *writer);
/* Set writer byte order */
void cmBufferWriterSetByteOrder(CMBufferWriter *writer, NQ_BOOL le);

/* Clone writer - initialize new writer (to) with current position of the old one + offset */
void cmBufferWriterClone(const CMBufferWriter *what, CMBufferWriter *to, NQ_UINT offset);
/* Clone writer - initialize new writer (to) with current position of the old one and then skip by offset */
void cmBufferWriterCloneAndSkip(CMBufferWriter *what, CMBufferWriter *to, NQ_UINT offset);
/* Branch writer - initialize new writer (to) starting from the old writer current position + offset */
void cmBufferWriterBranch(const CMBufferWriter *what, CMBufferWriter *to, NQ_UINT offset);
/* Synchronize writer current positions */
void cmBufferWriterSync(CMBufferWriter *what, const CMBufferWriter *with);

/* Get writer start position */
NQ_BYTE *cmBufferWriterGetStart(const CMBufferWriter *writer);
/* Get writer current position */
NQ_BYTE *cmBufferWriterGetPosition(const CMBufferWriter *writer);
/* Set writer current position (must be inside the buffer) */
void cmBufferWriterSetPosition(CMBufferWriter *writer, NQ_BYTE *position);
#if 0
/* Set writer current offset relative to buffer start */
void cmBufferWriterSetOffset(CMBufferWriter *writer, NQ_UINT offset);
#endif
/* Get written data count in bytes */
NQ_COUNT cmBufferWriterGetDataCount(const CMBufferWriter *writer);
/* Get remaining data count */
NQ_COUNT cmBufferWriterGetRemaining(const CMBufferWriter *writer);

/* Align current position and zero the gap (anchor must be inside the buffer), possible alignments: 2, 4, 8, 16, ... */
void cmBufferWriterAlign(CMBufferWriter *writer, NQ_BYTE *anchor, NQ_UINT alignment);
/* Move data pointer forward */
void cmBufferWriterSkip(CMBufferWriter *writer, NQ_UINT bytes);

/* Write 1 byte */
void cmBufferWriteByte(CMBufferWriter *writer, NQ_BYTE value);
/* Write bytes */
void cmBufferWriteBytes(CMBufferWriter *writer, const NQ_BYTE *bytes, NQ_COUNT size);
/* Write zero bytes */
void cmBufferWriteZeroes(CMBufferWriter *writer, NQ_COUNT size);
/* Write unsigned 16 bit value */
void cmBufferWriteUint16(CMBufferWriter *writer, NQ_UINT16 value);
/* Write unsigned 32 bit value */
void cmBufferWriteUint32(CMBufferWriter *writer, NQ_UINT32 value);
/* Write unsigned 64 bit value */
void cmBufferWriteUint64(CMBufferWriter *writer, const NQ_UINT64 *value);
/* Write GUID structure */
void cmBufferWriteUuid(CMBufferWriter * writer, const NQ_Uuid * pUuid);
/* Write a null terminated sequence of NQ_TCHARs as LE unicode string */
void cmBufferWriteTStringAsUnicode(CMBufferWriter *writer, const NQ_TCHAR *string, CMBufferStringFlags flags);
/* Write a sequence of 'length' NQ_TCHARs as LE unicode string */
void cmBufferWriteTStringAsUnicodeN(CMBufferWriter *writer, const NQ_TCHAR *string, NQ_UINT length, CMBufferStringFlags flags);
/* Write a sequence of 'length' NQ_CHARs as LE unicode string */
void cmBufferWriteAsciiAsUnicodeN(CMBufferWriter *writer, const NQ_CHAR *string, NQ_UINT length, CMBufferStringFlags flags);
/* Write TCHAR string (null-terminated) */
void cmBufferWriteTString(CMBufferWriter *writer, const NQ_TCHAR *string);
/* Write Unicode string */
void cmBufferWriteUnicode(CMBufferWriter *writer, const NQ_WCHAR *string);
/* Write Unicode string without null terminator */
void cmBufferWriteUnicodeNoNull(CMBufferWriter *writer, const NQ_WCHAR *string);
/* Write random bytes */
void cmBufferWriteRandomBytes(CMBufferWriter *writer, NQ_COUNT size);
    
#endif

