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

#include "cmcapture.h"

#ifdef UD_NQ_INCLUDESMBCAPTURE
#include "cmparams.h"
#include "udconfig.h"

/* --- Static Data --- */
static SYFile file = syInvalidFile();
static NQ_BOOL initialized = FALSE;
static SYMutex	fileGuard;
static SYMutex  staticGuard;
static NQ_UINT  totalPacketLen = 0 ;
#ifdef UD_NQ_USETRANSPORTIPV4
static NQ_UINT16 IPv4Id = 1;
#endif /* UD_NQ_USETRANSPORTIPV4 */

/* --- PCAP Header constants ---*/
static const NQ_BYTE pcapBlockOrderMagic[] = {0xD4 , 0XC3 , 0xB2 , 0xA1};
static const NQ_BYTE pcapBlockVersion[]    = {0x02 , 0x00 , 0x04 , 0x00};
static const NQ_BYTE pcapBlockSnapLen[]    = {0xFF , 0xFF , 0x00 , 0x00};
static const NQ_UINT pcapFileHeaderSize = sizeof(pcapBlockOrderMagic) + sizeof(pcapBlockVersion) + sizeof(pcapBlockSnapLen) + 3 + 9;
static const NQ_BYTE pcapHeaderLen = sizeof(NQ_UINT32) * 4;

/* --- Ethernet Header --- */
static const NQ_BYTE ethernetHeader[] = { 0x01 , 0x02 , 0x03 , 0x04 , 0x05 , 0x06 , 0x11 ,
										  0x12 , 0x13 , 0x14 , 0x15 , 0x16};
static const NQ_BYTE ethernetIPv4[] = {0x08 , 0x00};
static const NQ_BYTE ethernetIPv6[] = {0x86 , 0xdd};
static const NQ_INT ethernetHeaderLength = 14;

/* --- IPv4 Header Constants --- */
static const NQ_INT ipv4HeaderLength = 20;
static const NQ_BYTE IPv4Type = 0x45;
static const NQ_BYTE IPv4Flags[] = { 0x40 , 0x00 , 0x80 , 0x06 , 0x00 , 0x00};

/* --- IPv6 Header Constants --- */
static const NQ_INT ipv6HeaderLength = 40;
static const NQ_BYTE IPv6Type = 0x60;
static const NQ_BYTE IPv6NextHeaderTCP = 0x06;

/* --- TCP Header Constants --- */
static const NQ_INT tcpHeaderLength = 32;
static const NQ_BYTE tcpHeaderLen =  0x80;
static const NQ_BYTE tcpFlags = 0x10;
static const NQ_BYTE tcpWindowSize[] = { 1 , 0 };
static NQ_UINT32  sequenceNumber = 1;

static const NQ_INT netBiosHeaderLength = 4;

/* --- Constants For Large Packets --- */
/*
 * maxPacketLen -> Maximal Length of the packet, if the length is larger than this constant the packet will be cut.
 * cutPacketLen -> Size of the packet after it has been cut.
 */
static const NQ_UINT maxPacketLen = 10240 , cutPacketLen = 10225;

/* --- static functions --- */
static void preparePcapFile(NQ_BYTE * buffer);
static void preparePcapHeader(CMBufferWriter * writer , NQ_UINT length , NQ_BOOL isIpv6);
static NQ_BOOL prepareIpHeader(const CMCaptureHeader * header , CMBufferWriter * writer , NQ_UINT length);
static void prepareTcpHeader(const CMCaptureHeader * header , CMBufferWriter * writer , NQ_UINT length);
static void prepareNetBiosHeader(NQ_BYTE * buffer , NQ_UINT length);
static NQ_INT writeToFile(const NQ_BYTE *buffer, NQ_UINT32 size);

static NQ_BOOL captureWrite = FALSE;

NQ_BOOL cmCaptureStart(void)
{
	static NQ_WCHAR filename[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXPATHLEN)];
	NQ_BYTE * pcapFileHeader = NULL;
	NQ_UINT	  res = 0;
	NQ_BOOL   result = FALSE;

	if (!initialized)
	{
		NQ_WCHAR *nameW;
		NQ_WCHAR pathSep[CM_BUFFERLENGTH(NQ_WCHAR, 2)];
		pcapFileHeader = (NQ_BYTE *)cmMemoryAllocate(pcapFileHeaderSize);
		cmAnsiToUnicode(filename, NQ_CONFIGPATH);
		if (NQ_CONFIGPATH[syStrlen(NQ_CONFIGPATH) - 1] != SY_PATHSEPARATOR)
		{
			pathSep[0] = cmWChar(SY_PATHSEPARATOR);
			pathSep[sizeof(NQ_WCHAR)] = cmWChar(0);
			syWStrcat(filename, pathSep);
		}
		nameW = cmMemoryCloneAString(UD_CM_CAPTURE_FILENAME);
		syWStrcat(filename, nameW);
		cmMemoryFree(nameW);

		syDeleteFile(filename);
		file = syCreateFile(filename, FALSE, FALSE, FALSE);
		if (!syIsValidFile(file))
		{
			syPrintf("Could not create capture file:%s, error: %d\n", cmWDump(filename), syGetLastError());
			goto Exit;
		}

		totalPacketLen = pcapFileHeaderSize;
		syMutexCreate(&fileGuard);
		syMutexCreate(&staticGuard);
		preparePcapFile(pcapFileHeader);
		res = (NQ_UINT)writeToFile(pcapFileHeader , (NQ_UINT32)pcapFileHeaderSize);
		if (res != pcapFileHeaderSize)
		{
			syPrintf("Could not write pcap header to file, error: %d\n", syGetLastError());
			syCloseFile(file);
			syDeleteFile(filename);
			goto Exit;
		}

		initialized = TRUE;
	}
    result = TRUE;

Exit:
	cmMemoryFree(pcapFileHeader);
	return result;
}

void cmCaptureShutdown(void)
{
	if (initialized)
	{
		initialized = FALSE;
		syMutexDelete(&fileGuard);
		syMutexDelete(&staticGuard);
		syCloseFile(file);
	}
}

static NQ_INT writeToFile(const NQ_BYTE *buffer, NQ_UINT32 size)
{
	NQ_BOOL		cutPacket = FALSE;
	NQ_UINT 	remainingLen = totalPacketLen;
	NQ_INT		res;

	cutPacket = (cutPacketLen - totalPacketLen < size) ? TRUE : FALSE;
	syMutexTake(&staticGuard);
	totalPacketLen += (NQ_UINT)((cutPacket) ? (cutPacketLen - totalPacketLen) : size);
	syMutexGive(&staticGuard);
	res = syWriteFile(file , buffer , (NQ_COUNT)((cutPacket) ?  (cutPacketLen - remainingLen) : size));
	return res;
}

static void preparePcapFile(NQ_BYTE * buffer)
{
	CMBufferWriter	writer;

	cmBufferWriterInit(&writer , buffer , pcapFileHeaderSize);
#ifdef SY_BIGENDIANHOST
	cmBufferWriterSetByteOrder(&writer , FALSE); /* set buffer writer to stop rotating the value */
#endif /* SY_BIGENDIANHOST */
	cmBufferWriteBytes(&writer , pcapBlockOrderMagic , sizeof(pcapBlockOrderMagic));
	cmBufferWriteBytes(&writer , pcapBlockVersion , sizeof(pcapBlockVersion));
	cmBufferWriteZeroes(&writer , 8);
	cmBufferWriteBytes(&writer , pcapBlockSnapLen , sizeof(pcapBlockSnapLen));
	cmBufferWriteByte(&writer , 1);
	cmBufferWriteZeroes(&writer , 3);
}

static void preparePcapHeader(CMBufferWriter * writer , NQ_UINT length , NQ_BOOL isIpv6)
{
	NQ_UINT32	packetLen = (NQ_UINT32)length  + (NQ_UINT32)tcpHeaderLength + (NQ_UINT32)sizeof(ethernetHeader) + 2;
	NQ_UINT32   timeMicroSec = 0;

	packetLen += (NQ_UINT32)(isIpv6 ? ipv6HeaderLength : ipv4HeaderLength);
	cmBufferWriteUint32(writer , (NQ_UINT32)syGetTimeInSec());
	cmBufferWriteUint32(writer , timeMicroSec);
	cmBufferWriteUint32(writer , cmHtol32(packetLen));
	cmBufferWriteUint32(writer , cmHtol32(packetLen));
}

static NQ_BOOL prepareIpHeader(const CMCaptureHeader * header , CMBufferWriter * writer , NQ_UINT length)
{
	NQ_BOOL result = FALSE;

	switch (CM_IPADDR_VERSION(header->srcIP))
	{
#ifdef UD_NQ_USETRANSPORTIPV4
		case CM_IPADDR_IPV4:
		{
			cmBufferWriteByte(writer , IPv4Type);
			cmBufferWriteByte(writer  , 0);
			cmBufferWriteUint16(writer , (NQ_UINT16)cmHtob16(length + (NQ_UINT)ipv4HeaderLength + (NQ_UINT)tcpHeaderLength)); /* IP + TCP + Length*/
			cmBufferWriteUint16(writer , (NQ_UINT16)cmHtob16(IPv4Id));
			syMutexTake(&staticGuard);
			IPv4Id++;
			syMutexGive(&staticGuard);
			cmBufferWriteBytes(writer , IPv4Flags , sizeof(IPv4Flags));
			cmBufferWriteUint32(writer , header->receiving ?  CM_IPADDR_GET4(header->dstIP) : CM_IPADDR_GET4(header->srcIP));
			cmBufferWriteUint32(writer , header->receiving ?  CM_IPADDR_GET4(header->srcIP) : CM_IPADDR_GET4(header->dstIP));
			
			break;
		}
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
		case CM_IPADDR_IPV6:
		{
			NQ_INT i;
			cmBufferWriteByte(writer , IPv6Type);
			cmBufferWriteZeroes(writer  , 3);
			cmBufferWriteUint16(writer , (NQ_UINT16)cmHtob16(length + (NQ_UINT)(ipv6HeaderLength + tcpHeaderLength))); /* IP + TCP + Length*/
			cmBufferWriteByte(writer , IPv6NextHeaderTCP);
			cmBufferWriteByte(writer , 0x80); /* Hop Limit 128 */
			for (i = 0; i < 8; i++)
			{
				const NQ_UINT16 *	addr;

				addr = header->receiving ?  CM_IPADDR_GET6(header->dstIP) : CM_IPADDR_GET6(header->srcIP);
				cmBufferWriteUint16(writer , addr[i]);
			}
			for (i = 0; i < 8; i++)
			{
				const NQ_UINT16 *	addr;

				addr = header->receiving ?  CM_IPADDR_GET6(header->srcIP) : CM_IPADDR_GET6(header->dstIP);
				cmBufferWriteUint16(writer , addr[i]);
			}
			break;
		}
#endif /* UD_NQ_USETRANSPORTIPV6 */
		default:
		{
			goto Exit;
		}
	}
	result = TRUE;

Exit:
	return result;
}

static void prepareTcpHeader(const CMCaptureHeader * header , CMBufferWriter * writer , NQ_UINT length)
{

	cmBufferWriteUint16(writer , (NQ_UINT16)(header->receiving ?  cmHtob16(header->dstPort) : cmHtob16(header->srcPort)));
	cmBufferWriteUint16(writer , (NQ_UINT16)(header->receiving ? cmHtob16(header->srcPort) : cmHtob16(header->dstPort)));
	syMutexTake(&staticGuard);
	sequenceNumber += length;
	syMutexGive(&staticGuard);
	cmBufferWriteUint32(writer , cmHtob32(sequenceNumber));
	cmBufferWriteZeroes(writer , 4);
	cmBufferWriteByte(writer , tcpHeaderLen);
	cmBufferWriteByte(writer , tcpFlags);
	cmBufferWriteBytes(writer , tcpWindowSize , sizeof(tcpWindowSize));
	cmBufferWriteUint16(writer , 0);
	cmBufferWriteUint16(writer , 0);
	cmBufferWriteZeroes(writer , 12);
}

static void prepareNetBiosHeader(NQ_BYTE * buffer , NQ_UINT length)
{
	CMNetBiosSessionMessage * 	msgHeader;

	msgHeader = (CMNetBiosSessionMessage *)buffer;
	msgHeader->type = CM_NB_SESSIONMESSAGE;
	msgHeader->flags = (NQ_BYTE) (length >> 16) & CM_NB_SESSIONLENGTHEXTENSION;
	cmPutSUint16(msgHeader->length , syHton16((NQ_UINT16)length));
}

void cmCapturePacketWriteStart(const CMCaptureHeader * header ,NQ_UINT length)
{
	CMBufferWriter	writer;
	NQ_BYTE  		buffer[128]; /* packetHeaderLength */
	NQ_UINT32		packetHeaderLength = (NQ_UINT32)(pcapHeaderLen + ethernetHeaderLength  + tcpHeaderLength + netBiosHeaderLength);
	CMNetBiosSessionMessage	nbHeader;
	NQ_UINT16		totalLen = (NQ_UINT16)((length > maxPacketLen) ? cutPacketLen : length);
#ifndef UD_NQ_USETRANSPORTIPV6
	NQ_BOOL 		isIPv6 = CM_IPADDR_VERSION(header->srcIP) != CM_IPADDR_IPV4;
#else
	NQ_BOOL 		isIPv6 = CM_IPADDR_VERSION(header->srcIP) == CM_IPADDR_IPV6;
#endif /* UD_NQ_USETRANSPORTIPV6*/

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "header:%p len:%u", header, length);

	if (!initialized)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, " not initialized");
		goto Exit;
	}
	packetHeaderLength += (NQ_UINT32)(isIPv6 ? ipv6HeaderLength : ipv4HeaderLength);
	syMutexTake(&fileGuard);
	
	if (!captureWrite)
		captureWrite = TRUE;
	else
	{
		LOGERR(CM_TRC_LEVEL_ERROR, " capture start without ending first");
	}
	syMutexTake(&staticGuard);
	totalPacketLen = 0;
	syMutexGive(&staticGuard);

	cmBufferWriterInit(&writer , buffer , (NQ_COUNT)packetHeaderLength);
#ifdef SY_BIGENDIANHOST
	cmBufferWriterSetByteOrder(&writer , FALSE); /* set buffer writer to stop rotating the value */
#endif /* SY_BIGENDIANHOST */
	preparePcapHeader(&writer , (NQ_UINT)(totalLen + netBiosHeaderLength), isIPv6);
	cmBufferWriteBytes(&writer , ethernetHeader , sizeof(ethernetHeader));
	switch (CM_IPADDR_VERSION(header->srcIP))
	{
#ifdef UD_NQ_USETRANSPORTIPV4
		case CM_IPADDR_IPV4:
		{
			cmBufferWriteBytes(&writer , ethernetIPv4 , 2);
			break;
		}
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
		case CM_IPADDR_IPV6:
		{
			cmBufferWriteBytes(&writer , ethernetIPv6 , 2);
			break;
		}
#endif /* UD_NQ_USETRANSPORTIPV6 */
		default:
		{
			cmBufferWriteBytes(&writer , ethernetIPv4 , 2);
			break;
		}
	}
	prepareIpHeader(header , &writer , (NQ_UINT)(totalLen + netBiosHeaderLength));
	prepareTcpHeader(header , &writer , (NQ_UINT)(totalLen + netBiosHeaderLength));
	prepareNetBiosHeader((NQ_BYTE *)&nbHeader , totalLen);
	cmBufferWriteBytes(&writer , (NQ_BYTE *)&nbHeader , (NQ_COUNT)netBiosHeaderLength);

	writeToFile(buffer , packetHeaderLength);
	syMutexTake(&staticGuard);
	totalPacketLen = 0;
	syMutexGive(&staticGuard);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void cmCapturePacketWritePacket(NQ_BYTE * packet ,NQ_UINT length  )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "packet:%p len:%u", packet, length);
	if (!initialized)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, " not initialized");
		goto Exit;
	}
	writeToFile(packet , length);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void cmCapturePacketWriteEnd()
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	if (!initialized)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, " not initialized");
		goto Exit;
	}
    captureWrite = FALSE;
	syMutexGive(&fileGuard);	

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

#endif /* UD_NQ_INCLUDESMBCAPTURE */
