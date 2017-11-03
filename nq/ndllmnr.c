/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : LLMNR Resolver
 *--------------------------------------------------------------------
 * MODULE        : RD - Responder Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 08-Dec-2008
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ndllmnr.h"

#if defined UD_ND_INCLUDENBDAEMON && defined(UD_NQ_USETRANSPORTIPV4)

static SYSocketHandle 	LLMNRSocket;

void ndLLMNRSetSocket(SYSocketHandle socket)
{
	LLMNRSocket = socket;
}

NQ_STATUS
ndLLMNRProcessExternalMessage(
    NDAdapterInfo* adapter
    )
{
	CMBufferReader	reader;
	CMBufferWriter	writer;
	DnsHeader		headerIn, headerOut;
	NQ_INT 			j;
	NQ_STATUS       result = NQ_FAIL;

	syMemset(&headerOut,  0 , sizeof(DnsHeader));
	cmBufferReaderInit(&reader , adapter->inMsg , adapter->inLen);
	cmBufferReaderSetByteOrder(&reader , FALSE);

	nsReadDnsHeader(&reader , &headerIn);

	if (headerIn.questions == 0)
	{
		goto Exit;
	}

	for (j = 0; j < headerIn.questions; j++)
	{
		NQ_BYTE		*	queryPos;
		NQ_CHAR			name[CM_NQ_HOSTNAMESIZE];
		NQ_STATUS		res;
		NQ_UINT16		type;
		NQ_COUNT		queryLen;

		queryPos = cmBufferReaderGetPosition(&reader);
		if (nsDnsDecodeName(&reader, name) == NQ_FAIL)
            goto Exit;

		cmBufferReadUint16(&reader , &type);
		cmBufferReaderSkip(&reader , 2);

		if (type == NS_DNS_A)
		{
			if (syStrlen(name) < CM_NB_NAMELEN)
			{
				NQ_CHAR			NBname[CM_NQ_HOSTNAMESIZE];

				syStrcpy(NBname , name);

				if (ndLLMNRNameLookup(NBname) != NULL)
				{
					NQ_IPADDRESS  	ipAnswer;
					NQ_STATUS		res;

					syMemcpy(&headerOut , &headerIn , sizeof(DnsHeader));

					CM_IPADDR_ASSIGN4(ipAnswer , adapter->ip);
					headerOut.answers = 1;
					headerOut.flags1 = DNS_QUERY_RESPONSE;
					cmBufferWriterInit(&writer , adapter->outMsg ,CM_NB_DATAGRAMBUFFERSIZE );
					cmBufferWriterSetByteOrder(&writer , FALSE);

					nsWriteDnsHeader(&writer , &headerOut);

					queryLen = cmBufferReaderGetDataCount(&reader);
					cmBufferReaderSetPosition(&reader , queryPos);
					queryLen -= cmBufferReaderGetDataCount(&reader);
					cmBufferWriteBytes(&writer, cmBufferReaderGetPosition(&reader) , queryLen);

					nsDnsWriteAnswer(&writer , name, type , &CM_IPADDR_GET4(ipAnswer)  , sizeof(NQ_UINT32));

					CM_IPADDR_ASSIGN4(ipAnswer , adapter->inIp);
					res = sySendToSocket(LLMNRSocket,(NQ_BYTE*)adapter->outMsg,(NQ_UINT)cmBufferWriterGetDataCount(&writer),&ipAnswer,adapter->inPort);

					result = (res != NQ_FAIL ? NQ_SUCCESS : NQ_FAIL);
					goto Exit;

				}
			}
		}
		else if (type == NS_DNS_PTR)
		{
			NQ_IPADDRESS * qIp = NULL;
			NQ_CHAR			nameP[CM_NQ_HOSTNAMESIZE];

			syStrcpy(nameP , name);
			qIp = nsDnsParseReversedName(nameP ,CM_IPADDR_IPV4);

			if (qIp != NULL)
			{
				if (CM_IPADDR_EQUAL4(*qIp , adapter->ip))
				{
					NQ_IPADDRESS  	sendIp;

                    cmMemoryFree(qIp);
					syMemcpy(&headerOut , &headerIn , sizeof(DnsHeader));

					headerOut.answers = 1;
					headerOut.flags1 = DNS_QUERY_RESPONSE;
					cmBufferWriterInit(&writer , adapter->outMsg ,CM_NB_DATAGRAMBUFFERSIZE );
					cmBufferWriterSetByteOrder(&writer , FALSE);

					nsWriteDnsHeader(&writer , &headerOut);

					queryLen = cmBufferReaderGetDataCount(&reader);
					cmBufferReaderSetPosition(&reader , queryPos);
					queryLen -= cmBufferReaderGetDataCount(&reader);
					cmBufferWriteBytes(&writer, cmBufferReaderGetPosition(&reader) , queryLen);

					nsDnsWriteAnswer(&writer , name, type  ,(void *)cmNetBiosGetHostNameZeroed()  , (NQ_UINT16)syStrlen(cmNetBiosGetHostNameZeroed()));

					CM_IPADDR_ASSIGN4(sendIp , adapter->inIp);
					res = sySendToSocket(LLMNRSocket,(NQ_BYTE*)adapter->outMsg,(NQ_UINT)cmBufferWriterGetDataCount(&writer),&sendIp,adapter->inPort);
					result = ( res != NQ_FAIL ? NQ_SUCCESS : NQ_FAIL );
					goto Exit;
				}
                cmMemoryFree(qIp);
			}
		}
	}
	result = NQ_SUCCESS;

Exit:
	return result;
}

#endif /* UD_ND_INCLUDENBDAEMON && UD_NQ_USETRANSPORTIPV4*/
