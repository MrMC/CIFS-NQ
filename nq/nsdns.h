/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Light-weight DNS client
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 31-Oct-2005
 * CREATED BY    : Alexey Yarovinsky
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#ifndef _NSDNS_H_
#define _NSDNS_H_

#define DNS_PORT       53       /* The UDP port used for DNS queries */
#define LLMNR_PORT     5355     /* The UDP port used for LLMNR queries */
#define DNS_TIMEOUT    4        /* Timeout for DNS requests in seconds */
#define DNS_QUERY      0x01
#define DNS_UPDATE     0x28
#define DNS_QUERY_RESPONSE 0x80
#define NS_DNS_CNAME   0x05
#define NS_DNS_SOA     0x06
#define DNS_REPLY_CODE 0xf
#define DNS_REPLY_CODE_NO_SUCH_NAME 0x3
#define DNS_REPLY_CODE_REFUSED 0x5
#define DNS_UPDATE_RESPONSE         0xa8

typedef struct
{
    NQ_UINT16 id;
    NQ_BYTE flags1;
    NQ_BYTE flags2;
    NQ_UINT16 questions;
    NQ_UINT16 answers;
    NQ_UINT16 authority;
    NQ_UINT16 additional;
}
DnsHeader;

void nsWriteDnsHeader(CMRpcPacketDescriptor * writer, const DnsHeader * pHeader);

void nsReadDnsHeader(CMRpcPacketDescriptor * reader, DnsHeader * pHeader);

void nsDnsEncodeName(CMRpcPacketDescriptor * writer, const NQ_CHAR *name);

NQ_STATUS nsDnsDecodeName(CMRpcPacketDescriptor * reader, NQ_CHAR * name);

NQ_CHAR * nsDnsCreateReversedName(const NQ_IPADDRESS * ip);

NQ_IPADDRESS *  nsDnsParseReversedName(NQ_CHAR * name , NQ_UINT16 type);

void nsDnsWriteAnswer(CMRpcPacketDescriptor * writer, const NQ_CHAR * string, NQ_UINT16 type , void * answer , NQ_UINT16 answerLen);

#endif /* _NSDNS_H_ */
