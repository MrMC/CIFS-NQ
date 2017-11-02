/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : API defintion for this module
 *                 (this is the only file other modules should include)
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NSAPI_H_
#define _NSAPI_H_

#include "cmapi.h"

/********************************************************************
 *      Datatypes & constants
 *      _____________________
 *
 ********************************************************************/

typedef NQ_HANDLE NSSocketHandle;       /* socket ID (descriptior) */
typedef SYSocketSet NSSocketSet;        /* set of sockets for select */

typedef struct      /* internet address (name) structure is used in
                       nsSendTo when the socket is an Internet socket */
{
    NQ_IPADDRESS   ip;     /* IP address */
    NQ_PORT        port;   /* port */
}
NSInternetName;

typedef
void                        /* pointer to callback function for asynchronous buffer release */
(*NSReleaseCallback)(
    const NQ_BYTE* buf      /* buffer to release */
    );

/* Available transport values */

#define NS_TRANSPORT_NETBIOS 1
#define NS_TRANSPORT_IPV4    2
#define NS_TRANSPORT_IPV6    3

/* Available types for socket creation */

#define NS_SOCKET_STREAM 1      /* TCP socket                               */
#define NS_SOCKET_DATAGRAM 2    /* UDP socket                               */

/********************************************************************
 *      Function prototypes
 ********************************************************************
 *
 * The functions below suport BSD socket functionality
 *
 ********************************************************************/

NSSocketHandle
nsSocket(
    NQ_UINT type,     /* socket type */
    NQ_UINT transport /* socket transport */
    );

NQ_STATUS
nsRegisterName(
    const CMNetBiosNameInfo* name   /* pointer to NetBIOS name to register */
    );

NQ_STATUS
nsReleaseName(
    const CMNetBiosNameInfo* name   /* pointer to NetBIOS name to unregister */
    );

NQ_STATUS
nsBindNetBios(
    NSSocketHandle socket,          /* socket descriptor */
    const CMNetBiosNameInfo* name   /* pointer to NetBIOS name */
    );

NQ_STATUS
nsBindInet(
    NSSocketHandle socket,          /* socket descriptor */
    NQ_IPADDRESS *ip,               /* IP address to bind to socket */
    NQ_PORT port                    /* port to bind to socket */
    );

NQ_STATUS
nsClose(
    NSSocketHandle fd               /* socket to close */
    );

NQ_STATUS
nsConnect(
    NSSocketHandle socket,          /* socket to connect on */
    NQ_IPADDRESS *ip,               /* IP of the remote host */
    CMNetBiosNameInfo* name         /* called name as a NetBIOS name */
    );

NQ_STATUS
nsListen(
    NSSocketHandle socket,      /* socket to listen on */
    NQ_INT backlog              /* listen queue length */
    );

NSSocketHandle
nsAccept(
    NSSocketHandle socket,      /* socket to accept calls on */
    NQ_IPADDRESS *ip            /* ip of the peer */
    );

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_STATUS
nsPostAccept(
    NSSocketHandle *socket      /* socket to accept SESSION REQUEST on */
    );

#endif /* UD_NQ_USETRANSPORTNETBIOS */

NQ_INT
nsSelect(
    NSSocketSet* set,           /* read set */
    NQ_TIME timeout             /* timeout in sec */
    );

NQ_INT
nsRecv(
    NSSocketHandle socket,      /* receiving socket */
    NQ_BYTE *buf,               /* buffer for incoming data */
    NQ_UINT buflen              /* buffer length */
    );

NQ_INT
nsRecvFrom(
    NSSocketHandle socket,  /* receiving socket */
    NQ_BYTE *buf,           /* buffer for incoming data */
    NQ_UINT buflen,         /* buffer length */
    NQ_IPADDRESS* ip        /* source IP will be written here */
    );

NQ_INT
nsRecvFromName(
    NSSocketHandle socket,  /* receiving socket */
    NQ_BYTE *buf,           /* buffer for incoming data */
    NQ_UINT buflen,         /* buffer length */
    CMNetBiosNameInfo* name /* calling name */
    );

NQ_INT
nsSend(
    NSSocketHandle socket,          /* sending socket */
    const NQ_BYTE *data,            /* data to send */
    NQ_UINT datalen                 /* data length */
    );

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_INT
nsSendTo(
    NSSocketHandle socket,              /* sending socket */
    const NQ_BYTE *data,                /* data to send */
    NQ_UINT datalen,                    /* data length */
    const CMNetBiosNameInfo* calledName,/* name to call */
    NQ_IPADDRESS *dstIp                 /* called IP address */
    );

NQ_INT
nsSendToName(
    NSSocketHandle socket,          /* sending socket */
    const NQ_BYTE *data,            /* data to send */
    NQ_UINT datalen,                /* data length */
    CMNetBiosNameInfo* name         /* called name */
    );

#endif /* UD_NQ_USETRANSPORTNETBIOS */

NQ_INT
nsSendFromBuffer(
    NSSocketHandle socket,      /* socket to write on */
    NQ_BYTE *buffer,            /* buffer to use */
    NQ_UINT packetlen,          /* packet length */
    NQ_UINT dataCount,          /* data length (may the entire packet data or just headers with no payload) */
    NSReleaseCallback release   /* callback function releasing the buffer */
    );

typedef struct 
{
    NSSocketHandle socket;  /* socket to read from */
    NQ_COUNT remaining;		/* remaing bytes in the NBT packet */
}
NSRecvDescr;

NQ_INT						/* Number of bytes remaining or NQ_FAIL on error. A zero value mmeans a control message. */
nsStartRecvIntoBuffer(
    NSSocketHandle socket,  /* socket to read from */
    NSRecvDescr * descr		/* receive descriptor */ 
    );

NQ_STATUS					/* NQ_SUCCESS or NQ_FAIL on error */
nsEndRecvIntoBuffer(
    NSRecvDescr * descr		/* receive descriptor */ 
    );

NQ_INT
nsRecvIntoBuffer(
    NSRecvDescr * descr,	/* receive descriptor */ 
    NQ_BYTE *buf,           /* buffer to use */
    NQ_COUNT len			/* max number of bytes to receive */
    );

NQ_BYTE*
nsSkipHeader(
    NSSocketHandle socket,  /* socket to write to */
    NQ_BYTE *buf            /* buffer to use */
    );

/********************************************************************
 *      Socket-set calls
 ********************************************************************/

NQ_BOOL
nsAddSocketToSet(
    NSSocketSet* set,       /* set to add socket for */
    NSSocketHandle socket   /* socket to add */
    );

NQ_BOOL
nsSocketInSet(
    NSSocketSet* set,       /* set to inspect */
    NSSocketHandle socket   /* socket to look for */
    );

void
nsClearSocketSet(
    NSSocketSet* set        /* set to clear */
    );

/********************************************************************
 *      Additional functionality
 ********************************************************************/

NQ_STATUS                         /* get host IP by its name */
nsGetHostByName(
    NQ_IPADDRESS *hostIp,         /* OUT: ip adresss */
    CMNetBiosNameInfo *nameInfo   /* IN: name to resolve,
                                         the group flag of this name will be revealed */
    );

NQ_STATUS                         /* PURPOSE: Get host name by its IP */
nsGetHostName(
    NQ_IPADDRESS *hostIp,         /* IN: ip adresss */
    CMNetBiosNameInfo* hostName   /* OUT: name to return on sucess */
    );

NQ_BOOL                     /* check socket availability */
nsIsSocketAlive(
    NSSocketHandle socket   /* socket to check */
    );

SYSocketHandle
nsGetSySocket(
    NSSocketHandle socket   /* socket */
    );

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)

/********************************************************************
 *      DNS functionality
 ********************************************************************/

#define NS_DNS_A    0x01 /* A - Host record - IPv4 address */
#define NS_DNS_AAAA 0x1c /* AAAA - IPv6 Host record - IPv6 address */
#define NS_DNS_SRV  0x21 /* SRV - Service Location - service provider address */
#define NS_DNS_PTR  0x0c /* *PTR - Domain Name Pointer */
#define NS_DNS_TKEY 0xf9 /* TKEY - Authentication */

NQ_STATUS                /* Initializes the DNS client */
nsDnsInit(
    void
    );

void                     /* Shutdown the DNS client */
nsDnsExit(
    void
    );

NQ_STATUS                /* Asks the DNS server for host responsible for the given service */
nsDnsGetHostNameByService(
    const NQ_CHAR *service, /* Service name */
    NQ_CHAR *name           /* Service provider host name */
    );

NQ_STATUS                /* Updates the DNS with address of the target */
nsDnsSetTargetAddresses(
    void                 
    );

NQ_STATUS                /* Clears from the DNS address of the target */
nsDnsClearTargetAddress(
    NQ_BYTE type         /* Recods type: one of NS_DNS_A, NS_DNS_AAAA or NS_DNS_SRV */
    );

#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/********************************************************************
 *      Initialization and shutdown
 *  Subsequent calls to nsInit are allowed yet have no effect
 ********************************************************************/

void                /* prepare for nsInit() */
nsInitGuard(
    void
    );

void                /* dispose guard */
nsExitGuard(
    void
    );

NQ_STATUS           /* initialize NS for the current task */
nsInit(
    NQ_BOOL createSocket    /* whether to create "common" datagram socket */
    );

NQ_STATUS           /* stop using NS by the current task */
nsExit(
    NQ_BOOL reg     /* the same value that was passed in nsInit() */
    );

NQ_STATUS           /* start NSMessage (should not be called from other then NS */
nsInitMessage(
    void
    );

void                /* release NSMessage (should not be called from other then NS */
nsExitMessage(
    void
    );

NQ_BYTE*
nsGetBuffer(
    void
    );                      /* take a buffer from the pool */

void
nsPutBuffer(
    NQ_BYTE *buffer
    );                      /* return a buffer to the pool */

void
nsResetBufferPool(
    void
    );                      /* reset buffer pool to ist initial state */ 

/* get send datagram buffer */

NQ_BYTE*
nsGetSendDatagramBuffer(
    void
    );

/* return send datagram buffer */

void
nsPutSendDatagramBuffer(
    void
    );

/* get receive datagram buffer */

NQ_BYTE*
nsGetRecvDatagramBuffer(
    void
    );

/* return receive datagram buffer */

void
nsPutRecvDatagramBuffer(
    void
    );

/********************************************************************
 *  Common datagram listening socket management (common for browser
 *  client and pass-through authentication)
 ********************************************************************/

NSSocketHandle
nsGetCommonDatagramSocket(
    void
    );

/********************************************************************
 *  Resolver callbacks
 ********************************************************************/

NQ_STATUS nsRequestByNameWins(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    );         

NQ_STATUS nsRequestByNameBcast(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    );         

NQ_STATUS nsResponseByName(
    SYSocketHandle socket, 
    NQ_IPADDRESS ** pAddressArray, 
    NQ_INT * numIps, 
    void ** pContext
    );

NQ_STATUS nsRequestByIp(
    SYSocketHandle socket, 
    const NQ_IPADDRESS * ip, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    );

NQ_STATUS nsRequestByIp(
    SYSocketHandle socket, 
    const NQ_IPADDRESS * ip, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    );

NQ_STATUS nsResponseByIp(
    SYSocketHandle socket, 
    const NQ_WCHAR ** pName, 
    void ** pContext
    );

#endif  /* _NSAPI_H_ */
