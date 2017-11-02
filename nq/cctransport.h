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

#ifndef _CCTRANSPORT_H_
#define _CCTRANSPORT_H_

#include "cmapi.h"
#include "nsapi.h"

/* -- Typedefs -- */

/* Description
   Prototype for a callback function on SMB response.
   
   Transport calls this function when it encounters an incoming
   message in its select loop in the receive thread.
   Parameters
   transport : A transport object that was hit.  

   Returns
   None.                                                        */
typedef void (* CCTransportResponseCallback)(void * transport);

/* Description
   Prototype for a callback function on unexpected disconnect.
   
   Transport calls this function when it encounters an incoming
   message in its select loop in the receive thread.
   Parameters
   transport : A transport object that was hit.  

   Returns
   None.                                                        */
typedef void (* CCTransportCleanupCallback)(void * transport);

/* Description
   Transport entry.
   
   NQ creates transport entry per a TCP connection, i.e., one for
   a server object.  
*/
typedef struct _cctransport
{
	CMItem item;							/* List item. */
	NSSocketHandle socket;					/* Socket to listen on. */
	NSRecvDescr recv;						/* Receive descriptor. */
	CCTransportResponseCallback callback;	/* Function to call when data is available on this socket. */
	void * context;							/* Context to pass. */
	NQ_BOOL connected;						/* TRUE when the transport is connected. */
    NQ_TIME lastTime;                       /* last tramsit/receive timestamp for connection timeout */
	CCTransportCleanupCallback cleanupCallback;	
                                            /* Function to call on unexpected connection break. */
    void * cleanupContext;                  /* Context for the callback above. */
    NQ_BOOL isReceiving;                    /* TRUE when this transport is in receiving an SMB */
    SYMutex guard;                          /* Critical section guard for this transport. */
}
CCTransport;	/* Transport entry */	

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccTransportStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccTransportShutdown(void);

/* Description
   Initialize a transport object.
   Parameters
   transport : Pointer to the transport object to initialize.
   Returns
   None.   */
void ccTransportInit(CCTransport * transport);

/* Description
   Connects to a remote server.
   Parameters
   transport : Pointer to the transport object to use for this connection.
   ips :     Pointer to an array of IP addresses to try. 
   numIps :  Number of IP addresses.
   host : 	 Server host name.
   cleanupCallback : callback fucntion to call for connection cleanup
   cleanupContext : context for the function above
   Returns
   TRUE on success and FALSE on error.   */
NQ_BOOL ccTransportConnect(
    CCTransport * transport, 
    const NQ_IPADDRESS * ips, 
    NQ_INT numIps, 
    const NQ_WCHAR * host, 
    CCTransportCleanupCallback cleanupCallback,
    void * cleanupContext
    );

/* Description
   Check that transport has TCP connection. 
   Parameters
   transport : Pointer to the transport object to check.
   Returns
   TRUE when this object corresponds to an established TCP connection. FALSE when there was no connection established yet or it was dropped.   */
NQ_BOOL ccTransportIsConnected(CCTransport * transport);

/* Description
   Check that transport idle timeout has expired. 
   Parameters
   transport : Pointer to the transport object to check.
   Returns
   TRUE when this this transport connection was idle too long. FALSE otherwise.   */
NQ_BOOL ccTransportIsTimeoutExpired(CCTransport * transport);

/* Description
   Disconnects from a remote server.
   Parameters
   transport : Pointer to the transport object being used for this connection.
   Returns
   TRUE on success, FALSE on error.   */
NQ_BOOL ccTransportDisconnect(CCTransport * transport);

/* Description
   Lock transport so that it will be a critical section. No other thread will use it and all sends/receives will be contigous.
   
   transport :  Pointer to the transport object being used for
                this connection.
   Returns
   None.                                                                  */
void ccTransportLock(CCTransport * transport);

/* Description
   Unlock the transport thus ending a critical section on it so that other ttreads can use it.
   
   transport :  Pointer to the transport object being used for
                this connection.
   Returns
   None.                                                                  */
void ccTransportUnlock(CCTransport * transport);

/* Description
   Send request to server. This call may send entire request or
   just SMB header and structure.
   
   In contrary to the <link ccTransportSend@CCTransport *@NQ_BYTE *@NQ_COUNT@NQ_COUNT, ccTransportSend>()
   call, this call expects that the calling function will
   explicitly receive the response.
   Parameters
   transport :  Pointer to the transport object being used for
                this connection.
   buffer :     TCP payload to send.
   packetLen :  The length of the NBT packet. May be equal or
                less to the number bytes to send.
   dataLen :    Number of bytes to send. This value is equal to
                the above value or less. In the last case, the
                rest of the packet will be sent separately.
   Returns
   TRUE on success and FALSE on failure.                                                                  */
NQ_BOOL ccTransportSendSync(CCTransport * transport, const NQ_BYTE * buffer, NQ_COUNT packetLen, NQ_COUNT dataLen);

/* Description
   Send request to server. This call may send entire request or
   just SMB header and structure.
   
   This function expects that the response will be received in
   the receiving thread and delegated to the calling module
   through its callback function. See <link ccTransportConnect@CCTransport *@NQ_IPADDRESS *@NQ_INT@NQ_WCHAR *, ccTransportConnect()>.
   Parameters
   transport :  Pointer to the transport object being used for
                this connection.
   buffer :     TCP payload to send.
   packetLen :  The length of the NBT packet. May be equal or
                less to the number bytes to send.
   dataLen :    Number of bytes to send. This value is equal to
                the above value or less. In the last case, the
                rest of the packet will be sent separately.
   Returns
   TRUE on success and FALSE on failure.                                                                                              */
NQ_BOOL ccTransportSend(CCTransport * transport, const NQ_BYTE * buffer, NQ_COUNT packetLen, NQ_COUNT dataLen);

/* Description
   Send the tail (or a tail portion) of an NBT request to server.
   Parameters
   transport : Pointer to the transport object being used for this connection.
   data :     	Data to send.
   dataLen :  	Number of bytes to send. 
   Returns
   TRUE on success and FALSE on failure. */
NQ_BOOL ccTransportSendTail(CCTransport * transport, const NQ_BYTE * data, NQ_COUNT dataLen);

/* Description
   Set callback for response on the given socket.
   Parameters
   transport : Pointer to the transport object being used for this connection.
   callback : Routine to call on response on this socket.
   context : A context object to be supplied to the callback function.
   Returns
   None. */
void ccTransportSetResponseCallback(CCTransport * transport, CCTransportResponseCallback callback, void * context);

/* Description
   Remove callback for response on the given socket.
   Parameters
   transport : Pointer to the transport object being used for this connection.
   Returns
   None. */
void ccTransportRemoveResponseCallback(CCTransport * transport);

/* Description
   Receive NetBIOS header and the packet. The packet is received
   in an allocated buffer.
   
   This function assumes that the data is already on the socket
   (select was hit).
   Parameters
   transport : Pointer to the transport object being used for this connection.
   buffer :   Buffer to read data in.
   dataLen :  OUT\: buffer for the lengh of the received packet,
              not including NBT header.
   Returns
   Pointer to received buffer or NULL on error.                  */
NQ_BYTE * ccTransportReceiveAll(CCTransport * transport, NQ_COUNT * dataLen);

/* Description
   Receive NetBIOS header of the response and return packet
   length.
   
   This function assumes that the data is already on the socket
   (select was hit).
   
   Data can be received by calling <link ccTransportReceiveBytes@NSRecvDescr@NQ_BYTE *@NQ_COUNT, ccTransportReceiveBytes()>
   and <link ccTransportReceiveEnd@NSRecvDescr, ccTransportReceiveEnd()>.
   Parameters
   transport : Pointer to the transport object being used for this connection.
   Returns
   Number of bytes in the packet. On error it will have an NQ_FAIL value. */
NQ_INT ccTransportReceivePacketLength(CCTransport * transport);

/* Description
   Receive part of thge response in an outside buffer.
   
   This function assumes that <link ccTransportReceiveEnd@NSRecvDescr, ccTransportReceiveEnd()>
   will be called.
   Parameters
   transport : Pointer to the transport object being used for this connection.
   buffer :   Buffer to read data in.
   dataLen :  Number of bytes to receive.
   Returns
   Number of bytes reeceived or NQ_FAIL on error.                                                  */
NQ_COUNT ccTransportReceiveBytes(CCTransport * transport, NQ_BYTE * buffer, NQ_COUNT dataLen);

/* Description
   Discard the rest of response in an outside buffer.
   
   This function assumes that <link ccTransportReceivePacketLength@NSSocketHandle, ccTransportReceivePacketLength()>
   was called before.
   Parameters
   transport : Pointer to the transport object being used for this connection.
   buffer :   Buffer to read data in.
   dataLen :  Number of bytes to receive.
   Returns
   Number of bytes reeceived or NQ_FAIL on error.                                                  */
NQ_COUNT ccTransportReceiveEnd(CCTransport * transport);

/* Description
   Discard the response and wait for another response.
      
   Protocol calls this function when a response is not an expected one. For instance,
   this happens on SMB2 interim response.
   
   This fucntion should be only called in the receive thread. 
   Parameters
   transport : Pointer to the transport object being used for this connection.
   Returns
   None.                                                  */
void ccTransportDiscardReceive(CCTransport * transport);

#endif /* _CCTRANSPORT_H_ */
