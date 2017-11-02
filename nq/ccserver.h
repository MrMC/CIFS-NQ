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

#ifndef _CCSERVER_H_
#define _CCSERVER_H_

#include "cmapi.h"
#include "nsapi.h"
#include "cccifs.h"
#include "cctransport.h"
#include "amcredentials.h"

/* -- Capabilities -- */

/* Set when server chooses message signing. */
#define CC_CAP_MESSAGESIGNING 1
/* Set when server supports DFS. */
#define CC_CAP_DFS 2
/* Set when server supports passthrough information levels. */
#define CC_CAP_INFOPASSTHRU 4
	
/* Description
   This structure describes a remote server.
   
   Since this structure inherits from <link CMItem> the server network name
   is designated as item name. 
   
   Server is using unlock callback. */
typedef struct _ccserver
{
	CMItem item;				/* List item. */
	const NQ_WCHAR * calledName;/* Name of the server as it was called.
	                               
	                               It is not the same as host name since server may be called
	                               either by name or by IP. This value is used to withdraw
	                               credentials since application may use different credentials
	                               for calling by IP and by user name even though both designate
	                               the same host. */	                                                                                             
	const NQ_IPADDRESS * ips;   /* Pointer to server IP addresses. */
	NQ_COUNT numIps;			/* Number of IP addresses in the array above.*/
	CCTransport transport;		/* Transport object. */ 
	const CCCifsSmb * smb;		/* Pointer to SMB dialect descriptor. */
	void * smbContext;			/* Pointer to a block of dialect-dependent data. */
	CMList users;				/* List of logons to this server. */
	NQ_UINT32 capabilities;		/* Server capabilities and other flags. */
	NQ_UINT32 maxTrans;			/* Maximum query size that server accepts. */
	NQ_UINT32 maxRead;			/* Maximum read size that server accepts. */
	NQ_UINT32 maxWrite;			/* Max write size that server accepts. */
	NQ_BOOL useSigning;			/* Potentially use signing. TRUE when requests should be signed
								   and responses should be checked. This does not concern
								   capabilities. Signing will be in effect only when other
								   conditions are true. See <link ccServerUseSignatures@CCServer *, ccServerUseSignatures()>. */
    NQ_BOOL isLoggedIn;         /* <i>TRUE</i> when non anonymous user logged in - <i>FALSE<i> otherwise. */								   
	NQ_INT credits;			    /* Number of outstanding requests granted by server so far */
	CMBlob firstSecurityBlob;	/* this is a blob obtained on Negotiate response. When server (or client 
								   does not support extended security, this will be NULL blob. */
	NQ_BOOL useExtendedSecurity;/* <i>TRUE</i> to negotiate extended security - <i>FALSE<i> to hide it. */
    NQ_UINT16 vcNumber;         /* Virtual Circuit number to use with SMB. */
    CMList threads;             /* Waiting thread semaphore. */ 
    CMList async;               /* Outstanding async operation contexts. CCServer keeps track of 
                                   all outstanding contexts, so that on server release it will release lost ones. */
    CMList expectedResponses;   /* List of async matches , used to free them when connection is broken etc. */
    CMItem * masterUser;        /* Master user pointer - the one that will be used for signing (SMB1 only). */  
    NQ_BOOL     useName;        /* TRUE when you should use the server name to connect*/
    NQ_BOOL     isReconnecting; /* TRUE if server is already reconnecting , used to stop recursion on reconnect*/
    NQ_BOOL     userSecurity;   /* TRUE if security is set by user , FALSE if by share*/
    NQ_BOOL     isTemporary;    /* TRUE if used for temporary purpose (like ccRap functions), FALSE otherwise */
} 
CCServer; /* Remote server. */

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   <i>TRUE</i> on success and <i>FALSE</i> on failure.
 */
NQ_BOOL ccServerStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccServerShutdown(void);

/* Description
   Define whether traffic should be signed.
   Parameters
   server : Pointer to the server structure.
   Returns 
   TRUE for signed traffic, FALSE otherwise.
 */
NQ_BOOL ccServerUseSignatures(CCServer * server);

/* Description
   Disconnect server (on shutdown or reconnect).
   Parameters
   pServer : Pointer to the server object.
   Returns 
   None.
 */
void ccServerDisconnect(CCServer * pServer);

/* Description
   Either find a server or add new server descriptor and connect to the server.
   
   This call:
     * Creates and links a server object;
     * Connects server by either of the transports;
     * Conveys Negotiate.
   Parameters
   name :  Name of the server to create.
   extendedSecurity :  <i>TRUE</i> to attempt extended security, 
                       <i>FALSE</i> to restrict to low security.
   pDialect : Pointer to desired dialect, can be NULL
   Returns
   Pointer to server descriptor or NULL on failure. Creating a
   server may fail for the following reasons:
     * out of memory
     * cannot connect to the server.                          */
CCServer * ccServerFindOrCreate(const NQ_WCHAR * name, NQ_BOOL extendedSecurity, const CCCifsSmb *pDialect);

/* Description
   Connect a server that is not in the list.
   
   This call:
     * Connects server by either of the transports;
     * Conveys Negotiate.
   Parameters
   pServer : Pointer to the server object
   name :  Name of the server.
   Returns
   Pointer to server descriptor or NULL on failure. Creating a
   server may fail for the following reasons:
     * out of memory
     * cannot connect to the server.                          */
NQ_BOOL ccServerConnect(CCServer * pServer, const NQ_WCHAR * name);

/* Description
   Dispose all servers.
   
   This function disconnects all servers and disposes all server structures. 
   Returns 
   None.
 */
void ccServerDisconnectAll(void);

/* Description
   NQ calls this function when it suspects server disconnect.
   
   This call:
     * Checks the TCP connection;
     * If the connection was lost - reconnects TCP and;
       * Reconnects all users;  
   Parameters
   server : Pointer to the server structure.
   Returns 
   TRUE when server was reconnected, FALSE when TCP connection was not lost or NQ did not succeed to connect it again.
 */
NQ_BOOL ccServerReconnect(CCServer * server);

/* Description
   NQ calls this function to check server timeouts. When NQ encounters a server with expired timeout
   it disconnects and disposes it.
   
   Currently, NQ calls this function when establishing a new server.   
   Returns 
   None.
 */
void ccServerCheckTimeouts(void);

/* Description
   This function creates iterator for enumerating all servers.
   Parameters
   iterator : Pointer to the iterator that will be used for enumerating servers.
   Returns 
   None.
 */
void ccServerIterateServers(CMIterator * iterator);

/* Description
   This function creates iterator for enumerating all servers.
   Parameters
   server : Pointer to the server to iterate users on. 
   iterator : Pointer to the iterator that will be used for enumerating users on the given server.
   Returns 
   None.
 */
void ccServerIterateUsers(CCServer * server, CMIterator * iterator);

/* Description
   Place the current thread into the wait queue on the server semaphore.
   Parameters
   server : Server pointer.
   Returns
   TRUE if the thread was posted, FALSE on timeout. */
NQ_BOOL ccServerWaitForCredits(CCServer * server);

/* Description
   Continue the latest waiting thread. On an empty queue - do nothing.
   Parameters
   server : Server pointer.
   credits : number of credits granted
   Returns
   None. */
void ccServerPostCredits(CCServer * server, NQ_COUNT credits);



#ifdef SY_DEBUGMODE

/* Description
   Printout the list of servers.
   Returns 
   None
 */
void ccServerDump(void);

#endif /* SY_DEBUGMODE */

#endif /* _CCSERVER_H_ */
