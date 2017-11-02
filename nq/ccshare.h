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

#ifndef _CCSHARE_H_
#define _CCSHARE_H_

#include "cmapi.h"
#include "ccserver.h"
#include "ccuser.h"

/* -- Defines -- */

/* Set when share is in DFS */
#define CC_SHARE_IN_DFS 1

/* -- Structures -- */

/* Description
   This structure describes a remote share.
   
   Since this structure inherits from <link CMItem> the share network name
   is designated as item name. 
   
   It is using unlock callback. It references the respective server. */
typedef struct _ccshare
{
	CMItem item;			/* List item. */
	CCUser * user;			/* Pointer to logon descriptor. */
	NQ_UINT32 tid;			/* Server-assigned tree ID. */
	NQ_BYTE type;			/* Share type as:
	             			     * Disk
	             			     * Pipe
	             			     * Print
	             			   This field is available in SMB2 only and is formatted as
	             			   defined in the SMB2 spec.
	             			   
	             			   \ \                                                      */
	NQ_UINT32 flags;		/* Flags in this field are dialect-specific.  */
	NQ_UINT32 access;		/* Maximal access in NT access format. */
	CMList files;			/* Open files. */
	CMList searches;		/* Open Searches*/
	struct _ccshare * dfsReferral;	/* DFS resolution result. Should be NULL when the share is not
	                              	   in DFS and non-NULL when the share is in DFS.               */
	NQ_BOOL connected;		/* TRUE when the share was successfully connected */
	NQ_BOOL isIpc;			/* TRUE when the share is IPC$ */
} CCShare; /* Remote share. */

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   <i>TRUE</i> on success and <i>FALSE</i> on failure.
 */
NQ_BOOL ccShareStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccShareShutdown(void);

/* Description
   Find share for a user providing tree ID
   
   Parameters
   pUser :         Pointer to the user object.
   tid :           Tree ID.
   Returns
   Pointer to the share object or NULL on error.        */
CCShare * ccShareFindById(CCUser * pUser, NQ_UINT32 tid);

/* Description
   Find share connection by its name.
   Parameters
   pServer :       Pointer to server to look shares on.
   path :          Full network path.
   treeName :      Name of the share to look for. This is share
                   name, not a network path.
   pUser:            Pointer to user.
   pCredentaisl :  Pointer to a variable which stores a pointer
                   to user credentials. See notes below.
   Returns
   Pointer to share descriptor or NULL if it was not found.
   Note
   The <i>pCredentials </i>argument is a pointer to a variable
   that stores pointer to credentials.
   
   If this variable is NULL on call to this function, it will
   prompt application for user credentials. Then, it will update
   the variable pointer by <i>pCredentials</i>.
   
   If this variable is not NULL on call, this function will
   first attempt to use the provided credentials. If operation
   does not succeed, it will prompt application for alternative
   credentials. If the latter succeeded, this function will
   replace the contents of the variable pointed by <i>pCredentisl</i>
   with a pointer to freshly allocated block of credentials.
   
   The code that calls this function is responsible for original
   credentials, the following is advised:
     * it should save the original pointer before the call
     * after the call compare the same variable with the
       original pointer
     * if they do not match, consider freeing new credentials.        */
CCShare * ccShareFind(CCServer * pServer, const NQ_WCHAR * path, const NQ_WCHAR * treeName, CCUser * pUser , const AMCredentialsW ** pCredentials);

/* Description
   Connect to the remote share using remote path.
   
   This call:
     * Finds a server object or creates it;
     * If server supports DFS &#45; resolves the path;
     * Finds or creates a share object;
   Parameters
   path :          Full network path. This path may be a path to
                   \file or folder.
   pCredentaisl :  Pointer to a variable which stores a pointer
                   to user credentials. See notes below.
   doDfs : Whether to perform DFS resolution.
   Returns
   Pointer to share descriptor or NULL on failure. Connecting to
   share may fail for the following reasons:
     * out of memory
     * cannot connect to the share.
   See Also
   <link ccShareFind@CCServer *@NQ_WCHAR *@NQ_WCHAR *@AMCredentialsW **, ccShareFind()>
   
   <link ccShareCreate@CCServer *@NQ_WCHAR *@NQ_WCHAR *@AMCredentialsW **, ccShareCreate()>
   Note
   The <i>pCredentials </i>argument is a pointer to a variable
   that stores pointer to credentials.
   
   If this variable is NULL on call to this function, it will
   prompt application for user credentials. Then, it will update
   the variable pointer by <i>pCredentials</i>.
   
   If this variable is not NULL on call, this function will
   first attempt to use the provided credentials. If operation
   does not succeed, it will prompt application for alternative
   credentials. If the latter succeeded, this function will
   replace the contents of the variable pointed by <i>pCredentisl</i>
   with a pointer to freshly allocated block of credentials.
   
   The code that calls this function is responsible for original
   credentials, the following is advised:
     * it should save the original pointer before the call
     * after the call compare the same variable with the
       original pointer
     * if they do not match, consider freeing new credentials.                             */
CCShare * ccShareConnect(const NQ_WCHAR * path, const AMCredentialsW ** pCredentials, NQ_BOOL doDfs);

/* Description
   Connect to the remote IPC share by server.
   
   If necessary, this call creates a share object.
   Parameters
   pServer :       Pointer to server to connect IPC share on.
   pCredentaisl :  Pointer to a variable which stores a pointer
                   to user credentials. See notes below.
   Returns
   Pointer to share descriptor or NULL on failure. Connecting to
   share may fail for the following reasons:
     * out of memory
     * cannot connect to the share.
   See Also
   <link ccShareFind@CCServer *@NQ_WCHAR *@NQ_WCHAR *@AMCredentialsW **, ccShareFind()>
   
   <link ccShareCreate@CCServer *@NQ_WCHAR *@NQ_WCHAR *@AMCredentialsW **, ccShareCreate()>
   Note
   The <i>pCredentials </i>argument is a pointer to a variable
   that stores pointer to credentials.
   
   If this variable is NULL on call to this function, it will
   prompt application for user credentials. Then, it will update
   the variable pointer by <i>pCredentials</i>.
   
   If this variable is not NULL on call, this function will
   first attempt to use the provided credentials. If operation
   does not succeed, it will prompt application for alternative
   credentials. If the latter succeeded, this function will
   replace the contents of the variable pointed by <i>pCredentisl</i>
   with a pointer to freshly allocated block of credentials.
   
   The code that calls this function is responsible for original
   credentials, the following is advised:
     * it should save the original pointer before the call
     * after the call compare the same variable with the
       original pointer
     * if they do not match, consider freeing new credentials.                             */
CCShare * ccShareConnectIpc(CCServer * pServer, const AMCredentialsW ** pCredentials);

/* Description
   Connect to the remote IPC share by server name using anonymous logon.
   
   If necessary, this call creates a share object.
   Parameters
   pServer :       Pointer to server to connect IPC share on.
   Returns
   Pointer to share descriptor or NULL on failure. Connecting to
   share may fail for the following reasons:
     * out of memory
     * cannot connect to the share.
   See Also
   <link ccShareFind@CCServer *@NQ_WCHAR *@NQ_WCHAR *@AMCredentialsW **, ccShareFind()>
   
   <link ccShareCreate@CCServer *@NQ_WCHAR *@NQ_WCHAR *@AMCredentialsW **, ccShareCreate()> */
CCShare * ccShareConnectIpcAnonymously(const NQ_WCHAR * server);

/* Description
   Disconnect from a share.
   
   Parameters
   pShare : Pointer to share object to disconnect from. 
   Returns
   None. */
void ccShareDisconnect(CCShare * pShare);

/* Description
   Connect to a share using existing share object.
   
   Parameters
   pShare : Pointer to share object to connect to. 
   doDfs : Whether to perform DFS resolution.
   Returns
   TRUE on success or FALSE on failure. */
NQ_BOOL ccShareConnectExisting(CCShare * pShare, NQ_BOOL doDfs);

/* Description
   Reopen file objects. 
   
   Parameters
   pShare : Pointer to share object to use. 
   Returns
   None. */
void ccShareReopenFiles(CCShare * pShare);
/* Description
   Echoes the server to which the share points to 
   
   Parameters
   pShare : Pointer to share object to use. 
   Returns
   Status returned from echo */
NQ_BOOL ccShareEcho(CCShare * pShare);


#endif /* _CCSHARE_H_ */
