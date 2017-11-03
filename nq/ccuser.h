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

#ifndef _CCUSER_H_
#define _CCUSER_H_

#include "cmapi.h"
#include "ccserver.h"
#include "ccapi.h"
#include "amcredentials.h"

/* -- Structures -- */

/* Description
   This structure describes user logon.
   
   Since this structure inherits from <link CMItem> the user name
   is designated as item name. 
   
   It is using unlock callback. It references the respective server. */
typedef struct _ccuser
{
	CMItem item;				        /* List item. */
	CMList shares;				        /* List of share connections under this logon. */
	CCServer * server;			        /* Pointer to remote server descriptor. */
	NQ_UINT64 uid;				        /* Server-assigned user ID */
    const AMCredentialsW * credentials; /* Pointer to user credentials. */
    NQ_BOOL isAnonymous;                /* TRUE when user is anonymous (empty credentials) */
	NQ_BOOL logged;				        /* TRUE when the user has logged. */
	CMBlob sessionKey;			        /* Session key - used for logons and later for message signing. Data is allocated. */
	CMBlob macSessionKey;		        /* MAC session key. Used for signing. Data is allocated. */
	NQ_BOOL isGuest;					/* TRUE when user is guest */
    NQ_BOOL isEncrypted;                /* TRUE when (global) data encryption is required for session (SMB3).*/
    NQ_BOOL isLogginOff;				/* TRUE when user is going to log off */
#ifdef UD_NQ_INCLUDESMB3
	CMBlob encryptionKey;
	CMBlob decryptionKey;
	CMBlob applicationKey;
#ifdef UD_NQ_INCLUDESMB311
	NQ_BOOL isPreauthIntegOn;	/* is pre-authentication integrity validation on*/
	NQ_BYTE preauthIntegHashVal[SMB3_PREAUTH_INTEG_HASH_LENGTH]; /* array to hold hash results of negotiate packets */
#endif /* UD_NQ_INCLUDESMB311 */
#endif /* UD_NQ_INCLUDESMB3 */
} CCUser; /* User logon. */

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccUserStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccUserShutdown(void);

/* Description
   Determine signing policy for user
   
   Parameters
   pUser :         Pointer to the user object to check.
                   to user credentials. See notes below.
   Returns
   <i>TRUE</i> when user should sign, <i>FALSE</i> otherwise.        */
NQ_BOOL ccUserUseSignatures(CCUser * pUser);

/* Description
   Find user on server providing user ID
   
   Parameters
   pServer :       Pointer to the server object.
   uid :           User ID.
   Returns
   Pointer to the user object or NULL on error.        */
CCUser * ccUserFindById(CCServer * pServer, NQ_UINT64 uid);

/* Description
   This function creates iterator for enumerating shares of this user.
   Parameters
   pUser :         Pointer to the user object.
   iterator : Pointer to the iterator that will be used for enumerating shares.
   Returns 
   None.
 */
void ccUserIterateShares(CCUser * pUser, CMIterator * iterator);

/* Description
   Obtain credentials for an anonymous connection.
   Returns
   Pointer to credentials structure with empty name, password and domain.                 */
const AMCredentialsW * ccUserGetAnonymousCredentials(void);

/* Description
   Check whether supplied credentials are for anonymous user.
   Returns
   TRUE if credentials are for anonymous user, FALSE otherwise.                 */
NQ_BOOL ccUserIsAnonymousCredentials(const AMCredentialsW *pCredentials);

/* Description
   Find or create a user
   
   This call:
     * If credentials were provided:
       * \  Attempts to find a user by provided credentials, or:
       * Creates a new user and attempts logon (SessionSetup)
       * On failure, behaves as no credentials were provided
         (see below).
     * If no credentials were provided (NULL), prompts
       application for credentials
       * \  Attempts to find a user by new credentials, or:
       * Creates a new user and attempts logon (SessionSetup).
   Parameters
   pServer :       Pointer to server to create share on.
   path :          Full network path, including share name.
   pCredentaisl :  Pointer to a variable which stores a pointer
                   to user credentials. See notes below.
   Returns
   Pointer to user descriptor or NULL on failure. Creating a
   user may fail for the following reasons:
     * out of memory
     * cannot logon to the server.
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
CCUser * ccUserGet(CCServer * pServer, const NQ_WCHAR * path, const AMCredentialsW ** pCredentials);

/* Description
   Explicitly log off the user.
   
   This sanity call may be called even when server is
   disconnected, so that we do not care about its result.
   Parameters
   pUser :  Pointer to the user object.
   Returns
   None.                                                  */
void ccUserLogoff(CCUser * pUser);

/* Description
   Explicitly log on the user.
   Parameters
   pUser :  Pointer to the user object.
   Returns
   TRUE on success or FALSE on failure. */
NQ_BOOL ccUserLogon(CCUser * pUser);

/* Description
   Reconnect existing shares.
   Parameters
   pUser :  Pointer to the user object.
   Returns
   TRUE on success or FALSE on failure. */
NQ_BOOL ccUserReconnectShares(CCUser * pUser);

/* Description
   Set administrative credentials and use them.
   Parameters
   credentials : Pointer to administrative credentials. If this pointer is not NULL, NQ 
                 continues to use those credentials instead of asking the application. When
                 this parameter is NULL, NQ reverts to asking the application for 
                 credentials. 
   Returns
   None. 
   Notes
   NQ assumes a critical section between */
void ccUserSetAdministratorCredentials(const AMCredentialsW * credentials);

/* Description
   Get administrative credentials and use them.
   Parameters
   Returns
   Pointer to administrative credentials. If this pointer is not NULL, NQ 
   continues to use those credentials instead of asking the application. When
   this parameter is NULL, NQ reverts to asking the application for 
   credentials. 
   Notes
   NQ assumes a critical section between */
const AMCredentialsW * ccUserGetAdministratorCredentials();

#endif /* _CCUSER_H_ */
