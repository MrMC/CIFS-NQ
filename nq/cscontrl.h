/*********************************************************************
 *
 *           Copyright (c) 2010 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Control protocol for CIFS Server
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 4-Jan-2010
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSCONTRL_H_
#define _CSCONTRL_H_

#include "cmapi.h"

/* internal port for CIFS Server control */
#ifdef UD_CS_CONTROLPORT
#define CS_CONTROL_PORT  UD_CS_CONTROLPORT
#else /* UD_CS_CONTROLPORT */
#define CS_CONTROL_PORT  4445
#endif /* UD_CS_CONTROLPORT */

/* buffer size - determined as maximum of all protocol messages */
#define CS_CONTROL_MAXMSG   (   \
    sizeof(NQ_TCHAR) *          \
    (UD_FS_MAXSHARELEN +        \
     UD_FS_MAXPATHLEN +         \
     UD_FS_MAXDESCRIPTIONLEN    \
    ) +                         \
    4 * 20      \
                            )   
/* 
 * Control functions
 */

/* Description
   This function is called by application to stop the server and clean its resources.
   
   Returns
   This function returns NQ_SUCCESS or an error code.            */
NQ_STATUS csCtrlStop(void);

/* Description
   This function is called by application to restart the server.
   
   Returns
   This function returns NQ_SUCCESS or an error code.            */
NQ_STATUS csCtrlRestart(void);

/* Description
   This function is called by application to add another share to
   the NQ Server database.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   name :      Share name.
   path :  Local path to share. 
   isPrinter :   TRUE for a printer share, FALSE for a file share.
   comment : Share comment for display only. 
   Returns
   This function returns NQ_SUCCESS or an error code.            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define csCtrlAddShare csCtrlAddShareW
#else
    #define csCtrlAddShare csCtrlAddShareA
#endif
NQ_STATUS csCtrlAddShareA(const NQ_CHAR* name, const NQ_CHAR* path, NQ_BOOL isPrinter, const NQ_CHAR* comment); /* ASCII version */
NQ_STATUS csCtrlAddShareW(const NQ_WCHAR* name, const NQ_WCHAR* path, NQ_BOOL isPrinter, const NQ_WCHAR* comment); /* Unicode version */

/* Description
   This function is called by application to remove a share from
   the NQ Server database.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   name :      Share name.
   Returns
   This function returns NQ_SUCCESS or an error code.            */
/* remove share by name */
#ifdef UD_CM_UNICODEAPPLICATION
    #define csCtrlRemoveShare csCtrlRemoveShareW
#else
    #define csCtrlRemoveShare csCtrlRemoveShareA
#endif

NQ_STATUS csCtrlRemoveShareA(const NQ_CHAR* name);  /* ASCII version */
NQ_STATUS csCtrlRemoveShareW(const NQ_WCHAR* name); /* Unicode version */

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
/* Description
   This function is called by application to add another user to
   the NQ Server database.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   name :      Logon user name.
   fullName :  Display user name. 
   password :  Logon password.
   isAdmin :   TRUE for Administrator rights, FALSE for a
               regular user.
   Returns
   This function returns NQ_SUCCESS or an error code.            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define csCtrlAddUser csCtrlAddUserW
#else
    #define csCtrlAddUser csCtrlAddUserA
#endif
NQ_STATUS csCtrlAddUserA(const NQ_CHAR* name, const NQ_CHAR* fullName, const NQ_CHAR* description, const NQ_CHAR* password, NQ_BOOL isAdmin);   /* ASCII version */
NQ_STATUS csCtrlAddUserW(const NQ_WCHAR* name, const NQ_WCHAR* fullName, const NQ_WCHAR* description, const NQ_WCHAR* password, NQ_BOOL isAdmin);   /* Unicode version */

/* Description
   This function is called by application to remove a user from
   the NQ Server database.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   name :      Logon user name.
   Returns
   This function returns NQ_SUCCESS or an error code.            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define csCtrlRemoveUser csCtrlRemoveUserW
#else
    #define csCtrlRemoveUser csCtrlRemoveUserA
#endif
NQ_STATUS csCtrlRemoveUserA(const NQ_CHAR* name);   /* ASCII version */
NQ_STATUS csCtrlRemoveUserW(const NQ_WCHAR* name);  /* Unicode version */

/* Description
   This function is called by application to close deleted
   user's connections on NQ Server.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   name :          Logon user name.
   isDomainUser :  TRUE to consider a domain user, FALSE to
                   consider a local user.
   Returns
   This function returns NQ_SUCCESS or an error code.       */
#ifdef UD_CM_UNICODEAPPLICATION
    #define csCtrlCleanUserConnections csCtrlCleanUserConnectionsW
#else
    #define csCtrlCleanUserConnections csCtrlCleanUserConnectionsA
#endif
NQ_STATUS csCtrlCleanUserConnectionsA(const NQ_CHAR *name, NQ_BOOL isDomainUser);   /* ASCII version */
NQ_STATUS csCtrlCleanUserConnectionsW(const NQ_WCHAR *name, NQ_BOOL isDomainUser);   /* UNICODE version */

/* This structure contains user information and is used for
   enumerating users on NQ Server.
   Note
   The string parameters in this structure have NQ_TCHAR type
   which depends on the NQ compilation parameters. See <link References, Referenced Documents>. */
typedef struct 
{
    NQ_TCHAR name[256];        /* user name */
    NQ_TCHAR fullName[256];    /* full user name */
    NQ_TCHAR description[256]; /* user description */
    NQ_BOOL isAdmin;           /* TRUE for Administrator rights, FALSE for a regular user */
} 
CsCtrlUser;

/* Description
   This function is called to get user information from NQ
   Server.
   Parameters
   userEntry :  Pointer to a user information structure. See <link CsCtrlUser, CsCtrlUser Structure>
                for details.
   index :      Zero\-based user index. When index exceeds the
                number of logged user, this function returns
                error.
   Returns
   This function returns NQ_SUCCESS or an error code.                                              */
NQ_STATUS csCtrlEnumUsers(CsCtrlUser * userEntry, NQ_INDEX index);

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

/* This structure contains share information and is used for
   enumerating shares on NQ Server.
   Note
   The string parameters in this structure have NQ_TCHAR type
   which depends on the NQ compilation parameters. See <link References, Referenced Documents>. */
typedef struct 
{
    NQ_TCHAR name[UD_FS_MAXSHARELEN ];              /* share name */
    NQ_TCHAR path[UD_FS_MAXPATHLEN ];               /* the path on which the share is mapped  */
    NQ_BOOL isPrinter;                              /* TRUE for print queue, FALSE for a file share */
    NQ_TCHAR comment[UD_FS_MAXDESCRIPTIONLEN ];     /* share description */
} 
CsCtrlShare;

/* Description
   This function is called to get share information from NQ
   Server.
   Parameters
   shareEntry :  Pointer to a share information structure. See <link CsCtrlShare, CsCtrlShare Structure>
                 for details.
   index :       Zero\-based share index. When index exceeds the
                 number of installed shares, this function
                 \returns error.
   Returns
   This function returns NQ_SUCCESS or an error code.                                                    */
NQ_STATUS csCtrlEnumShares(CsCtrlShare * shareEntry, NQ_INDEX index);

/* This structure contains information about a client connection. It is used for
   enumerating client connections on NQ Server.
*/
typedef struct 
{
    NQ_IPADDRESS ip;    /* client IP */
    NQ_BOOL isSmb2;     /* TRUE for an SMB2 connection, FALSE for an SMB connection */
} 
CsCtrlClient;

/* Description
   This function is called to get client connection information from NQ
   Server.
   Parameters
   clientEntry :  Pointer to a client information structure. See <link CsCtrlClient, CsCtrlClient Structure>
                 for details.
   index :       Zero\-based share index. When index exceeds the
                 number of connected clients, this function
                 \returns error.
   Returns
   This function returns NQ_SUCCESS or an error code.                                                    */
NQ_STATUS csCtrlEnumClients(CsCtrlClient * clientEntry, NQ_INDEX index);

/* 
## Bitmap flags for enabling/disabling encryption methods 
*/

 /* This flag enables LM encryption method. */ 
#define CS_CONTROL_ENCRYPTION_LM        1  
/* This flag enables NTLM encryption method. */
#define CS_CONTROL_ENCRYPTION_NTLM      2   
/* This flag enables LMv2 encryption method. */ 
#define CS_CONTROL_ENCRYPTION_LMV2      4   
/* This flag enables NTLMv2 encryption method. */
#define CS_CONTROL_ENCRYPTION_NTLMV2    8   

#ifdef UD_CS_MESSAGESIGNINGPOLICY
/* Description
   This function is called to modify message signing policy in
   NQ Server.
   
   New messages signing policy affects new client connections
   and it does not affect already established connections.
   Parameters
   newPolicy :  New message signing policy. This argument should
                be one of the following values\:
                * 0 &#45; signing is disabled.
                * 1 &#45; signing is enabled,
                * 2 &#45; signing is required.
   Returns
   This function returns NQ_SUCCESS or an error code.            */
NQ_STATUS csCtrlSetMessageSigningPolicy(NQ_INT newPolicy);
#endif /* UD_CS_MESSAGESIGNINGPOLICY*/
/* Description
   This function is called to enable/disable encryption methods
   in NQ Server.
   Parameters
   mask :  Bitmap mask of enabled methods. It should be a bitwise
           combination of the flags defined in <link Encryption methods>.
   Returns
   This function returns NQ_SUCCESS or an error code.                     */
NQ_STATUS csCtrlSetEncryptionMethods(NQ_UINT mask);

/*
 * Protocol values
 */
#define CS_CONTROL_STOP 1
#define CS_CONTROL_RESTART 2
#define CS_CONTROL_ADDSHARE 3
#define CS_CONTROL_REMOVESHARE 4
#define CS_CONTROL_ENUMSHARES 5
#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
#define CS_CONTROL_ADDUSER 6
#define CS_CONTROL_REMOVEUSER 7
#define CS_CONTROL_CLEANUSERCONS 8
#define CS_CONTROL_ENUMUSERS 9
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */
#define CS_CONTROL_ENUMCLIENTS 10
#define CS_CONTROL_CHANGEENCRYPTION 11
#ifdef UD_CS_MESSAGESIGNINGPOLICY
#define CS_CONTROL_CHANGEMSGSIGN 12
#endif /* UD_CS_MESSAGESIGNINGPOLICY*/

/* 
 * Protocol definition (IDL)
 * ------------------------
 * 
 * Function [CS_CONTROL_STOP]:
 *      NQ_STATUS csControlStop (
 *          OUT NQ_UINT32 result
 *          );
 * Function [CS_CONTROL_RESTART]:
 *      NQ_STATUS csControlRestart (
 *          OUT NQ_UINT32 result
 *          );
 */

#endif /* _CSCONTRL_H_ */
