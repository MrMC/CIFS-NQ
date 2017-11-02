/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : API functions (envelope only)
 *--------------------------------------------------------------------
 * MODULE        : UD - user defined
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 6-Jun-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include <string.h>
#include <stdio.h>

#include "sycompil.h" // ITA - debug
#include "cmapi.h"
#include "amapi.h" // ITA - debug
#include "nqapi.h"
#include "udconfig.h"
#ifdef UD_NQ_INCLUDECIFSCLIENT
#include "ccapi.h"
#endif

/*
  This file contains a formal implementation of UD functions.

  The functions are placeholders that delegate the call to a sample
  implementation. User is supposed to change some of them
 */

/*
 *====================================================================
 * PURPOSE: initialize the CIFS configuration
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS on success or NQ_FAIL on error
 *
 * NOTES:   Inits this module
 *====================================================================
 */

NQ_STATUS
udInit(
    void
    )

{
    return udDefInit();
}

/*
 *====================================================================
 * PURPOSE: stop the CIFS configuration
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udStop(
    void
    )

{
    udDefStop();
}

/*
 *====================================================================
 * PURPOSE: Signal to the user level of CIFS server start
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   NQ calls this function after NQ Server is ready
 *          This implementation is a placeholder
 *====================================================================
 */

#ifdef UD_CS_INCLUDERPC_SPOOLSS
NQ_BOOL
syInitPrinters(
    void
    );
#endif

void joinDomain(void);

#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP
#if 0 // ITA - debug
static
#endif // ITA - debug//
void
joinDomain(void)
{
    if (!udGetComputerSecret(NULL))
    {
#if 1 // ITA - debug
        AMCredentialsA admin;
#else // ITA - debug
        CCCredentialsA admin;
#endif // ITA - debug
        NQ_BYTE secret[16];
        const NQ_CHAR *domain;

        /* setup domain administrator account information */
        if ((domain = cmGetFullDomainName()) == NULL)
            domain = cmNetBiosGetDomain()->name;
        syMemset(&admin, 0, sizeof(admin));
        syStrcpy(admin.domain.name, domain);
        /* change the credentials below to match your administrative name/password */
#if 1 // ITA - debug
        syStrcpy(admin.user, "administrator");
#else // ITA - debug
        syStrcpy(admin.name, "administrator");
#endif // ITA - debug
        syStrcpy(admin.password, "password");
       
        /* join domain and store secret */
        if (ccDomainJoinA(domain, cmNetBiosGetHostNameZeroed(), &admin, secret))
        {
            ccCloseAllConnections();
            udSetComputerSecret(secret);
        }
    }
}
#endif 
/*
void
udCifsServerStarted(
    void
    )
{
#ifdef UD_CS_INCLUDERPC_SPOOLSS
    static NQ_CHAR *ok = "printer installed";
#endif
    static NQ_CHAR *failure = "no printer";

    NQ_CHAR *result = failure;

#ifdef UD_CS_INCLUDERPC_SPOOLSS
    printf("NQCS: initializing printers...\n");

    if (syInitPrinters())
    {
        printf("NQCS: adding printer share...\n");

        if (nqAddShareA("printer", "/dev/usb/lp0", TRUE, "Shared printer", "") == 0)
            result = ok;
    }
#endif

#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP
    joinDomain();
#endif

    printf("NQCS: server is ready (%s)\n", result);
}
*/
/*
 *====================================================================
 * PURPOSE: Signal to the user level of CIFS server shutdown
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   NQ calls this function after NQ Server is closed and may be restarted
 *          This implementation is a placeholder
 *====================================================================
 */
/*
void
udCifsServerClosed(
    void
    )
{
    printf("\n---- NQ Server was shut down ---\n");
}
*/
/*
 *====================================================================
 * PURPOSE: Signal to the user level of NetBios Daemon start
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   NQ calls this function after NetBios Daemon is ready
 *          This implementation is a placeholder
 *====================================================================
 */
/*
void
udNetBiosDaemonStarted(
    void
    )
{
}
*/
/*
 *====================================================================
 * PURPOSE: Signal to the user level of NetBios Daemonshutdown
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   NQ calls this function after NetBios Daemon is closed and may be restarted
 *          This implementation is a placeholder
 *====================================================================
 */
/*
void
udNetBiosDaemonClosed(
    void
    )
{
}
*/
/*
 *====================================================================
 * PURPOSE: Signal to the user level of Browser Daemon start
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   NQ calls this function after Browser Daemon is ready
 *          This implementation is a placeholder
 *====================================================================
 */
/*
void
udBrowserDaemonStarted(
    void
    )
{
}
*/
/*
 *====================================================================
 * PURPOSE: Signal to the user level of Browser Daemon shutdown
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   NQ calls this function after Browser Daemon closed and may be restarted
 *          This implementation is a placeholder
 *====================================================================
 */
/*
void
udBrowserDaemonClosed(
    void
    )
{
}
*/
/*
 *====================================================================
 * PURPOSE: get scope id
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the result
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udGetScopeID(
    NQ_TCHAR *buffer
    )
{
    udDefGetScopeID(buffer);
}

/*
 *====================================================================
 * PURPOSE: get WINS address
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: WINS address or 0
 *
 * NOTES:   returns wins address if on the same subnetwork
 *====================================================================
 */

NQ_IPADDRESS4
udGetWins(
    void
    )
{
    return udDefGetWins();
}

/*
 *====================================================================
 * PURPOSE: get domain name
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the result
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udGetDomain(
    NQ_TCHAR *buffer,
    NQ_BOOL  *isWorkgroup
    )
{
    udDefGetDomain(buffer, isWorkgroup);
}

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
/*
 *====================================================================
 * PURPOSE: get DNS initialization parameters
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the default domain target belongs to
 *          OUT The DNS server IP address
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udGetDnsParams(
    NQ_TCHAR *domain,
    NQ_TCHAR *server
    )
{
    udDefGetDnsParams(domain, server);
}
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/*
 *====================================================================
 * PURPOSE: get authentication parameters
 *--------------------------------------------------------------------
 * PARAMS:  IN: URI the CIFS client is about to connect to
 *          OUT buffer for user name
 *          OUT buffer for password
 *          OUT buffer for domain name
 *
 * RETURNS: TRUE - success
 *          FALSE - fail
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udGetCredentials(
    const void* resource,
    NQ_TCHAR* userName,
    NQ_TCHAR* password,
    NQ_TCHAR* domain
    )
{
    return udDefGetCredentials(resource, userName, password, domain);
}

/*
 *====================================================================
 * PURPOSE: Determine fielsystem for the given share
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the share name
 *          IN pointer to the share path
 *          OUT buffer for the filesytem name
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udGetFileSystemName(
    const NQ_TCHAR* shareName,
    const NQ_TCHAR* sharePath,
    NQ_TCHAR* fileSystemName
    )
{
    cmAnsiToTchar(fileSystemName, UD_FS_FILESYSTEMNAME);
}

/*
 *====================================================================
 * PURPOSE: get next share in the list of shares for CIFS sServer
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for share name
 *          OUT buffer for the local path
 *          OUT pointer to variable getting 0 for file system share and 1 for a print queue
 *          OUT buffer for the share description
 *
 * RETURNS: TRUE - next share read
 *          FALSE - no more shares
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udGetNextShare(
    NQ_TCHAR* name,
    NQ_TCHAR* map,
    NQ_BOOL* printQueue,
    NQ_TCHAR* description
    )
{
    return udDefGetNextShare(name, map, printQueue, description);
}

/*
 *====================================================================
 * PURPOSE: get next mount in the list of mounted volumes for CIFS
 *          Client
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for volume name
 *          OUT buffer for the map path
 *
 * RETURNS: TRUE - a mount read FALSE - no more mounts
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udGetNextMount(
    NQ_TCHAR* name,
    NQ_TCHAR* map
    )
{
    return udDefGetNextMount(name, map);
}

/*
 *====================================================================
 * PURPOSE: get transport priority
 *--------------------------------------------------------------------
 * PARAMS:  transport - the transport identifier
 *
 * RETURNS: transport priority
 *   0 - the transport isn't used
 *   1..3 - the bigger number is highest priority
 *   if more then one transport has same priority
 *   built in order is used: IPv6, IPv4, NetBIOS
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
udGetTransportPriority(
    NQ_UINT transport
    )
{
    /* default implementation returns the same priority for all transports */

    return 1 ;

    /* for redefining one or more priorities:
        1) comment the previous operator
        2) uncomment switch statement
        3) leave cases for those transports that should be redefined
        4) place appropriate priorities (0,1,2,3) instead of ???
    */

    /*    switch (transport)
      {
          case NS_TRANSPORT_NETBIOS:
              return ???;

          case NS_TRANSPORT_IPV4
              return ???;

          case NS_TRANSPORT_IPV6
              return ???;

          default:
              return 0;
    }
    */
}

/*
 *====================================================================
 * PURPOSE: get task priority
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: task priority
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
udGetTaskPriorities(
    void
    )
{
    return udDefGetTaskPriorities();
}

/*
 *====================================================================
 * PURPOSE: get server comment string
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the result
 *
 * RETURNS: None
 *
 * NOTES:
 *
 *====================================================================
 */

void
udGetServerComment(
    NQ_TCHAR *buffer
    )
{
    udDefGetServerComment(buffer);
}

/*
 *====================================================================
 * PURPOSE: get next user name and password from the list of passwords
 *--------------------------------------------------------------------
 * PARAMS:  IN login name
 *          OUT buffer for password
 *          OUT TRUE if the password is hashed, FALSE - otherwise
 *          OUT user number while administrative users have numbers < 0
 *
 * RETURNS: NQ_CS_PWDFOUND - user found equivalent to 3 (deprecated)
 *          NQ_CS_PWDNOAUTH - authentication is not required
 *          NQ_CS_PWDNOUSER - no such user
 *          NQ_CS_PWDLMHASH - user found and password is LM hash (*pwdIsHashed value has to
 *              be TRUE in this case)
 *          NQ_CS_PWDANY - user found and password is either LM and NTLM hash or plain
 *              text depending on the *pwdIsHashed value
 *
 * NOTES:   Opens the file, parses it and stores parameter values if
 *          those parameters were found. User number is returned as ID from
 *          the pwd file
 *====================================================================
 */

NQ_INT
udGetPassword(
    const NQ_TCHAR* userName,
    NQ_CHAR* password,
    NQ_BOOL* pwdIsHashed,
    NQ_UINT32* userNumber
    )
{
    return udDefGetPassword(userName, password, pwdIsHashed, userNumber);
}


/*
 *====================================================================
 * PURPOSE: return driver name
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for the result
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udGetDriverName(
    NQ_CHAR *buffer
    )
{
    udDefGetDriverName(buffer);
}

/*
 *====================================================================
 * PURPOSE: project-level processing on incoming data to NetBios Daemon
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   Include any project-level processing here
 *====================================================================
 */

void
udNetBiosDataIn(
    void
    )
{
}

/*
 *====================================================================
 * PURPOSE: project-level processing on incoming data to NQ Server
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   Include any project-level processing here
 *====================================================================
 */

void
udServerDataIn(
    void
    )
{
}

/*
 *====================================================================
 * PURPOSE: project-level processing on client connection to a share
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: None
 *
 * NOTES:   Include any project-level processing here
 *====================================================================
 */

void
udServerShareConnect(
    const NQ_TCHAR* share
    )
{
}

/*
 *====================================================================
 * PURPOSE: project-level processing on client disconnect from a share
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: None
 *
 * NOTES:   Include any project-level processing here
 *====================================================================
 */

void
udServerShareDisconnect(
    const NQ_TCHAR* share
    )
{
}

/*
 *====================================================================
 * PURPOSE: allocate buffer in the user space
 *--------------------------------------------------------------------
 * PARAMS:  IN buffer index zero based
 *          IN total number of buffers
 *          IN buffer size in bytes
 *
 * RETURNS: pointer to the buffer
 *
 * NOTES:   Include any project-level processing here
 *====================================================================
 */

NQ_BYTE*
udAllocateBuffer(
    NQ_INT idx,
    NQ_COUNT numBufs,
    NQ_UINT bufferSize
    )
{
    return udDefAllocateBuffer(idx, numBufs, bufferSize);
}

/*
 *====================================================================
 * PURPOSE: release buffer in the user space
 *--------------------------------------------------------------------
 * PARAMS:  IN buffer index zero based
 *          IN total number of buffers to release
 *          IN buffer address
 *          IN buffer size in bytes
 *
 * RETURNS: None
 *
 * NOTES:   Include any project-level processing here
 *====================================================================
 */

void
udReleaseBuffer(
    NQ_INT idx,
    NQ_COUNT numBufs,
    NQ_BYTE* buffAddr,
    NQ_UINT bufferSize
    )
{
    /* do nothing for static buffers */
}

#ifdef UD_NQ_INCLUDECODEPAGE

/*
 *====================================================================
 * PURPOSE: get current code page number
 *--------------------------------------------------------------------
 * PARAMS:
 *
 * RETURNS: code page as defined in udparams.h (UD_NQ_CODEPAGE<XXX>)
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
udGetCodePage(
    void
    )
{
    return udDefGetCodePage();
}

#endif /* UD_NQ_INCLUDECODEPAGE */

/*
 *====================================================================
 * PURPOSE: validate port usage
 *--------------------------------------------------------------------
 * PARAMS:  IN suggested port number
 *
 * RETURNS: valid port number in HBO
 *
 * NOTES:   This function allows to redefine port numbers for those ports that
 *          NQ uses. For instance NQ NetBIOS component is capable of co-existence
 *          with a foreign NetBIOS component on the same server. In this case
 *          NQ NetBIOS should use alternate port numbers instead of well-known
 *          port numbers. Each one of three well-known ports may be alternated separately.
 *====================================================================
 */

// ITA - debug
#import <TargetConditionals.h>
NQ_PORT
udGetPort(
    NQ_PORT port
    )
{
    /* default implementation returns the same number */

// ITA - debug
#ifndef TARGET_IPHONE_SIMULATOR
     /* Running on a device */
    return port;
#else
    /* for redefining one or more ports:
        1) comment the previous operator
        2) uncomment switch statement
        3) leave cases for those ports that should be redefined
        4) plave appropriate numbers instead of ???
    */

    switch (port)
    {
    case 137:
        return 5022;
    case 138:
        return 5023;
    case 139:
        return 5024;
    case UD_BR_INTERNALIPCPORT:
        return 5021;
    case 1022:
        return 5025;
    case 1023:
        return 5026;
   // case UD_BR_INTERNALDSPORT:
   //     return ???;
   // case UD_BR_INTERNALNSPORT:
   //     return ???;
    default:
        return port;
    }
#endif
}

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/*
 *====================================================================
 * PURPOSE: get unique ID for the current machine
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer of 12 bytes length
 *
 * RETURNS: None
 *
 * NOTES:   The returned 12-byte value should be:
 *           - "statistically unique" for the given machine
 *           - persistently the same for each call
 *          Recommended methods are:
 *           - MAC address of the default adapter
 *           - product serial number when available
 *====================================================================
 */

void
udGetComputerId(
    NQ_BYTE* buf
    )
{
    udDefGetComputerId(buf);
}

/*
 *====================================================================
 * PURPOSE: Get persistent security descriptor for share
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          OUT buffer for SD
 *          IN buffer length
 *
 * RETURNS: SD length or zero on error
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
udLoadShareSecurityDescriptor(
    const NQ_TCHAR* shareName,
    NQ_BYTE* buffer,
    NQ_COUNT bufferLen
    )
{
    return udDefLoadShareSecurityDescriptor(shareName, buffer, bufferLen);
}

/*
 *====================================================================
 * PURPOSE: Save persistent security descriptor for share
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          In pointer to SD
 *          IN SD length
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udSaveShareSecurityDescriptor(
    const NQ_TCHAR* shareName,
    const NQ_BYTE* sd,
    NQ_COUNT sdLen
    )
{
    udDefSaveShareSecurityDescriptor(shareName, sd, sdLen);
}

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/*
 *====================================================================
 * PURPOSE: get number of local users
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: Number of local users
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
udGetUserCount(
    void
    )
{
    return udDefGetUserCount();
}

/*
 *====================================================================
 * PURPOSE: get user ID by name
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *          OUT buffer for user ID
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udGetUserRidByName(
    const NQ_TCHAR* name,
    NQ_UINT32* rid
    )
{
    return udDefGetUserRidByName(name, rid);
}

/*
 *====================================================================
 * PURPOSE: get user name by ID
 *--------------------------------------------------------------------
 * PARAMS:  IN user ID
 *          OUT buffer for user name
 *          OUT buffer for full user name
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udGetUserNameByRid(
    NQ_UINT32 rid,
    NQ_TCHAR* nameBuffer,
    NQ_TCHAR* fullNameBuffer
    )
{
    return udDefGetUserNameByRid(rid, nameBuffer, fullNameBuffer);
}

/*
 *====================================================================
 * PURPOSE: enumerate users
 *--------------------------------------------------------------------
 * PARAMS:  IN user index (zero based)
 *          OUT buffer for user id
 *          OUT buffer for user name (256 bytes)
 *          OUT buffer for user's full name (256 bytes)
 *          OUT buffer for user description (256 bytes)
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udGetUserInfo(
    NQ_UINT index,
    NQ_UINT32* rid,
    NQ_TCHAR* name,
    NQ_TCHAR* fullName,
    NQ_TCHAR* description
    )
{
    return udDefGetUserInfo(index, rid, name, fullName, description);
}

/*
 *====================================================================
 * PURPOSE: modify user
 *--------------------------------------------------------------------
 * PARAMS:  IN user RID
 *          IN user name
 *          IN full user name
 *          IN user description
 *          IN Unicode text password or NULL
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:   This function either creates a new user or modifies an existing one.
 *====================================================================
 */

NQ_BOOL
udSetUserInfo(
    NQ_UINT32 rid,
    const NQ_TCHAR* name,
    const NQ_TCHAR* fullName,
    const NQ_TCHAR* description,
    const NQ_WCHAR* password
    )
{
    return udDefSetUserInfo(rid, name, fullName, description, password);
}

/*
 *====================================================================
 * PURPOSE: add user
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *          IN full user name
 *          IN user description
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:   This function either creates a new user or modifies an existing one.
 *====================================================================
 */

NQ_BOOL
udCreateUser(
    const NQ_TCHAR* name,
    const NQ_TCHAR* fullName,
    const NQ_TCHAR* description
    )
{
    return udDefCreateUser(name, fullName, description);
}

/*
 *====================================================================
 * PURPOSE: remove user
 *--------------------------------------------------------------------
 * PARAMS:  IN user RID
 *
 * RETURNS: TRUE when user was deleted
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udDeleteUserByRid(
    NQ_UINT32 rid
    )
{
    return udDefDeleteUserByRid(rid);
}

/*
 *====================================================================
 * PURPOSE: set user administrative rights
 *--------------------------------------------------------------------
 * PARAMS:  IN user RID
 *          IN TRUE to make user an administrator
 *
 * RETURNS: TRUE when user was found
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udSetUserAsAdministrator(
    NQ_UINT32 rid,
    NQ_BOOL    isAdmin
    )
{
    return udDefSetUserAsAdministrator(rid, isAdmin);
}

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)*/

#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION

/*
 *====================================================================
 * PURPOSE: modify/create share information in a persistent store
 *--------------------------------------------------------------------
 * PARAMS:  IN share name to change or NULL for a new share
 *          IN share name
 *          IN share path
 *          IN share descriptor
 *
 * RETURNS: TRUE on success, FALSE on failure
 *
 * NOTES:   user-level should return TRUE in the following cases:
 *          1) new share was perisistently stored
 *          2) existing share was peristently modified
 *          3) new share was not persistently stored but it should
 *             be exposed until server shutdown
 *          4) share was not persistently modified but this modification
 *             should be exposed until server shutdown
 *          user-level should return FALSE when a new share should not \
 *          be created or an existing share should not be modified
 *====================================================================
 */

NQ_BOOL
udSaveShareInformation(
    const NQ_TCHAR* name,
    const NQ_TCHAR* newName,
    const NQ_TCHAR* newMap,
    const NQ_TCHAR* newDescription
    )
{
    return udDefSaveShareInformation(name, newName, newMap, newDescription);
}

/*
 *====================================================================
 * PURPOSE: remove share from the persistent store
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: TRUE on success, FALSE on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
udRemoveShare(
    const NQ_TCHAR* name
    )
{
    return udDefRemoveShare(name);
}

#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */

#ifdef UD_NQ_INCLUDEEVENTLOG

/*
 *====================================================================
 * PURPOSE: event log function
 *--------------------------------------------------------------------
 * PARAMS:  IN code of NQ module that originated this event
 *          IN event class code
 *          IN event type
 *          IN pointer to the user name string
 *          IN IP address on the second side of the connection
 *          IN zero if the operation has succeeded or error code on failure
 *             for server event this code is the same that will be transmitted
 *             to the client
 *             for an NQ CIFS client event this value is the same that will be
 *             installed as system error
 *          IN pointer to a structure that is filled with event data
 *             actual structure depends on event type
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
udEventLog (
    NQ_UINT module,
    NQ_UINT class,
    NQ_UINT type,
    const NQ_TCHAR* userName,
    const NQ_IPADDRESS* pIp,
    NQ_UINT32 status,
    const NQ_BYTE* parameters
    )
{
    udDefEventLog(module, class, type, userName, pIp, status, parameters);
}

#endif /* UD_NQ_INCLUDEEVENTLOG */

#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP

NQ_BOOL
udGetComputerSecret(
    NQ_BYTE **secret
    )
{
    return udDefGetComputerSecret(secret);
}

void
udSetComputerSecret(
    NQ_BYTE *secret
    )
{
    udDefSetComputerSecret(secret); 
}

#endif /* UD_CS_INCLUDEDOMAINMEMBERSHIP */

void
udNetBiosError(
    NQ_STATUS cause,                /* error code */
    const NQ_CHAR* name             /* NetBIOS name that caused that error */
    )
{
}
