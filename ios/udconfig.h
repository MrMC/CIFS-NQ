/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : User-defined NQ configuration
 *--------------------------------------------------------------------
 * MODULE        : UD - User-defined
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-Jan-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : Felix Tener (December 2009)
 ********************************************************************/

#ifndef _UDCONFIG_H_
#define _UDCONFIG_H_

/* initialize UD module */

NQ_STATUS                 /* NQ_SUCCESS or NQ_FAIL */
udDefInit(
    void
    );

/* stop UD module */

void
udDefStop(
    void
    );

/* get the system's Scope ID */

void
udDefGetScopeID(
    NQ_WCHAR *buffer        /* buffer for the result */
    );

/* get wins address information */

NQ_IPADDRESS4              /* wins address in NBO or 0 */
udDefGetWins(
    void
    );

/* get domain name */

void
udDefGetDomain(
    NQ_WCHAR *buffer,       /* buffer for the result */
    NQ_BOOL *isWorkgroup    /* TRUE if the name is a workgroup name */
    );

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
/* get DNS initialization parameters */

void
udDefGetDnsParams(
    NQ_WCHAR *domain,       /* The default domain target belongs to */
    NQ_WCHAR *server        /* The DNS server IP address */
    );
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/* get authentication parameters for CC */
NQ_BOOL                     /* TRUE - got credentials, FALSE - failed */
udDefGetCredentials(
    const void* resource,   /* URI about to connect to */
    NQ_WCHAR* userName,     /* buffer for user name */
    NQ_WCHAR* password,     /* buffer for password */
    NQ_WCHAR* domain        /* buffer for domain name */
    );

/* get next share in the list of shares for CS */

NQ_BOOL                     /* TRUE - a share read FALSE - no more shares */
udDefGetNextShare(
    NQ_WCHAR* name,         /* buffer for share name */
    NQ_WCHAR* map,          /* buffer for the map path */
    NQ_BOOL* printQueue,    /* buffer getting 0 for file system and 1 for print queue */
    NQ_WCHAR* description   /* buffer for the share description */
    );

/* get next mount in the list of mounted volumes for CC */

NQ_BOOL                     /* TRUE more valumes in the list, FALSE when no more volumes available */
udDefGetNextMount(
    NQ_WCHAR* name,         /* buffer for volume name */
    NQ_WCHAR* map           /* buffer for the map path */
    );

/* check password for a specific user */

NQ_INT              /* See values in udapi.h */
udDefGetPassword(
    const NQ_WCHAR* userName,   /* user name */
    NQ_CHAR* password,          /* buffer for password */
    NQ_BOOL* pwdIsHashed,       /* TRUE - paasword hashed, FALSE - plain text */
    NQ_UINT32* userNumber       /* >1000 for administrators */
    );

/* reads last system error and tries to convert it to an SMB error */

NQ_UINT32                   /* SMB error or 0 to use the default conversion */
udDefGetSmbError(
    void
    );

/* query user-defined security descriptor */

int                         /* returns descriptor length */
udDefGetSecurityDescriptor(
    NQ_INT file,            /* ID of an opened file */
    NQ_INT32 information,   /* descriptor to get */
    void* buffer            /* output buffer */
    );

/* write user-defined security descriptor */

NQ_INT                      /* returns 1 on success, 0 on error */
udDefSetSecurityDescriptor(
    NQ_INT file,            /* ID of an opened file */
    NQ_INT32 information,   /* descriptor to set */
    const void* buffer,     /* input buffer */
    NQ_COUNT len            /* descriptor length */
    );

/* get task priorities */

NQ_INT
udDefGetTaskPriorities(
    void
    );

/* get server comment string */

void
udDefGetServerComment(
    NQ_WCHAR *buffer        /* buffer for the result */
    );

/* get CIFS driver name */

void
udDefGetDriverName(
    NQ_CHAR *buffer         /* buffer for the result */
    );

#ifdef UD_NQ_INCLUDECODEPAGE

/* get default code page */

NQ_INT
udDefGetCodePage(
    void
    );

#endif /* UD_NQ_INCLUDECODEPAGE */

/* allocate buffer in the user space */

NQ_BYTE*
udDefAllocateBuffer(
    NQ_INT idx,         /* buffer index zero based */
    NQ_COUNT numBufs,   /* total number of buffers to be allocated */
    NQ_UINT bufferSize  /* buffer size in bytes */
    );

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/* get unique ID for the current machine */

void
udDefGetComputerId(
    NQ_BYTE* buf        /* 12 - byte buffer to be filled with unique value */
    );

/* Get persistent security descriptor for share */

NQ_COUNT                        /* SD length or zero on error */
udDefLoadShareSecurityDescriptor(
    const NQ_WCHAR* shareName,  /* share name */
    NQ_BYTE* buffer,            /* buffer to read SD in */
    NQ_COUNT bufferLen          /* buffer length */
    );

/* Save persistent security descriptor for share */

void
udDefSaveShareSecurityDescriptor(
    const NQ_WCHAR* shareName,  /* share name */
    const NQ_BYTE* sd,          /* pointer to SD */
    NQ_COUNT sdLen              /* SD length */
    );

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/* get number of local users */

NQ_COUNT                        /* number of local users */
udDefGetUserCount(
    void
    );

/* get user ID by name */

NQ_BOOL                         /* TRUE when user was found */
udDefGetUserRidByName(
    const NQ_WCHAR* name,       /* user name */
    NQ_UINT32* rid              /* buffer for user ID */
    );

/* get user name by ID */

NQ_BOOL                         /* TRUE when user was found */
udDefGetUserNameByRid(
    NQ_UINT32 rid,              /* user id */
    NQ_WCHAR* nameBuffer,       /* buffer for user name */
    NQ_WCHAR* fullNamebuffer    /* buffer for full user name */
    );

/* enumerate users */

NQ_BOOL                         /* TRUE when user was available */
udDefGetUserInfo(
    NQ_UINT index,              /* user index (zero based) */
    NQ_UINT32* rid,             /* user id */
    NQ_WCHAR* name,             /* buffer for user name */
    NQ_WCHAR* fullName,         /* buffer for full user name */
    NQ_WCHAR* description       /* buffer for full user name */
    );

/* modify user */

NQ_BOOL                        /* TRUE when user was added/modified */
udDefSetUserInfo(
    NQ_UINT32 rid,                  /* user RID */
    const NQ_WCHAR* name,           /* user name */
    const NQ_WCHAR* fullName,       /* full user name */
    const NQ_WCHAR* description,    /* buffer for full user name */
    const NQ_WCHAR* password        /* Unicode text password or NULL */
    );

/* add user */

NQ_BOOL                        /* TRUE when user was added/modified */
udDefCreateUser(
    const NQ_WCHAR* name,           /* user name */
    const NQ_WCHAR* fullName,       /* full user name */
    const NQ_WCHAR* description     /* user description */
    );

/* set user administrative rights */

NQ_BOOL                     /* TRUE when opration succeeded */
udDefSetUserAsAdministrator(
    NQ_UINT32 rid,          /* user RID */
    NQ_BOOL    isAdmin      /* TRUE to set user as administrator */
    );

/* remove user */

NQ_BOOL                     /* TRUE when user was deleted */
udDefDeleteUserByRid(
    NQ_UINT32 rid           /* user RID */
    );

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined (UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)*/


#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION

/* modify/create share information in a persistent store */

NQ_BOOL
udDefSaveShareInformation(
    const NQ_WCHAR* name,           /* share to modify or NULL for a new share */
    const NQ_WCHAR* newName,        /* new share name */
    const NQ_WCHAR* newMap,         /* new share path */
    const NQ_WCHAR* newDescription  /* new share description */
    );

/* remove share from the persistent store */

NQ_BOOL
udDefRemoveShare(
    const NQ_WCHAR* name            /* share to remove */
    );

#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */

#ifdef UD_NQ_INCLUDEEVENTLOG

/*  event log */

void
udDefEventLog (
    NQ_UINT module,                 /* NQ module that originated this event */
    NQ_UINT class,                  /* event class */
    NQ_UINT type,                   /* event type */
    const NQ_WCHAR* userName,       /* name of the user */
    const NQ_IPADDRESS* pIp,        /* next side IP address */
    NQ_UINT32 status,               /* zero if the operation has succeeded or error code on failure
                                       for server event this code is the same that will be transmitted
                                       to the client
                                       for an NQ CIFS client event this value is the same
                                       that will be installed as system error */
    const NQ_BYTE* parameters       /* pointer to a structure that is filled with event data
                                       actual structure depends on event type */
    );

#endif /* UD_NQ_INCLUDEEVENTLOG */

/*
 *=====================================================================
 * DESCRIPTION: function that is used to set client's credentials.
 * --------------------------------------------------------------------
 * INPUT: user - user's name.
 *        pwd - user's password.
 *        domain - the domain in which the user is.
 * RETURNED VALUE: none.
 * NOTES: if the domain name is empty, than we client's domain is set
 *        as default value.
 *=====================================================================
 */
void udSetCredentials (
        const char* user, 
        const char* pwd, 
        const char* domain
        );

#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP

NQ_BOOL
udDefGetComputerSecret(
    NQ_BYTE **secret
    );

void
udDefSetComputerSecret(
    NQ_BYTE *secret
    );

#endif  /* UD_CS_INCLUDEDOMAINMEMBERSHIP */

#endif  /* _UDCONFIG_H_ */
