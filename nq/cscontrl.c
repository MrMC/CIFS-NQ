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

#include "cscontrl.h"
#include "cmbuf.h"
#include "nsapi.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* 
 * Local definitions and data
 * --------------------------  
 */
/* timeouts */
#define STARTSTOP_TIMEOUT 30 
#define SHORT_TIMEOUT 5 
#define LONG_TIMEOUT 15 

/* abstract command packer */
typedef void (*Packer)(CMBufferWriter * writer, const void * params); 
/* abstract response parser */
typedef void (*Parser)(CMBufferReader * reader, void * params); 

/* peform protocol transaction */
static NQ_STATUS        
doTransact(
    NQ_UINT32 command,  /* command code */      
    Packer packer,  /* pointer to the packer of the input params (may be NULL) */
    Parser parser,  /* pointer to the parser of the response (may be NULL) */
    void * params,  /* command-dependent struct for in and out params (may be NULL)*/
    NQ_INT timeout  /* timeout in seconds */ 
    );

/* add share: structures and functions */
typedef struct
{
    const NQ_WCHAR* name;       /* share name */
    const NQ_WCHAR* path;       /* share path */
    NQ_BOOL isPrinter;          /* TRUE for print queue */
    const NQ_WCHAR* comment;     /* share descripton */
} AddShareParams;
static NQ_STATUS                /* NQ_SUCCESS or error code */
addShare(
    const NQ_WCHAR* name,       /* share name */
    const NQ_WCHAR* path,       /* share path */
    NQ_BOOL isPrinter,          /* TRUE for print queue */
    const NQ_WCHAR* comment     /* share descripton */
    );
static void 
addSharePacker(
    CMBufferWriter * writer, 
    const void * params
    ); 

/* remove share: structures and functions */
typedef struct
{
    const NQ_WCHAR* name;       /* share name */
} RemoveShareParams;
static NQ_STATUS                /* NQ_SUCCESS or error code */
removeShare(
    const NQ_WCHAR* name        /* share name */
    );
static void 
removeSharePacker(
    CMBufferWriter * writer, 
    const void * params
    ); 
#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/* add user: structures and functions */
typedef struct
{
    const NQ_WCHAR* name;           /* logon name */
    const NQ_WCHAR* fullName;       /* full name */
    const NQ_WCHAR* description;    /* user descripton */
    const NQ_WCHAR* password;       /* password */
    NQ_BOOL isAdmin;                /* TRUE for Admistrator rights */
} AddUserParams;
static NQ_STATUS                    /* NQ_SUCCESS or error code */
addUserT(
    const NQ_WCHAR* name,           /* logon name */
    const NQ_WCHAR* fullName,       /* full name */
    const NQ_WCHAR* description,    /* user descripton */
    const NQ_WCHAR* password,       /* password */
    NQ_BOOL isAdmin                 /* TRUE for Admistrator rights */
    );
static void 
addUserPacker(
    CMBufferWriter * writer, 
    const void * params
    ); 

/* remove user: structures and functions */
typedef struct
{
    const NQ_WCHAR* name;           /* logon name */
} RemoveUserParams;
static NQ_STATUS                    /* NQ_SUCCESS or error code */
removeUserT(
    const NQ_WCHAR* name            /* logon name */
    );
static void 
removeUserPacker(
    CMBufferWriter * writer, 
    const void * params
    ); 


/* clean user connections: structures and functions */
typedef struct
{
    const NQ_WCHAR* name;           /* user name */
    NQ_BOOL isDomainUser;           /* domain or local user */
} CleanUserConsParams;
static NQ_STATUS                    /* NQ_SUCCESS or error code */
cleanUserConsT(
    const NQ_WCHAR* name,           /* user name */
    NQ_BOOL isDomainUser            /* domain or local user */
    );
static void 
cleanUserConsPacker(
    CMBufferWriter * writer, 
    const void * params
    ); 


/* enum users: structures and functions */
typedef struct
{
    NQ_INDEX index;        /* share index */
    NQ_WCHAR* name;        /* user name */
    NQ_WCHAR* fullName;    /* full name */
    NQ_WCHAR* description; /* user descripton */
    NQ_BOOL* isAdmin;      /* TRUE Admistrator rights */
} EnumUsersParams;
static void 
enumUsersPacker(
    CMBufferWriter * writer, 
    const void * params
    );
static void 
enumUsersParser(    
    CMBufferReader * reader, 
    void * params
    );    
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

/* enum shares: structures and functions */
typedef struct
{
    NQ_INDEX index;       /* share index */
    NQ_WCHAR* name;       /* share name */
    NQ_WCHAR* path;       /* share path */
    NQ_BOOL isPrinter;    /* TRUE for print queue */
    NQ_WCHAR* comment;    /* share descripton */
} EnumSharesParams;

static void 
enumSharesPacker(
    CMBufferWriter * writer, 
    const void * params
    );

static void 
enumSharesParser(    
    CMBufferReader * reader, 
    void * params
    );

typedef struct
{
	NQ_INDEX 		index;
	NQ_IPADDRESS*	ip;
	NQ_UINT16	*	dialect;
} EnumClientsParams;

static void
enumClientsPacker(
		CMBufferWriter * writer,
		const void * params
		);

static void
enumClientsParser(
		CMBufferReader * reader,
		void * params
		);

typedef struct
{
	NQ_UINT mask;
}setEncryptParams;

static void
setEncryptPacker(
		CMBufferWriter * writer,
		const void * params
		);

#ifdef UD_CS_MESSAGESIGNINGPOLICY

typedef struct
{
	NQ_INT newPolicy;
}setMsgSgnParams;

static void
setMsgSgnPacker(
		CMBufferWriter * writer,
		const void * params
		);

#endif /* UD_CS_MESSAGESIGNINGPOLICY*/

/* enum shares: structures and functions */
typedef struct
{
    NQ_INDEX 	index;       /* share index */
    NQ_IPADDRESS*	ip;
    NQ_WCHAR* 	name;       /* share name */
    NQ_WCHAR* 	userName;    /* share descripton */
    NQ_BOOL 	isDir;    /* TRUE for print queue */
} EnumFilesParams;

static void
enumFilesPacker(
    CMBufferWriter * writer,
    const void * params
    );

static void
enumFilesParser(
    CMBufferReader * reader,
    void * params
    );

/*
 *====================================================================
 * PURPOSE: Stop server
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   
 *====================================================================
 */

NQ_STATUS
csCtrlStop(  
    void
    )
{
    return doTransact(CS_CONTROL_STOP, NULL, NULL, NULL, STARTSTOP_TIMEOUT);
}

/*
 *====================================================================
 * PURPOSE: Restart server
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   
 *====================================================================
 */

NQ_STATUS
csCtrlRestart(  /* restart server */
    void
    )
{
    return doTransact(CS_CONTROL_RESTART, NULL, NULL, NULL, STARTSTOP_TIMEOUT);
}

/*====================================================================
 * PURPOSE: Add share (ASCII)
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          IN share path
 *          IN TRUE for print queue
 *          IN share comment
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csCtrlAddShareA(
    const NQ_CHAR* name,
    const NQ_CHAR* path,
    NQ_BOOL isPrinter,
    const NQ_CHAR* comment
    )
{
    NQ_WCHAR nameW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXSHARELEN)];
    NQ_WCHAR pathW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXPATHLEN)];
    NQ_WCHAR commentW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXDESCRIPTIONLEN)];

    syAnsiToUnicode(nameW, name);
    syAnsiToUnicode(pathW, path);
    syAnsiToUnicode(commentW, comment);
    return addShare(nameW, pathW, isPrinter, commentW);
}

/*====================================================================
 * PURPOSE: Add share (Unicode)
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          IN share path
 *          IN TRUE for print queue
 *          IN share comment
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csCtrlAddShareW(
    const NQ_WCHAR* name,
    const NQ_WCHAR* path,
    NQ_BOOL isPrinter,
    const NQ_WCHAR* comment
    )
{
    return addShare(name, path, isPrinter, comment);
}

/*====================================================================
 * PURPOSE: Add share (common)
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          IN share path
 *          IN TRUE for print queue
 *          IN share comment
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
addShare(
    const NQ_WCHAR* name,
    const NQ_WCHAR* path,
    NQ_BOOL isPrinter,
    const NQ_WCHAR* comment
    )
{
    AddShareParams params;
    params.name = name;
    params.path = path;
    params.isPrinter = isPrinter;
    params.comment = comment;
    return doTransact(CS_CONTROL_ADDSHARE, addSharePacker, NULL, &params, SHORT_TIMEOUT);
}

/*====================================================================
 * PURPOSE: Packer for the Add Share command
 *--------------------------------------------------------------------
 * PARAMS:  OUT writer
 *          IN parameters
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static void 
addSharePacker(
    CMBufferWriter * writer, 
    const void * params
    )
{
    AddShareParams * p = (AddShareParams *)params;
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->name));
    cmBufferWriteUnicode(writer, p->name);
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->path));
    cmBufferWriteUnicode(writer, p->path);
    cmBufferWriteUint16(writer, p->isPrinter? 1 : 0);
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->comment));
    cmBufferWriteUnicode(writer, p->comment);
}

/*====================================================================
 * PURPOSE: Remove share (ASCII)
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csCtrlRemoveShareA(
    const NQ_CHAR* name
    )
{
    NQ_WCHAR nameW[UD_FS_MAXSHARELEN];

    syAnsiToUnicode(nameW, name);
    return removeShare(nameW);
}

/*====================================================================
 * PURPOSE: Remove share (Unicode)
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csCtrlRemoveShareW(
    const NQ_WCHAR* name
    )
{
    return removeShare(name);
}

/*====================================================================
 * PURPOSE: Remove share (common)
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
removeShare(
    const NQ_WCHAR* name
    )
{
    RemoveShareParams params;
    params.name = name;
    return doTransact(CS_CONTROL_REMOVESHARE, removeSharePacker, NULL, &params, SHORT_TIMEOUT);
}

/*====================================================================
 * PURPOSE: Packer for the Remove Share command
 *--------------------------------------------------------------------
 * PARAMS:  OUT writer
 *          IN parameters
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static void 
removeSharePacker(
    CMBufferWriter * writer, 
    const void * params
    )
{
    RemoveShareParams * p = (RemoveShareParams *)params;
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->name));
    cmBufferWriteUnicode(writer, p->name);
}

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

/*====================================================================
 * PURPOSE: Add user (ASCII)
 *--------------------------------------------------------------------
 * PARAMS:  IN logon name 
 *          IN full name
 *          IN user descripton
 *          IN password
 *          IN TRUE for Admistrator rights
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csCtrlAddUserA(
    const NQ_CHAR* name,  
    const NQ_CHAR* fullName, 
    const NQ_CHAR* description,
    const NQ_CHAR* password,    
    NQ_BOOL isAdmin             
    )
{
    NQ_WCHAR tname[CM_BUFFERLENGTH(NQ_WCHAR, 256)];
    NQ_WCHAR tfullname[CM_BUFFERLENGTH(NQ_WCHAR, 256)];
    NQ_WCHAR tdescription[CM_BUFFERLENGTH(NQ_WCHAR, 256)];
    NQ_WCHAR tpassword[CM_BUFFERLENGTH(NQ_WCHAR, 256)];

    syAnsiToUnicode(tname, name);
    syAnsiToUnicode(tfullname, fullName);
    syAnsiToUnicode(tdescription, description);
    syAnsiToUnicode(tpassword, password);
    return addUserT(tname, tfullname, tdescription, tpassword, isAdmin);
}

/*====================================================================
 * PURPOSE: Add user (Unicode)
 *--------------------------------------------------------------------
 * PARAMS:  IN logon name 
 *          IN full name
 *          IN user descripton
 *          IN password
 *          IN TRUE for Admistrator rights
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csCtrlAddUserW(
    const NQ_WCHAR* name,  
    const NQ_WCHAR* fullName, 
    const NQ_WCHAR* description,
    const NQ_WCHAR* password,   
    NQ_BOOL isAdmin             
    )
{
    NQ_WCHAR tname[CM_BUFFERLENGTH(NQ_WCHAR, 256)];
    NQ_WCHAR tfullname[CM_BUFFERLENGTH(NQ_WCHAR, 256)];
    NQ_WCHAR tdescription[CM_BUFFERLENGTH(NQ_WCHAR, 256)];
    NQ_WCHAR tpassword[CM_BUFFERLENGTH(NQ_WCHAR, 256)];

    syWStrcpy(tname, name);
    syWStrcpy(tfullname, fullName);
    syWStrcpy(tdescription, description);
    syWStrcpy(tpassword, password);
    return addUserT(tname, tfullname, tdescription, tpassword, isAdmin);
}

/*====================================================================
 * PURPOSE: Add user (common)
 *--------------------------------------------------------------------
 * PARAMS:  IN logon name 
 *          IN full name
 *          IN user descripton
 *          IN password
 *          IN TRUE for Admistrator rights
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
addUserT(
    const NQ_WCHAR* name,
    const NQ_WCHAR* fullName,
    const NQ_WCHAR* description,
    const NQ_WCHAR* password,
    NQ_BOOL isAdmin             
    )
{
    AddUserParams params;
    params.name = name;
    params.fullName = fullName;
    params.description = description;
    params.password = password;
    params.isAdmin = isAdmin;
    return doTransact(CS_CONTROL_ADDUSER, addUserPacker, NULL, &params, SHORT_TIMEOUT);
}

/*====================================================================
 * PURPOSE: Packer for the Add User command
 *--------------------------------------------------------------------
 * PARAMS:  OUT writer
 *          IN parameters
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static void 
addUserPacker(
    CMBufferWriter * writer, 
    const void * params
    )
{
    AddUserParams * p = (AddUserParams *)params;
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->name));
    cmBufferWriteUnicode(writer, p->name);
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->fullName));
    cmBufferWriteUnicode(writer, p->fullName);
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->description));
    cmBufferWriteUnicode(writer, p->description);
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->password));
    cmBufferWriteUnicode(writer, p->password);
    cmBufferWriteUint16(writer, p->isAdmin? 1 : 0);
}

/*====================================================================
 * PURPOSE: Remove user (ASCII)
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csCtrlRemoveUserA(
    const NQ_CHAR* name
    )
{
    NQ_WCHAR tname[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXSHARELEN)];

    syAnsiToUnicode(tname, name);
    return removeUserT(tname);
}

/*====================================================================
 * PURPOSE: Remove user (Unicode)
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csCtrlRemoveUserW(
    const NQ_WCHAR* name
    )
{
    NQ_WCHAR tname[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXSHARELEN)];

    syWStrcpy(tname, name);
    return removeUserT(tname);
}

/*====================================================================
 * PURPOSE: Remove user (common)
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
removeUserT(
    const NQ_WCHAR* name
    )
{
    RemoveUserParams params;
    params.name = name;
    return doTransact(CS_CONTROL_REMOVEUSER, removeUserPacker, NULL, &params, SHORT_TIMEOUT);
}

/*====================================================================
 * PURPOSE: Packer for the Remove User command
 *--------------------------------------------------------------------
 * PARAMS:  OUT writer
 *          IN parameters
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static void 
removeUserPacker(
    CMBufferWriter * writer, 
    const void * params
    )
{
    RemoveUserParams * p = (RemoveUserParams *)params;
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->name));
    cmBufferWriteUnicode(writer, p->name);
}


/* close deleted user's connections to NQ server */
NQ_STATUS                      /* NQ_SUCCESS or error code */
csCtrlCleanUserConnectionsA(
    const NQ_CHAR *name,       /* username */
    NQ_BOOL isDomainUser       /* domain or local user */
    )
{
    NQ_WCHAR tname[CM_BUFFERLENGTH(NQ_WCHAR, 256)];

    syAnsiToUnicode(tname, name);
    return cleanUserConsT(tname, isDomainUser);
}

NQ_STATUS                      /* NQ_SUCCESS or error code */
csCtrlCleanUserConnectionsW(
    const NQ_WCHAR *    name,  /* username */
    NQ_BOOL isDomainUser       /* domain or local user */
    )
{
    NQ_WCHAR tname[CM_BUFFERLENGTH(NQ_WCHAR, 256)];

    syWStrcpy(tname, name);
    return cleanUserConsT(tname, isDomainUser);   
}

/*====================================================================
 * PURPOSE: Clean user connections(common)
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *          IN domain or local user
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
cleanUserConsT(
    const NQ_WCHAR* name,
    NQ_BOOL isDomainUser
    )
{
    CleanUserConsParams params;
    params.name = name;
    params.isDomainUser = isDomainUser;
    return doTransact(CS_CONTROL_CLEANUSERCONS, cleanUserConsPacker, NULL, &params, SHORT_TIMEOUT);
}

/*====================================================================
 * PURPOSE: Packer for the Clean User Connections command
 *--------------------------------------------------------------------
 * PARAMS:  OUT writer
 *          IN parameters
 *
 * RETURNS: none
 *
 * NOTES:
 *====================================================================
 */

static void 
cleanUserConsPacker(
    CMBufferWriter * writer, 
    const void * params
    )
{
    CleanUserConsParams * p = (CleanUserConsParams *)params;
    cmBufferWriteUint16(writer, p->isDomainUser? 1 : 0);
    cmBufferWriteUint16(writer, (NQ_UINT16)syWStrlen(p->name));
    cmBufferWriteUnicode(writer, p->name);
}


NQ_STATUS                      /* NQ_SUCCESS or NQ_FAIL */
csCtrlEnumUsers(
    CsCtrlUser *userEntry,     /* user entry sructure */
    NQ_INDEX index             /* index */
    )
{
    EnumUsersParams params;
    params.index = index;
    params.name = userEntry->name;
    params.fullName = userEntry->fullName;
    params.description = userEntry->description;
    params.isAdmin = &userEntry->isAdmin;
    return doTransact(CS_CONTROL_ENUMUSERS, enumUsersPacker, enumUsersParser, &params, SHORT_TIMEOUT);
}

static void 
enumUsersPacker(
    CMBufferWriter * writer, 
    const void * params
    )
{
    EnumUsersParams * p = (EnumUsersParams *)params;
    cmBufferWriteUint16(writer, (NQ_UINT16)p->index);
}

static void 
enumUsersParser(
    CMBufferReader * reader, 
    void * params
    )
{
    NQ_UINT16 len;              /* string length */

    EnumUsersParams * p = (EnumUsersParams *)params;

    /* parse the command */
    cmBufferReadUint16(reader, &len);
    syWStrncpy(p->name, (const NQ_WCHAR*)cmBufferReaderGetPosition(reader), (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReadUint16(reader, &len);
    syWStrncpy(p->fullName,(const NQ_WCHAR*)cmBufferReaderGetPosition(reader), (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReadUint16(reader, &len);
    syWStrncpy(p->description,(const NQ_WCHAR*)cmBufferReaderGetPosition(reader), (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReadUint16(reader, &len);
    *p->isAdmin = len == 1? TRUE : FALSE;
}


#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

/*====================================================================
 * PURPOSE: Enumerate shares 
 *--------------------------------------------------------------------
 * PARAMS:  IN share entry struct
 *          IN share index
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This function returns NQ_FAIL when no more share entries
 *          exist
 *====================================================================
 */

NQ_STATUS                      /* NQ_SUCCESS or NQ_FAIL */
csCtrlEnumShares(
    CsCtrlShare *shareEntry,   
    NQ_INDEX index             
    )
{
	NQ_STATUS status;
    EnumSharesParams params;
    params.index = index;
    params.name = shareEntry->name;
    params.path = shareEntry->path;
    params.comment = shareEntry->comment;
    status =  doTransact(CS_CONTROL_ENUMSHARES, enumSharesPacker, enumSharesParser, &params, SHORT_TIMEOUT);
    shareEntry->isPrinter = params.isPrinter;
	return status;
}

static void 
enumSharesPacker(
    CMBufferWriter * writer, 
    const void * params
    )
{
    EnumSharesParams * p = (EnumSharesParams *)params;
    cmBufferWriteUint16(writer, (NQ_UINT16)p->index);
}

static void 
enumSharesParser(
    CMBufferReader * reader, 
    void * params
    )
{
    NQ_UINT16 len;              /* string length */

    EnumSharesParams * p = (EnumSharesParams *)params;

    /* parse the command */
    cmBufferReadUint16(reader, &len);
    syWStrncpy(p->name, (const NQ_WCHAR*)cmBufferReaderGetPosition(reader), (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReadUint16(reader, &len);
    syWStrncpy(p->path,(const NQ_WCHAR*)cmBufferReaderGetPosition(reader), (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReadUint16(reader, &len);
    p->isPrinter = len == 1? TRUE : FALSE;
    cmBufferReadUint16(reader, &len);
    syWStrncpy(p->comment,(const NQ_WCHAR*)cmBufferReaderGetPosition(reader), (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
}

/*====================================================================
 * PURPOSE: Enumerate clients
 *--------------------------------------------------------------------
 * PARAMS:  IN share entry struct
 *          IN share index
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This function returns NQ_FAIL when no more share entries
 *          exist
 *====================================================================
 */

NQ_STATUS                      /* NQ_SUCCESS or NQ_FAIL */
csCtrlEnumClients(
    CsCtrlClient *clientEntry,
    NQ_INDEX index
    )
{
	NQ_STATUS status;
    EnumClientsParams params;
    params.index = index;
    params.dialect = &clientEntry->dialect;
    params.ip = &clientEntry->ip;
    status =  doTransact(CS_CONTROL_ENUMCLIENTS, enumClientsPacker, enumClientsParser, &params, SHORT_TIMEOUT);

	return status;
}

static void
enumClientsPacker(
    CMBufferWriter * writer,
    const void * params
    )
{
    EnumClientsParams * p = (EnumClientsParams *)params;
    cmBufferWriteUint16(writer, (NQ_UINT16)p->index);
}

static void
enumClientsParser(
    CMBufferReader * reader,
    void * params
    )
{
    NQ_UINT16 len;              /* string length */
    NQ_CHAR	* ip;

    EnumClientsParams * p = (EnumClientsParams *)params;

    /* parse the command */
    cmBufferReadUint16(reader, &len);
    ip = cmMemoryCloneWStringAsAscii((NQ_WCHAR *)cmBufferReaderGetPosition(reader));
    if (ip == NULL)
    	return;
    cmAsciiToIp(ip , p->ip);
    cmMemoryFree(ip);
    cmBufferReaderSkip(reader , (NQ_UINT)(len+1)*2);
    cmBufferReadUint16(reader , &len);
    *p->dialect = len;
}

/*====================================================================
 * PURPOSE: Enumerate files
 *--------------------------------------------------------------------
 * PARAMS:  IN file entry struct
 *          IN file index
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This function returns NQ_FAIL when no more share entries
 *          exist
 *====================================================================
 */

NQ_STATUS                      /* NQ_SUCCESS or NQ_FAIL */
csCtrlEnumFiles(
    CsCtrlFile *fileEntry,
    NQ_INDEX index
    )
{
	NQ_STATUS status;
    EnumFilesParams params;

    params.index = index;
    params.name = fileEntry->name;
    params.userName = fileEntry->userName;
    params.ip = &fileEntry->ip;
    status =  doTransact(CS_CONTROL_ENUMFILES, enumFilesPacker, enumFilesParser, &params, SHORT_TIMEOUT);
    fileEntry->isDirectory = params.isDir;
	return status;
}

static void
enumFilesPacker(
    CMBufferWriter * writer,
    const void * params
    )
{
    EnumFilesParams * p = (EnumFilesParams *)params;
    cmBufferWriteUint16(writer, (NQ_UINT16)p->index);
}

static void
enumFilesParser(
    CMBufferReader * reader,
    void * params
    )
{
    NQ_UINT16 len;              /* string length */

    EnumFilesParams * p = (EnumFilesParams *)params;

    /* parse the command */
    cmBufferReadUint16(reader, &len);
	cmAsciiToIp((NQ_CHAR *)cmBufferReaderGetPosition(reader), p->ip);
	cmBufferReaderSkip(reader , (NQ_UINT)syStrlen((NQ_CHAR *)cmBufferReaderGetPosition(reader)) + 1);
    cmBufferReadUint16(reader, &len);
    syWStrncpy(p->name, (const NQ_WCHAR*)cmBufferReaderGetPosition(reader), (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReadUint16(reader, &len);
    syWStrncpy(p->userName,(const NQ_WCHAR*)cmBufferReaderGetPosition(reader), (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_WCHAR)));
    cmBufferReadUint16(reader, &len);
    p->isDir = len == 1? TRUE : FALSE;
}

NQ_STATUS
csCtrlSetEncryptionMethods(
		NQ_UINT mask
		)
{
	NQ_STATUS status;
	setEncryptParams params;

	params.mask = mask;

	status = doTransact(CS_CONTROL_CHANGEENCRYPTION , setEncryptPacker , NULL , &params , SHORT_TIMEOUT);
	return status;
}
static void
setEncryptPacker(
	CMBufferWriter * writer,
	const void * params
	)
{
	setEncryptParams * p = (setEncryptParams *)params;

	cmBufferWriteUint16(writer , (NQ_UINT16)p->mask);
}
#ifdef UD_CS_MESSAGESIGNINGPOLICY
NQ_STATUS
csCtrlSetMessageSigningPolicy(
		NQ_INT newPolicy)
{
	NQ_STATUS status;
	setMsgSgnParams params;

	params.newPolicy = newPolicy;

	status = doTransact(CS_CONTROL_CHANGEMSGSIGN , setMsgSgnPacker , NULL , &params , SHORT_TIMEOUT);
	return status;
}

static void
setMsgSgnPacker(
		CMBufferWriter * writer,
		const void * params
		)
{
	setMsgSgnParams * p = (setMsgSgnParams *)params;

	cmBufferWriteUint16(writer , (NQ_UINT16)p->newPolicy);
}

#endif /* UD_CS_MESSAGESIGNINGPOLICY*/
/*
 *====================================================================
 * PURPOSE: Perform transation against the server
 *--------------------------------------------------------------------
 * PARAMS:  IN      command code
 *          IN      pointer to the packer of the input params (may be NULL)
 *          IN      pointer to the parser of the response (may be NULL)
 *          IN/OUT  command-dependent struct for in and out params 
 *                  (may be NULL)
 *          IN      timeout in seconds
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *          
 *
 * NOTES:   System error code either conatins native system error code or 
 *          is set to the following NQ codes:
 *              NQ_ERR_NOSUPPORT - server unavailable (not running) 
 *              NQ_ERR_BADPARAM - unsupported command or other param error
 *====================================================================
 */

static NQ_STATUS        
doTransact(
    NQ_UINT32 command,          
    Packer packer,  
    Parser parser,  
    void * params,
    NQ_INT timeout
    )
{
    SYSocketHandle sock = 0;                        /* for internal communication */
#ifndef UD_NQ_USETRANSPORTIPV6     
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;   /* self address */
#else   
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_IPADDRESS localhostv6 = CM_IPADDR_LOCAL6;
#endif
    NQ_IPADDRESS ip;                            /* server IP in response */
    NQ_PORT port;                               /* server port in response */
    NQ_BYTE buf[CS_CONTROL_MAXMSG];             /* message buffer */
    CMBufferWriter writer;                      /* for composing the command */
    CMBufferReader reader;                      /* for composing the command */
    NQ_INT result;                              /* sent/received/select result */
    SYSocketSet  socketSet;                     /* set for reading from this socket */
    NQ_COUNT i;
    NQ_UINT transArr[] = {
#ifdef UD_NQ_USETRANSPORTIPV6
           NS_TRANSPORT_IPV6,
#endif
#ifdef UD_NQ_USETRANSPORTIPV4
           NS_TRANSPORT_IPV4,
#endif
#ifdef UD_NQ_USETRANSPORTNETBIOS
           NS_TRANSPORT_NETBIOS,
#endif
        			}; /* array to check transports*/

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* create socket */
    for (i = 0 ; i < (sizeof(transArr) / sizeof(transArr[0]))  ; i++)
	{

		if (!udGetTransportPriority(transArr[i]))
				continue;

#ifdef UD_NQ_USETRANSPORTIPV6
		if (transArr[i] == NS_TRANSPORT_IPV6)
				localhost = localhostv6;
#endif /*UD_NQ_USETRANSPORTIPV6*/

		sock = syCreateSocket(FALSE,
#ifndef UD_NQ_USETRANSPORTIPV6     
            CM_IPADDR_IPV4);
#else
            (transArr[i] == NS_TRANSPORT_IPV4) ? CM_IPADDR_IPV4 : CM_IPADDR_IPV6);    /* datagram socket */
#endif /*UD_NQ_USETRANSPORTIPV6*/

        if(!syIsValidSocket(sock))       /* error */
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create internal communication socket with transport %d" , transArr[i]);
			continue;
		}
		break;

	}

    if(!syIsValidSocket(sock))       /* error */
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create internal communication socket");
		LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
		return NQ_FAIL;
	}

    /* compose command */
    cmBufferWriterInit(&writer, buf, sizeof(buf));
    cmBufferWriteUint32(&writer, command);
    if (NULL != packer)
    {
        (*packer)(&writer, params);
    }
    
    /* send command */
    result = sySendToSocket(sock, buf, (NQ_COUNT)(writer.current - buf), &localhost,syHton16(CS_CONTROL_PORT));
    if (result != writer.current - buf)
    {
        if (result > 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Command not sent. Expected: %d, sent: %d", writer.current - buf, result);
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Command not sent");
        }
        syCloseSocket(sock);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }
    
    /* receive response */
    syClearSocketSet(&socketSet);
    syAddSocketToSet(sock, &socketSet);
    result = sySelectSocket(
        &socketSet,
        (NQ_UINT32)timeout
        );
    if (result == NQ_FAIL)                 /* error the select failed  */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Select failed");
        syCloseSocket(sock);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }
    if (result == 0)                /* timeout  */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Select timed out");
        sySetLastError(NQ_ERR_NOSUPPORT);
        syCloseSocket(sock);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }
    result = syRecvFromSocket(
        sock,
        buf,
        sizeof(buf),
        &ip,
        &port
        );

    if (result == 0 || result == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Receive failed with result: %d", result);
        syCloseSocket(sock);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }

    /* parse response */
    cmBufferReaderInit(&reader, buf, (NQ_COUNT)result);
    cmBufferReadUint32(&reader, &command);
    if (NQ_SUCCESS == command)
    {
        if (NULL != parser)
        {
            (*parser)(&reader, params);
        }
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Command failed by server: %d", command);
        sySetLastError(command);
    }
    
    /* close socket */   
    syCloseSocket(sock);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return command == NQ_SUCCESS? NQ_SUCCESS: NQ_FAIL;
}

    
#endif /* UD_NQ_INCLUDECIFSSERVER */
