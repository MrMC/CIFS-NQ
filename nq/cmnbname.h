/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Definition of NetBIOS names
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMNBNAME_H_
#define _CMNBNAME_H_

/*
 * Generic defintion of a NetBIOS name
 */

#define CM_NB_NAMELEN  16           /* NetBIOS name lengths as by RFC1002
                                       32 chars in half-octets */
#define CM_NB_ENCODEDNAMELEN  32    /* NetBIOS name in 1st level encoding as by RFC1002
                                       32 ASCII chars + the length byte */
#define CM_DNS_NAMELEN 256          /* DNS name length as by RFC1035
                                       255 ASCII char + null termination byte */
typedef NQ_CHAR CMNetBiosName[CM_NB_NAMELEN + 1];   /* NetBIOS name null-terminated */

typedef struct {                    /* NetBIOS name information */
    CMNetBiosName name;             /* name itself */
    NQ_BOOL    isGroup;             /* group flag */
}
CMNetBiosNameInfo;

#define CM_NB_NETBIOSANYNAME "*123456789012345"     /* this name says that any name
                                                       is accepted */

/* NetBIOS name postfix - defines name class */

#define CM_NB_POSTFIXPOSITION 15

#define CM_NB_POSTFIX_SERVER 0x20
#define CM_NB_POSTFIX_WORKSTATION 0x0
#define CM_NB_POSTFIX_DOMAINMASTERBROWSER 0x1b
#define CM_NB_POSTFIX_DOMAINCONTROLLER 0x1c
#define CM_NB_POSTFIX_MASTERBROWSER 0x1d
#define CM_NB_POSTFIX_NONE 0xff
#define CM_NB_POSTFIX_INTERNAL 0x0

/*
 * Host name definition
 */

#define CM_NQ_HOSTNAMESIZE          UD_NQ_HOSTNAMESIZE

/*
    Calls
    -----
 */

#define cmNetBiosNameCopy(to, from)     syMemcpy(to, from, CM_NB_NAMELEN + 1)

#define cmNetBiosSameNames(name1, name2)    (syMemcmp(name1, name2, CM_NB_NAMELEN)==0)

#define cmNetBiosCheckName(src)     (src->name[0]!='*')    /* asterisk is illegal */

                                    /* 01234567890123456 */
#define cmNetBiosGetEmptyName()     "                "

#define cmNetBiosIsHostAlias(name)  (syStrncmp("*SMBSERV", name, 8)==0)

/* create a NetBIOS name from an ASCII name */

void
cmNetBiosNameCreate(
    CMNetBiosName nbName,       /* name to create */
    const NQ_CHAR* textName,    /* text name */
    NQ_BYTE postfix             /* NetBIOS postfix (see above) */
    );

/* remove trailing spaces after the name */

void
cmNetBiosNameClean(
    CMNetBiosName nbName        /* name to process */
    );

/* format a name as a NetBIOS name */

void
cmNetBiosNameFormat(
    CMNetBiosName name,         /* name to format */
    NQ_BYTE postfix             /* NetBIOS postfix (see above) */
    );

/* get the system scope id */

const NQ_CHAR*
cmNetBiosGetScope(
    void
    );

/* get the system scope id length */

NQ_UINT
cmNetBiosGetScopelength(
    void
    );

/* encode a NetBIOS name according the domain name rules (as in RFC1001, RFC1002)
   the name is encoded with the current scope (system parameter) */

NQ_COUNT                            /* returns the length of the encoded name */
cmNetBiosEncodeName(
    const CMNetBiosName name,       /* name to encode */
    NQ_BYTE* encodedName            /* pointer to the encoded name + scope in the message */
    );

/* encode a NetBIOS name as pointers to the labels of a previously encoded name */

NQ_COUNT                            /* returns the length of the encoded name */
cmNetBiosEncodeNamePointer(
    void* msg,                      /* pointer to the beginning of the message */
    void* encodedName,              /* pointer to the encoded name in the message */
    const void* oldName             /* pointer to the old name (not a pointer) */
    );

/* get this host's node type */

NQ_UINT16                           /* returns node type ready to use in NB_NAME
                                       - shifted to an appropriate bit position */
cmNetBiosGetNodeType(
    void
    );

/* Parse a NetBIOS name + scope in a message */

NQ_BYTE*                            /* returns a pointer to the 1st byte after the
                                       name (+ scope) or NULL if the parsing failed */
cmNetBiosParseName(
    const void* msg,                /* pointer tp the beginning of the message */
    const void *encodedname,        /* pointer to the encoded name */
    CMNetBiosName decodedname,      /* buffer to place the decoded NetBIOS name */
    NQ_CHAR *scope,                    /* buffer of sufficient size for the scope */
    NQ_UINT scopesize                  /* size of this buffer */
    );

/* Skip a NetBIOS name + scope in a message */

NQ_BYTE*                            /* returns a pointer to the 1st byte after the
                                       name (+ scope) or NULL if the parsing failed */
cmNetBiosSkipName(
    const void* msg,                /* pointer tp the beginning of the message */
    const void *encodedname         /* pointer to the encoded name */
    );

/* initialize various name resources */

NQ_STATUS                /* NQ_SUCCESS or NQ_FAIL */
cmNetBiosNameInit(
    void
    );

/* release various name resources */

void
cmNetBiosNameExit(
    void
    );

/* Pre-defined names and values */

const NQ_CHAR*         /* get the server's host name (padded by zeroes) */
cmNetBiosGetHostNameZeroed(
    void
    );

const NQ_CHAR*         /* get the server's host name (padded by spaces) */
cmNetBiosGetHostNameSpaced(
    void
    );

const CMNetBiosNameInfo*    /* get the server's host name and no-group flag */
cmNetBiosGetHostNameInfo(
    void
    );

const CMNetBiosNameInfo*    /* NetBIOS domain name with group flag set */
cmNetBiosGetDomain(
    void
    );

const NQ_CHAR*              /* Full-qualified host name */
cmGetFullHostName(
    void
    );

const NQ_CHAR*              /* Full-qualified domain name */
cmGetFullDomainName(
    void
    );

void						/* sets NetBIOS domain name for authentication */
cmNetBiosSetDomainAuth(
	NQ_TCHAR *name
	);

const CMNetBiosNameInfo* 	/* NetBIOS domain name */
cmNetBiosGetDomainAuth(
    void
    );

#endif  /* _CMNBNAME_H_ */
