/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SAMR RPC client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 3-Jul-2005
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CCSAMRPC_H_
#define _CCSAMRPC_H_

#include "cmapi.h"
#include "ccdcerpc.h"

#if defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/*
 * Types and definitions
 * ---------------------
 */

/* Access mask bits */
#define SAMR_AM_GENERICREAD                   SMB_DESIREDACCESS_GENREAD
#define SAMR_AM_GENERICWRITE                  SMB_DESIREDACCESS_GENWRITE
#define SAMR_AM_GENERICEXECUTE                SMB_DESIREDACCESS_GENEXECUTE
#define SAMR_AM_GENERICALL                    SMB_DESIREDACCESS_GENALL
#define SAMR_AM_DELETE                        SMB_DESIREDACCESS_DELETE
#define SAMR_AM_READCONTROL                   SMB_DESIREDACCESS_READCONTROL
#define SAMR_AM_WRITEDAC                      SMB_DESIREDACCESS_WRITEDAC
#define SAMR_AM_WRITEOWNER                    SMB_DESIREDACCESS_WRITEOWNER
#define SAMR_AM_ACCESSSYSTEMSECURITY          SMB_DESIREDACCESS_GENSYSTEMSECURITY
#define SAMR_AM_MAXIMUMALLOWED                SMB_DESIREDACCESS_GENMAXIMUMALLOWED
#define SAMR_AM_GENERICACCESSSACL             0x00800000
#define SAMR_AM_DOMAINREADPASSWORDPARAMETERS  0x00000001
#define SAMR_AM_DOMAINWRITEPASSWORDPARAMS     0x00000002
#define SAMR_AM_DOMAINREADOTHERPARAMETERS     0x00000004
#define SAMR_AM_DOMAINWRITEOTHERPARAMETERS    0x00000008
#define SAMR_AM_DOMAINCREATEUSER              0x00000010
#define SAMR_AM_DOMAINCREATEGROUP             0x00000020
#define SAMR_AM_DOMAINCREATEALIAS             0x00000040
#define SAMR_AM_DOMAINGETALIASMEMBERSHIP      0x00000080
#define SAMR_AM_DOMAINLISTACCOUNTS            0x00000100
#define SAMR_AM_DOMAINLOOKUP                  0x00000200
#define SAMR_AM_DOMAINADMINISTERSERVER        0x00000400
#define SAMR_AM_DOMAINALLACCESS               0x000F07FF
#define SAMR_AM_DOMAINREAD                    0x00020084
#define SAMR_AM_DOMAINALLWRITE                0x0002047A
#define SAMR_AM_DOMAINALLEXECUTE              0x00020301
#define SAMR_AM_USERGETNAME                   0x1
#define SAMR_AM_USERGETLOCALE                 0x2
#define SAMR_AM_USERGETLOCCOM                 0x4
#define SAMR_AM_USERGETLOGONINFO              0x8
#define SAMR_AM_USERGETATTRIBUTES             0x10
#define SAMR_AM_USERSETATTRIBUTES             0x20
#define SAMR_AM_USERCHANGEPASSWORD            0x40
#define SAMR_AM_USERSETPASSWORD               0x80
#define SAMR_AM_USERGETGROUPS                 0x100
#define SAMR_AM_USERGETMEMBERSHIP             0x200
#define SAMR_AM_USERCHANGEMEMBERSHIP          0x400


/* account flags */
#define SAMR_ACB_NORMAL                       0x00000010  /* Normal user account */
#define SAMR_ACB_WSTRUST                      0x00000080  /* Workstation trust account */
#define SAMR_ACB_SVRTRUST                     0x00000100  /* Server trust account */

typedef struct {
    const NQ_BYTE *password;
    NQ_UINT16 size;
}
ParamsSamrUserSetInfo2Level24;

typedef struct {
    NQ_UINT32 flags;
}
ParamsSamrUserSetInfo2Level16;

/* get SAM pipe information */

const CCDcerpcPipeDescriptor*      /* pointer to pipe descriptor */
ccSamGetPipe(
    void
    );

/* get user groups by acount name */

NQ_STATUS                               /* returns NQ_SUCCESS if DC resolves user's token */
ccSamGetUserGroups(
    NQ_HANDLE pipeHandle,               /* pipe file handle */
    const NQ_WCHAR* name,               /* user name */
    const NQ_WCHAR* domain,             /* domain name */
    CMSdAccessToken* token              /* buffer for token */
    );

/* get domain sid */

NQ_STATUS                               /* returns NQ_SUCCESS if DC resolves domain name */
ccSamGetDomainSid(
    NQ_HANDLE pipeHandle,               /* pipe file handle */
    const NQ_WCHAR* domain,             /* domain name */
    CMSdDomainSid* sid                  /* resulting sid */
    );

/* SAMR::Connect5 */
NQ_UINT32
ccSamrConnect5(
    NQ_HANDLE samr,
    NQ_UINT32 access,
    CMRpcPolicyHandle *connect
    );

/* SAMR::OpenDomain */
NQ_UINT32
ccSamrOpenDomain(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *connect,
    const CMSdDomainSid *domain,
    NQ_UINT32 access,
    CMRpcPolicyHandle *open
    );

/* SAMR::CreateUser2 */
NQ_UINT32
ccSamrCreateUser2(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *domain,
    const NQ_WCHAR *name,
    NQ_UINT32 flags,
    NQ_UINT32 access,
    CMRpcPolicyHandle *user,
    NQ_UINT32 *rid,
    NQ_UINT32 *granted
    );

/* SAMR::SetUserInfo2 */
NQ_UINT32
ccSamrSetUserInfo2(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *user,
    NQ_UINT16 level,
    NQ_BYTE *params
    );

/* SAMR::GetUserInfo2 */
NQ_UINT32
ccSamrGetUserInfo2(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *user,
    NQ_UINT16 level,
    NQ_BYTE *params
    );

/* Set password for a supplied user by sending SAMR::SetUserInfo2 (level=24) */
NQ_UINT32
ccSamrSetUserPassword(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *user,
    const NQ_BYTE *password,
    NQ_UINT16 length
    );

/* SAMR::LookupNames */
NQ_UINT32
ccSamrLookupNames(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *domain,
    const NQ_WCHAR *name,
    NQ_UINT32 *rid,
    NQ_UINT32 *type
    );

/* SAMR::OpenUser */
NQ_UINT32
ccSamrOpenUser(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *domain,
    const NQ_UINT32 *rid,
    NQ_UINT32 access,
    CMRpcPolicyHandle *user
    );


/* SAMR::DeleteUser */
NQ_UINT32
ccSamrDeleteUser(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *user
    );
    
/* SAMR::Close */
NQ_UINT32
ccSamrClose(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *policy
    );

#endif /* defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH) */

#endif /* _CCSAMRPC_H_ */
