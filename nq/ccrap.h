/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RAP Iplementation definitions
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 18-Apr-2003
 * CREATED BY    : Alexey Yarovinsky
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CCRAP_H_
#define _CCRAP_H_

#include "ccapi.h"

#define NET_NAME_MAX_SIZE   13
#define NET_DESC_MAX_SIZE   256
#define NET_SRVR_MAX_SIZE   16

#define SV_TYPE_WORKSTATION         0x00000001  /* All workstations */
#define SV_TYPE_SERVER              0x00000002  /* All servers */
#define SV_TYPE_SQLSERVER           0x00000004  /* Any server running with SQL server */
#define SV_TYPE_DOMAIN_CTRL         0x00000008  /* Primary domain controller */
#define SV_TYPE_DOMAIN_BAKCTRL      0x00000010  /* Backup domain controller */
#define SV_TYPE_TIME_SOURCE         0x00000020  /* Server running the timesource service */
#define SV_TYPE_AFP                 0x00000040  /* Apple File Protocol servers */
#define SV_TYPE_NOVELL              0x00000080  /* Novell servers */
#define SV_TYPE_DOMAIN_MEMBER       0x00000100  /* Domain Member */
#define SV_TYPE_PRINTQ_SERVER       0x00000200  /* Server sharing print queue */
#define SV_TYPE_DIALIN_SERVER       0x00000400  /* Server running dialin service. */
#define SV_TYPE_XENIX_SERVER        0x00000800  /* Xenix server */
#define SV_TYPE_NT                  0x00001000  /* NT server */
#define SV_TYPE_WFW                 0x00002000  /* Server running Windows for Workgroups */
#define SV_TYPE_SERVER_NT           0x00008000  /* Windows NT non DC server */
#define SV_TYPE_POTENTIAL_BROWSER   0x00010000  /* Server that can run the browser service */
#define SV_TYPE_BACKUP_BROWSER      0x00020000  /* Backup browser server */
#define SV_TYPE_MASTER_BROWSER      0x00040000  /* Master browser server */
#define SV_TYPE_DOMAIN_MASTER       0x00080000  /* Domain Master Browser server */
#define SV_TYPE_LOCAL_LIST_ONLY     0x40000000  /* Enumerate only entries marked "local" */
#define SV_TYPE_DOMAIN_ENUM         0x80000000  /* Enumerate Domains. The pszServer and pszDomain parameters must be NULL. */

typedef struct {
    NQ_CHAR     netName[NET_NAME_MAX_SIZE];
    NQ_CHAR     pad;
    NQ_UINT16   type;
    NQ_UINT16   offsetLow;
    NQ_UINT16   offsetHigh;
}ShareInfo1;

typedef struct {
    NQ_WCHAR  srvName[CM_BUFFERLENGTH(NQ_TCHAR, NET_SRVR_MAX_SIZE)];
} ServerInfo0;

typedef struct {
    NQ_WCHAR  srvName[CM_BUFFERLENGTH(NQ_TCHAR, NET_SRVR_MAX_SIZE)];
    NQ_BYTE   versionMajor;
    NQ_BYTE   versionMinor;
    NQ_UINT32 type;
    NQ_TCHAR   comment[CM_BUFFERLENGTH(NQ_TCHAR, NET_DESC_MAX_SIZE)];
} ServerInfo1;

/* callback function for storing different names during enumeration */
typedef void
(*CCRapEnumerateNamesCallback)(
    const NQ_CHAR * name,       /* next name (null terminated) */
    void * params               /* abstract parameters */
    );

NQ_STATUS ccRapNetShareEnum(
    const NQ_WCHAR   *server,                         /* host name */
    CCRapEnumerateNamesCallback callback,       /* callback for storing names */
    void* params                                /* abstract parameters for callback */
   );

NQ_STATUS ccRapNetShareInfo(
    const NQ_WCHAR *server,                     /* host name */
    const NQ_WCHAR *share,                      /* share name */
    NQ_UINT16 *type,
    NQ_WCHAR *remark,
    NQ_INT maxRemarkSize,
    NQ_BOOL unicodeResult
   );

NQ_STATUS ccRapNetServerEnum(
    const NQ_WCHAR *server,                     /* server to query */
    CCRapEnumerateNamesCallback callback,       /* callback for storing names */
    void*       params,                         /* abstract parameters for callback */
    NQ_UINT32   serverType,                     /* either SERVERS or DOMAINS/WORKGROUPS */
    const NQ_WCHAR   *domain                    /* domain for SERVERS */
   );

#endif /* _CCRAP_H_ */
