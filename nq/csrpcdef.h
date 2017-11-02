/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RPC common definitions
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#ifndef _CSRPCDEF_H_
#define _CSRPCDEF_H_

#include "cmapi.h"

#define CS_RP_CALL(call)            \
{                                   \
    NQ_UINT32 status;               \
                                    \
    status = call;                  \
    if (status != 0)                \
    {                               \
        TRCE();                     \
        return status;              \
    }                               \
}                                   \

/* check space in the buffer */

#define CS_RP_CHECK(_out, _space)               \
{                                               \
    if (cmRpcSpace(_out) < (_space))            \
    {                                           \
        TRCERR("read buffer overflow");         \
        TRCE();                                 \
        return CM_RP_INSUFFICIENTBUFFER;        \
    }                                           \
}                                               \

/* RPC library */

typedef struct              /* function descriptor */
{
    NQ_UINT32 (*func)(
        CMRpcPacketDescriptor* in,
        CMRpcPacketDescriptor* out
        );
} CSRpcFunctionDescriptor;

typedef struct              /* pipe descriptor */
{
    NQ_STATUS (*init)();                    /* initialization function or NULL */
    void (*stop)();                         /* stop function or NULL */
    void (*cleanup)(const NQ_BYTE* file);   /* cleanup function or NULL */
    const NQ_CHAR* name;                    /* pipe name */
    const CMRpcUuid uuid;                   /* uuid */
    NQ_UINT16 version;                      /* interface version as major + minor * 0x10000 */
    NQ_INT numFuncs;                        /* number of functions */
    const CSRpcFunctionDescriptor* funcs;   /* array of function descriptors */
    NQ_UINT32 (*checkSize)(NQ_UINT16 code); /* fucntion to check response size by function code - may be NULL */
} CSRpcPipeDescriptor;

#endif /* _CSRPCDEF_H_ */
