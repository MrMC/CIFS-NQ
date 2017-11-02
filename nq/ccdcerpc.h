/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : DCERPC library for CIFS Client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 3-Sep-2005
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CCDCERPC_H_
#define _CCDCERPC_H_

#include "ccapi.h"
#include "cmapi.h"

/* -- Typedefs -- */

/* Description
   Callback function to compose RPC request payload.
   
   When RPC engine splits the call into fragments, it calls this
   function several times. It is the responsibility of the
   application to signal this situation by one of the fields in
   the <i>params</i> structure.
   Parameters
   buffer :    Buffer for outgoing data. This buffer is allocated
               (and released) by the RPC engine. 
   size :      Buffer size.
   params :    Pointer to an abstract parameter structure.
   moreData :  A buffer for the continuation indicator.<i> </i>The
               callback function should place there <i>TRUE</i>
               when the entire data fits into the buffer and <i>FALSE</i>
               to cause a continuation. 
   Returns
   NQ_SUCCESS or error code.                                            */
typedef NQ_COUNT    
(*CCDcerpcRequestCallback)(NQ_BYTE * buffer, NQ_COUNT size, void * params, NQ_BOOL * moreData);

/* Description
   Callback function to parse the RPC response payload.
   Parameters
   data :      Pointer to the data in the input buffer. This
               buffer is allocated (and released) by the RPC
               engine. 
   size :      Data length.
   params :    Pointer to an abstract parameter structure.
   moreData :  <i>TRUE</i> indicates that the buffer pointed by <i>data
               </i> contains the entire response. A <i>FALSE</i>
               value means that it is a fragment to be followed
               by more call(s). 
   Returns
   NQ_SUCCESS or error code.                                            */
typedef NQ_STATUS   
(*CCDcerpcResponseCallback)(const NQ_BYTE * data, NQ_COUNT size, void * params, NQ_BOOL moreData);

/* -- Structures -- */

/* Description
   Pipe descriptor. */
typedef struct
{
    const NQ_WCHAR * name;  /* Pipe name */
    NQ_Uuid uuid;         /* Pipe UUID */
    NQ_UINT32 version;      /* Pipe major/minor version */
} 
CCDcerpcPipeDescriptor;

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccDcerpcStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccDcerpcShutdown(void);

/* Description
   Connect to a remote RPC pipe.
   
   This function:
     * Opens the pipe file
     * Binds
   Parameters
   hostName :   Name of the host to connect.
   pCredentaisl : Pointer to credentaisl to use. A NULL value means anonymous connection. 
   pipeDesc :   Pointer to pipe descriptor.
   doDfs :      <i>TRUE</i> to force DFS resolution or <i>FALSE</i>
                to skip DFS resolution.
   Returns
   Pipe file handle or NULL on error.                                      */
NQ_HANDLE ccDcerpcConnect(const NQ_WCHAR * hostName, const AMCredentialsW * pCredentials, const CCDcerpcPipeDescriptor * pipeDesc, NQ_BOOL doDfs);

/* Description
   Disconnect from a remote RPC pipe.
   
   Parameters
   pipeHandle : Handle of an open pipe.
   Returns
   NQ_SUCCESS or error code.                                            */
NQ_STATUS ccDcerpcDisconnect(NQ_HANDLE pipeHandle);

/* Description
   Call RPC function.
   
   This function exchanges RPC messages to complete an RPC call.
   If necessary, it splits the call into several RPC fragments.
   Parameters
   pipeHandle :   Handle of an open pipe.
   request :      The request callback.
   response :     The response callback.
   callParams :   Pointer to the parameters. The parameters
                  structure will be passed to each of the
                  callback functions.
   Returns
   NQ_SUCCESS or error code.                                            */
NQ_BOOL ccDcerpcCall(NQ_HANDLE pipeHandle, CCDcerpcRequestCallback request, CCDcerpcResponseCallback response, void * callParams);

#endif /* _CCDCERPC_H_ */
