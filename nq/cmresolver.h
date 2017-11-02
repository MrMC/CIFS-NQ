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

#ifndef _CMRESOLVER_H_
#define _CMRESOLVER_H_

#include "udparams.h"
#include "udapi.h"
#include "syapi.h"
#include "cmcommon.h"

/* -- API structures -- */

/* Description
   A descriptor of one resolver method. */
typedef struct 
{
    NQ_INT type;        /* one of NQ_RESOLVER_NETBIOS or NQ_RESOLVER_DNS */
    NQ_BOOL isMulticast;/* This value shoudl be <i>TRUE</i> for a multicast method. NQ uses unicast methods first. 
                           If none of them has suceeded, NQ tries multiccast methods. */
    NQ_TIME timeout;    /* timeout in seconds to use with this method */
    NQ_BOOL waitAnyway; /* wait for this method result even if another one has already succeded */
    /* Routine for composing and sending a name resolution request
       Parameters:
        socket :    Socket handle to use for sending
        name :      Name to resolve
        context :   Pointer to a method-specific context. This value may be NULL on the first call.
        serverIp :  Pointer to  the IP of the server to query or NULL for multicast
       Return:
       NQ_SUCCESS           request sent
       1-n                  a positive number means that more then one request was sent
       NQ_ERR_<*>           error
     */
    NQ_STATUS (* requestByName)(SYSocketHandle socket, const NQ_WCHAR * name, void * context, const NQ_IPADDRESS * serverIp);         
    /* Routine for receiving and parsing a name resolution response 
       Parameters
        socket :    Socket handle to use for sending
        pAddressArray : Address of the pointer which this call sets to an array of 
                        resolved IP addresses. It is caller's responsibility to release this array.
                        On error, this pointer remains untouched. 
        numIps :    Pointer to the number of resolved IPs. 
        pContext :  Double pointer to a method-specific context. Method may dispose 
                    context and create a new one. 
       Return:
       NQ_SUCCESS           name successfully resolved
       NQ_ERR_MOREDATA      more exchange expected
       NQ_ERR_NOACCESS      more comprehensive method with the same code should be used
       NQ_ERR_<*>           error
     */
    NQ_STATUS (* responseByName)(SYSocketHandle socket, NQ_IPADDRESS ** pAddressArray, NQ_INT * numIps, void ** pContext);
    /* Routine for composing and sending an IP resolution request
       Parameters:
        socket :    Socket handle to use for sending
        ip :        Pointer to the IP address to resolve.
        context :   Pointer to a method-specific context. This value may be NULL on the first call.
        serverIp :  Pointer to  the IP of the server to query or NULL for multicast
       Return:
       NQ_SUCCESS           request sent
       NQ_ERR_<*>           error
     */
    NQ_STATUS (* requestByIp)(SYSocketHandle socket, const NQ_IPADDRESS * ip, void * context, const NQ_IPADDRESS * serverIp);         
    /* Routine for receiving and parsing a name resolution response 
     
       Parameters
        socket :    Socket handle to use for sending
        pName :     Double pointer to the resolved name. On success, this variable will
                    point to a newly allocated name. Its is caller's responsibility to release it later.
        pContext :  Double pointer to a method-specific context. Method may dispose 
                    context and create a new one. 
      
       Return:
       NQ_SUCCESS           name successfully resolved
       NQ_ERR_MOREDATA      more exchange expected
       NQ_ERR_NOACCESS      more comprehensive method with the same code should be used
       NQ_ERR_<*>           error
     */
    NQ_STATUS (* responseByIp)(SYSocketHandle socket, const NQ_WCHAR ** pName, void ** pContext);
} 
CMResolverMethodDescriptor;

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL cmResolverStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void cmResolverShutdown(void);

/* Description
   This function registers a resolution method.

   Resolution method may be NetBIOS (Name Service), DNS or LLMNR. 
   Parameters
   descriptor : Pointer to a method descriptor. 
   serverIp :  Pointer to  the IP of the server to query or NULL for multicast
   Returns
   TRUE on success or FALSE on failure. */

NQ_BOOL cmResolverRegisterMethod(const CMResolverMethodDescriptor * descriptor, const NQ_IPADDRESS * serverIp);

/* Description
   This function removes a previously registered method.

   This function removes the first method that matches the following parameters:
   * type;
   * multicast flag on/off;
   * server IP. 

   if there are more methods matching the same parameters - they will remain registered.
   Parameters
   descriptor : Pointer to a method descriptor. 
   serverIp :  Pointer to  the IP of the server to query or NULL for multicast
   Returns
   None. */
void cmResolverRemoveMethod(const CMResolverMethodDescriptor * descriptor, const NQ_IPADDRESS * serverIp);

#endif /* _CMRESOLVER_H_ */
