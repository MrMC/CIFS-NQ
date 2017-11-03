/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Initialization
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 25-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "cmtrace.h"
#include "cmfinddc.h"
#include "amspnego.h"

/*
  CM consists of two components: NetBIOS library and CIFS library. We initialize both
  of them.
 */

/*
 *====================================================================
 * PURPOSE: Initialize the library
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *====================================================================
 */

NQ_STATUS
cmInit(
    void
    )
{
    NQ_STATUS result = NQ_FAIL;

    if (sizeof(NQ_UINT32) != 4)
    {
        syPrintf("Type 'long' is not 4 bytes on the target platform. Define SY_INT32 in SYCOMPIL.H\n");
        sySetLastError(NQ_ERR_INVALIDUINT32SIZE);
        goto Exit;
    }

    if (!cmMemoryStart(0))
	{
		syPrintf("cmMemoryStart() failed\n");
		goto Exit;
	}

    if (NQ_FAIL == cmNetBiosInit())
    {
        syPrintf("cmNetBiosInit() failed\n");
        goto Error1;
    }

    if (NQ_FAIL == cmCifsInit())
    {
        syPrintf("cmCifsInit() failed\n");
        goto Error2;
    }

#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)
    if (NQ_FAIL == cmSdInit())
    {
        syPrintf("cmSdInit() failed\n");
        goto Error3;
    }
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */


    if (!cmSelfipStart())
    {
        syPrintf("cmSelfipStart() failed\n");
        goto Error4;
    }

    if (!cmResolverStart())
    {
        syPrintf("cmResolverStart() failed\n");
        goto Error5;
    }

    if (!cmThreadStart())
    {
        syPrintf("cmThreadStart() failed\n");
        goto Error6;
    }

    if (!cmPortManageStart())
    {
        syPrintf("cmPortManageStart() failed\n");
        goto Error7;
    }

    if (NQ_FAIL == cmFindDCInit())
    {
        syPrintf("cmFindDCInit() failed\n");
        goto Error7;
    }

#ifdef NQ_INTERNALTRACE
    cmTraceInit();
#endif    
#ifdef UD_NQ_EXTERNALTRACE
    syTraceInit();
#endif

    if (!amSpnegoStart())
    {
        syPrintf("amSpnegoStart() failed\n");
        goto Error8;
    }

    cmBufManStart();

#ifdef UD_NQ_INCLUDESMBCAPTURE
    cmCaptureStart();
#endif  /*UD_NQ_INCLUDESMBCAPTURE*/

    result = NQ_SUCCESS;
    goto Exit;

Error8:
    cmFindDCExit();

Error7:
    cmThreadShutdown();

Error6:
    cmResolverShutdown();

Error5:
    cmSelfipShutdown();

Error4:
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)
    cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */

Error3:
	cmCifsExit();

Error2:
	cmNetBiosExit();

Error1:
	cmMemoryShutdown();

Exit:
    return result;
}

/*
 *====================================================================
 * PURPOSE: Stop the library
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *====================================================================
 */

void
cmExit(
    void
    )
{    
#ifdef UD_NQ_INCLUDESMBCAPTURE
    cmCaptureShutdown();
#endif  /*UD_NQ_INCLUDESMBCAPTURE*/
    cmBufManShutdown();
    cmNetBiosExit();
    cmCifsExit();
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS)
    cmSdExit();
#endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */
    cmFindDCExit();
    /* new modules */
    cmResolverShutdown();
#ifdef NQ_INTERNALTRACE
    cmTraceFinish();
#endif
#ifdef UD_NQ_EXTERNALTRACE
    syTraceShutdown();
#endif
    cmThreadShutdown();
    cmSelfipShutdown();
    amSpnegoShutdown();
    cmMemoryShutdown();
}

NQ_UINT
cmGetNumOfAvailableTransports(
    void
    )
{
	NQ_UINT defaultTransports[] = {
#ifdef UD_NQ_USETRANSPORTIPV4
	          NS_TRANSPORT_IPV4,
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTNETBIOS
	          NS_TRANSPORT_NETBIOS,
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_NQ_USETRANSPORTIPV6
	          NS_TRANSPORT_IPV6,
#endif /* UD_NQ_USETRANSPORTIPV6 */
	          0 } ;

	return (NQ_UINT)(sizeof(defaultTransports) / sizeof(NQ_UINT) - 1);
}

/*
 *====================================================================
 * PURPOSE: returns the list of transports by their priorities
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: the pointer to array of transports following by zero
 *
 * NOTES:
 *====================================================================
 */

void
cmGetTransportPriorities(
    NQ_UINT	*	pBuf
    )
{
    static const NQ_UINT defaultTransports[] = {
#ifdef UD_NQ_USETRANSPORTIPV4
          NS_TRANSPORT_IPV4,
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTNETBIOS
          NS_TRANSPORT_NETBIOS,
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_NQ_USETRANSPORTIPV6
          NS_TRANSPORT_IPV6,
#endif /* UD_NQ_USETRANSPORTIPV6 */
          0 } ;

	const NQ_UINT *t;
	NQ_INT i, p;

    if (pBuf != NULL)
    {
		for (p = 3, i = 0; p > 0; p--)
		{
			/* lets try all transports */
			for (t = defaultTransports; *t; t++)
			{
				if (udGetTransportPriority(*t) == p)
					pBuf[i++] = *t;
			}
		}
    }
}
