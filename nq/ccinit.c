/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client Initialization
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 3-Jul-2001
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ccmount.h"
#include "ccserver.h"
#include "ccshare.h"
#include "ccfile.h"
#include "ccsearch.h"
#include "ccdfscache.h"
#include "ccdfs.h"
#include "ccutils.h"
#include "cctransport.h"
#include "ccparams.h"
#include "cccifs.h"
#include "ccwrite.h"
#include "ccread.h" 
#include "ccdcerpc.h"
#include "ccsdescr.h"
#include "ccsrvsvc.h"
#include "ccsmb10.h"
#include "ccsmb20.h"
#include "ccsmb30.h"
#include "ccsmb311.h"
#include "ccsecure.h"
#include "nqapi.h"
#include "nsapi.h"
#include "ldapi.h"
#include "ccnetwrk.h"
#ifdef UD_CC_INCLUDEOLDBROWSERAPI
#include "ccbrowse.h"
#endif /* UD_CC_INCLUDEOLDBROWSERAPI */
#include "ccdomain.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* static data */

static NQ_BOOL sCcIsInitialized = FALSE;

/*
 *====================================================================
 * PURPOSE: client module initialization
 *--------------------------------------------------------------------
 * PARAMS:  IN  pointer to handle error notification handler
 *
 * RETURNS: TRUE if succeeded, FALSE otherwise
 *
 * NOTES:  Application can examine the error code for the failure reason
 *====================================================================
 */

NQ_BOOL
ccInit(
    void (*fsdNotify)(NQ_INT eventId, NQ_ULONG param)
    )
{
	NQ_BOOL result = FALSE;
    NQ_INT error = NQ_ERR_OK;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "fsdNotify:%p", fsdNotify);

    if (!sCcIsInitialized)
    {
        ccConfigInit();

        if (NQ_SUCCESS != nsInit(TRUE)         
            || !ccUtilsStart()
            || !ccTransportStart()
            || !ccMountStart()
        	|| !ccServerStart()
            || !ccUserStart()
            || !ccShareStart()
            || !ccCifsStart()
            || !ccSmb10Start()
#ifdef UD_NQ_INCLUDESMB2
            || !ccSmb20Start()
#ifdef UD_NQ_INCLUDESMB3
            || !ccSmb30Start()
#ifdef UD_NQ_INCLUDESMB311
			|| !ccSmb311Start()
#endif /* UD_NQ_INCLUDESMB311 */
#endif /* UD_NQ_INCLUDESMB3 */
#endif /* UD_NQ_INCLUDESMB2 */
        	|| !ccFileStart()
			|| !ccSecureStart()
            || !ccDfsCacheStart()
            || !ccDfsStart()
            || !ccSearchStart()
        	|| !ccWriteStart()
            || !ccReadStart()
            || !ccDcerpcStart()
            || !ccSdescrStart()
        	|| !ccSrvsvcStart()
#ifdef UD_CC_INCLUDEOLDBROWSERAPI
            || !ccBrowseStart()
#endif /* UD_CC_INCLUDEOLDBROWSERAPI */
            || !ccNetworkStart()
#ifdef UD_CC_INCLUDEDOMAINMEMBERSHIP
			|| !ccDomainStart()
#endif /* UD_CC_INCLUDEDOMAINMEMBERSHIP */
#ifdef UD_CC_INCLUDELDAP
            || NQ_SUCCESS != ldStart()
#endif /* UD_CC_INCLUDELDAP */
        	)
        {
            error = (NQ_INT)syGetLastError();
			goto Exit;
        }
 
        sCcIsInitialized = TRUE;
    }
	result = TRUE;

Exit:
    sySetLastError(error);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: client module shutdown
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
ccShutdown(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);


	/* new modules */
#ifdef UD_CC_INCLUDEDOMAINMEMBERSHIP
	ccDomainShutdown();
#endif /* UD_CC_INCLUDEDOMAINMEMBERSHIP */
	ccSearchShutdown();
	ccMountShutdown();
	ccServerShutdown();
	ccUserShutdown();
	ccShareShutdown();
	ccCifsShutdown();
	ccUtilsShutdown();
	ccTransportShutdown();
	ccFileShutdown();
	ccDfsShutdown();
	ccDfsCacheShutdown();
#ifdef UD_CC_INCLUDEOLDBROWSERAPI
	ccBrowseShutdown();
#endif /* UD_CC_INCLUDEOLDBROWSERAPI */
	ccNetworkShutdown();
	ccWriteShutdown();
	ccReadShutdown();
	ccDcerpcShutdown();
	ccSdescrShutdown();
	ccSrvsvcShutdown();
	ccSmb10Shutdown();
#ifdef UD_NQ_INCLUDESMB2
	ccSmb20Shutdown();
#ifdef UD_NQ_INCLUDESMB3
	ccSmb30Shutdown();
#endif /* UD_NQ_INCLUDESMB3 */
#ifdef UD_NQ_INCLUDESMB311
	ccSmb311Shutdown();
#endif /* UD_NQ_INCLUDESMB3 */
#endif
	ccSecureShutdown();
	ccConfigShutdown();

	nsExit(TRUE);
	sCcIsInitialized = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: check if the client module initialized
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if initialized, FALSE otherwise
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL ccIsInitialized(void)
{
    return sCcIsInitialized;
}

/*
 *====================================================================
 * PURPOSE: dump client module data tables
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
ccDump(
    void
    )
{
#if SY_DEBUGMODE
    if (sCcIsInitialized)
    {
        ccMountDump();
    }
#endif /* SY_DEBUGMODE */
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
