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

#include "cccifs.h"
#include "ccsmb20.h"
#include "ccsmb10.h"

/* -- Constants -- */
#ifdef UD_NQ_INCLUDESMB2
#define NUM_DIALECTS 2
#ifdef ANY_SMB2
#define NUM_DIALECTS 3
#endif /* ANY_SMB2 */
#else /* UD_NQ_INCLUDESMB2 */
#define NUM_DIALECTS 1
#endif /* UD_NQ_INCLUDESMB2 */

/* -- Static data -- */

const CCCifsSmb * cifsDialects[NUM_DIALECTS];

/* -- API Functions */

NQ_BOOL ccCifsStart(void)
{
	cifsDialects[0] = ccSmb10GetCifs();
#ifdef UD_NQ_INCLUDESMB2
	cifsDialects[1] = ccSmb20GetCifs();
#ifdef ANY_SMB2
    {
        static CCCifsSmb anySmb2Dialect;
	    static const NQ_CHAR * anySmb2String = "SMB 2.???";
    	
	    anySmb2Dialect = *ccSmb20GetCifs();	/* copy SMB2.0 dialect */
	    anySmb2Dialect.name = anySmb2String;
	    cifsDialects[2] = &anySmb2Dialect;
    }
#endif /* ANY_SMB2 */
#endif /* UD_NQ_INCLUDESMB2 */
	return TRUE;
}

void ccCifsShutdown(void)
{
}

const CCCifsSmb * ccCifsGetDefaultSmb(void)
{
	return cifsDialects[0];
}

NQ_INT ccCifsGetDialects(const CCCifsSmb *** dialects)
{
	*dialects = cifsDialects;
	return NUM_DIALECTS;
}


