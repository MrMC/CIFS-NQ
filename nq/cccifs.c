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

#include "ccapi.h"
#include "cccifs.h"
#include "ccsmb311.h"
#include "ccsmb30.h"
#include "ccsmb20.h"
#include "ccsmb10.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data -- */

typedef struct{
    const CCCifsSmb *dialect;
    NQ_BOOL isActive;
}CCCifsSmbDialect;

static CCCifsSmbDialect cifsDialects[CCCIFS_SMB_NUM_DIALECTS];
static SYMutex cifsDialectsGuard;

/* -- API Functions */

NQ_BOOL ccCifsStart(void)
{
	NQ_INT dialectCount = 0;

    cifsDialects[dialectCount].dialect = ccSmb10GetCifs();
    cifsDialects[dialectCount++].isActive = TRUE;
#ifdef UD_NQ_INCLUDESMB2
    cifsDialects[dialectCount].dialect = ccSmb20GetCifs();
    cifsDialects[dialectCount++].isActive = TRUE;
    {
        static CCCifsSmb Smb0210Dialect;

        Smb0210Dialect = *ccSmb20GetCifs();	/* copy SMB 2.002 dialect */
        Smb0210Dialect.name = SMB2_1_DIALECTSTRING;
        Smb0210Dialect.revision = SMB2_1_DIALECTREVISION; 
        cifsDialects[dialectCount].dialect = &Smb0210Dialect;
        cifsDialects[dialectCount++].isActive = TRUE;
    }
#ifdef UD_NQ_INCLUDESMB3
    cifsDialects[dialectCount].dialect = ccSmb30GetCifs();
    cifsDialects[dialectCount++].isActive = TRUE;
    {
        static CCCifsSmb Smb0302Dialect;

        Smb0302Dialect = *ccSmb30GetCifs(); /* copy SMB 3.000 dialect */
        Smb0302Dialect.name = SMB3_0_2_DIALECTSTRING;
        Smb0302Dialect.revision = SMB3_0_2_DIALECTREVISION;
        cifsDialects[dialectCount].dialect = &Smb0302Dialect;
        cifsDialects[dialectCount++].isActive = TRUE;
    }
#ifdef UD_NQ_INCLUDESMB311
    cifsDialects[dialectCount].dialect = ccSmb311GetCifs();
    cifsDialects[dialectCount++].isActive = TRUE;
#endif /* UD_NQ_INCLUDESMB311 */
#endif /* UD_NQ_INCLUDESMB3 */
#endif /* UD_NQ_INCLUDESMB2 */
#if defined(UD_NQ_INCLUDESMB3) || defined(CCCIFS_SMB_ANY_SMB2)
    {
        static CCCifsSmb anySmb2Dialect;
        static const NQ_CHAR * anySmb2String = "SMB 2.???";

        anySmb2Dialect = *ccSmb20GetCifs();	/* copy SMB2.0 dialect */
        anySmb2Dialect.name = anySmb2String;
        anySmb2Dialect.revision = CCCIFS_ILLEGALSMBREVISION;
        cifsDialects[dialectCount].dialect = &anySmb2Dialect;
        cifsDialects[dialectCount++].isActive = TRUE;
    }
#endif /* defined(UD_NQ_INCLUDESMB3) || defined(CCCIFS_SMB_ANY_SMB2) */

    syMutexCreate(&cifsDialectsGuard);

	return TRUE;
}

void ccCifsShutdown(void)
{
    syMutexDelete(&cifsDialectsGuard);
}

const CCCifsSmb * ccCifsGetDefaultSmb(void)
{
	return cifsDialects[0].dialect;
}

NQ_INT ccCifsGetDialects(const CCCifsSmb *** dialects)
{
    NQ_INT dialectsNum = 0;
    NQ_COUNT i;
    const CCCifsSmb **dialectsActive = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "dialects:%p", dialects);

    dialectsActive = (const CCCifsSmb **)cmMemoryAllocate(CCCIFS_SMB_NUM_DIALECTS * sizeof(cifsDialects[0].dialect));
    if (NULL == dialectsActive)
    {
        *dialects = NULL;
        goto Exit;
    }

    syMutexTake(&cifsDialectsGuard);
    for (i = 0; i < CCCIFS_SMB_NUM_DIALECTS; i++)
    {
        if (cifsDialects[i].dialect != NULL && cifsDialects[i].isActive)
        {
            dialectsActive[dialectsNum++] = cifsDialects[i].dialect;
        }
    }
    *dialects = dialectsActive;
    syMutexGive(&cifsDialectsGuard);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "dialectsNum:%d", dialectsNum);
    return dialectsNum;
}

NQ_BOOL ccSetSmbDialect(CCSmbDialect dialect, NQ_BOOL setActive)
{
    NQ_BOOL result = FALSE;
    NQ_INT i;
    NQ_UINT16 revision;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "dialect:%d setActive:%d", dialect, setActive);

    switch (dialect)
    {
    case CC_SMB100:
        revision = CCCIFS_ILLEGALSMBREVISION;
        break;
    case CC_SMB202:
        revision = SMB2_DIALECTREVISION;
        break;
    case CC_SMB210:
        revision = SMB2_1_DIALECTREVISION;
        break;
    case CC_SMB300:
        revision = SMB3_DIALECTREVISION;
        break;
    case CC_SMB302:
        revision = SMB3_0_2_DIALECTREVISION;
        break;
    case CC_SMB311:
        revision = SMB3_1_1_DIALECTREVISION;
        break;
    default:
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid dialect:0x%x", dialect);
        goto Exit;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dialect:0x%x", revision);

    syMutexTake(&cifsDialectsGuard);
    for (i = 0; i < CCCIFS_SMB_NUM_DIALECTS; i++)
    {
        if (cifsDialects[i].dialect != NULL && cifsDialects[i].dialect->revision == revision)
        {
            cifsDialects[i].isActive = setActive;
            result = TRUE;
            break;
        }
    }
    syMutexGive(&cifsDialectsGuard);
    
Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */

