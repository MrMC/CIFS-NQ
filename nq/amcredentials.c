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

#include "amcredentials.h"

/* -- API functions -- */
void amCredentialsAsciiiToW(AMCredentialsW * to, const AMCredentialsA *from)
{
    cmAnsiToUnicode(to->domain.name, from->domain.name);
    cmWStrupr(to->domain.name);
    cmAnsiToUnicode(to->domain.realm, from->domain.realm);
    cmAnsiToUnicode(to->user, from->user); 
    cmAnsiToUnicode(to->password, from->password); 
}

void amCredentialsTcharToW(AMCredentialsW * to, const AMCredentials *from)
{
    cmTcharToUnicode(to->domain.name, from->domain.name);
    cmWStrupr(to->domain.name);
    cmTcharToUnicode(to->domain.realm, from->domain.realm);
    cmTcharToUnicode(to->user, from->user); 
    cmTcharToUnicode(to->password, from->password); 
}


