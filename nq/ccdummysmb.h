/*
 * ccdummysmb.h
 *
 *  Created on: Oct 27, 2016
 *      Author: iland
 */

#ifndef NQE2_NQ_CCDUMMYSMB_H_
#define NQE2_NQ_CCDUMMYSMB_H_

/* -- API Functions */

/* Description
   Initialize this module.
   Returns
   None
 */
NQ_BOOL ccSmbDummyStart(void);

/* Description
   Release resources used by this module.
   Returns
   <i>TRUE</i> on success and <i>FALSE</i> on failure.
 */
NQ_BOOL ccSmbDummyShutdown(void);

/* Description
   Get dialect descriptor
   Returns
   Pointer to dialect descriptor.
 */
const CCCifsSmb * ccSmbDummyGetCifs(void);


#endif /* NQE2_NQ_CCDUMMYSMB_H_ */
