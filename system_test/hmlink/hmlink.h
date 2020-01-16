/*
 * hmlink.h
 *
 *      Author: High-Mobility
 */

#ifndef HM_LINK_H_
#define HM_LINK_H_

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

void hmlink_init(void);
void hmlink_clock(void);

#ifdef __cplusplus
}
#endif

#endif /* HM_LINK_H_ */
