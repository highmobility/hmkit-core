/*
 * hmsensing.h
 *
 *      Author: High-Mobility
 */

#ifndef HM_SENSING_H_
#define HM_SENSING_H_

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

void hmsensing_init(void);
void hmsensing_clock(void);

#ifdef __cplusplus
}
#endif

#endif /* HM_SENSING_H_ */
