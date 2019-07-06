/*
 * SyncUtils.hpp
 *
 *  Created on: Jun 23, 2016
 *      Author: user
 */

#ifndef ENCLAVE_FORK_TRUSTED_SYNCUTILS_HPP_
#define ENCLAVE_FORK_TRUSTED_SYNCUTILS_HPP_

#ifdef __cplusplus
extern "C" {
#endif

void spin_lock(unsigned char volatile *p);
void spin_unlock(unsigned char volatile *p);

#ifdef __cplusplus
}
#endif

#endif /* ENCLAVE_FORK_TRUSTED_SYNCUTILS_HPP_ */
