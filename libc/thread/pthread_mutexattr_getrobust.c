#include "libc/thread/lock.h"
#include "libc/thread/thread.h"

/**
 * Gets robustness of mutex attributes.
 *
 * @param robust receives PTHREAD_MUTEX_STALLED or PTHREAD_MUTEX_ROBUST
 * @return 0 on success, or error number on failure
 */
errno_t pthread_mutexattr_getrobust(const pthread_mutexattr_t *attr,
                                    int *robust) {
  *robust = MUTEX_ROBUST(attr->_word);
  return 0;
}

__weak_reference(pthread_mutexattr_getrobust, pthread_mutexattr_getrobust_np);
