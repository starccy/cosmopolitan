#include "libc/errno.h"
#include "libc/thread/lock.h"
#include "libc/thread/thread.h"

/**
 * Sets robustness of mutex attributes.
 *
 * Cosmopolitan records the choice and reports it back, but a lock never
 * returns EOWNERDEAD: a mutex whose owner died stays locked, the way a
 * PTHREAD_MUTEX_STALLED one does everywhere. pthread_mutex_consistent()
 * accepts any mutex.
 *
 * @param robust may be PTHREAD_MUTEX_STALLED or PTHREAD_MUTEX_ROBUST
 * @return 0 on success, or EINVAL if `robust` is invalid
 */
errno_t pthread_mutexattr_setrobust(pthread_mutexattr_t *attr, int robust) {
  switch (robust) {
    case PTHREAD_MUTEX_STALLED:
    case PTHREAD_MUTEX_ROBUST:
      attr->_word = MUTEX_SET_ROBUST(attr->_word, robust);
      return 0;
    default:
      return EINVAL;
  }
}

__weak_reference(pthread_mutexattr_setrobust, pthread_mutexattr_setrobust_np);
