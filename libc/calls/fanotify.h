#ifndef COSMOPOLITAN_LIBC_CALLS_FANOTIFY_H_
#define COSMOPOLITAN_LIBC_CALLS_FANOTIFY_H_
COSMOPOLITAN_C_START_

#define FAN_ACCESS         0x00000001
#define FAN_MODIFY         0x00000002
#define FAN_ATTRIB         0x00000004
#define FAN_CLOSE_WRITE    0x00000008
#define FAN_CLOSE_NOWRITE  0x00000010
#define FAN_OPEN           0x00000020
#define FAN_MOVED_FROM     0x00000040
#define FAN_MOVED_TO       0x00000080
#define FAN_CREATE         0x00000100
#define FAN_DELETE         0x00000200
#define FAN_DELETE_SELF    0x00000400
#define FAN_MOVE_SELF      0x00000800
#define FAN_OPEN_EXEC      0x00001000
#define FAN_Q_OVERFLOW     0x00004000
#define FAN_FS_ERROR       0x00008000
#define FAN_OPEN_PERM      0x00010000
#define FAN_ACCESS_PERM    0x00020000
#define FAN_OPEN_EXEC_PERM 0x00040000
#define FAN_EVENT_ON_CHILD 0x08000000
#define FAN_RENAME         0x10000000
#define FAN_ONDIR          0x40000000
#define FAN_CLOSE          (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE)
#define FAN_MOVE           (FAN_MOVED_FROM | FAN_MOVED_TO)

#define FAN_CLOEXEC           0x00000001
#define FAN_NONBLOCK          0x00000002
#define FAN_CLASS_NOTIF       0x00000000
#define FAN_CLASS_CONTENT     0x00000004
#define FAN_CLASS_PRE_CONTENT 0x00000008
#define FAN_UNLIMITED_QUEUE   0x00000010
#define FAN_UNLIMITED_MARKS   0x00000020
#define FAN_ENABLE_AUDIT      0x00000040
#define FAN_REPORT_PIDFD      0x00000080
#define FAN_REPORT_TID        0x00000100
#define FAN_REPORT_FID        0x00000200
#define FAN_REPORT_DIR_FID    0x00000400
#define FAN_REPORT_NAME       0x00000800
#define FAN_REPORT_TARGET_FID 0x00001000
#define FAN_REPORT_DFID_NAME  (FAN_REPORT_DIR_FID | FAN_REPORT_NAME)
#define FAN_REPORT_DFID_NAME_TARGET \
  (FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID)

#define FAN_MARK_ADD                 0x00000001
#define FAN_MARK_REMOVE              0x00000002
#define FAN_MARK_DONT_FOLLOW         0x00000004
#define FAN_MARK_ONLYDIR             0x00000008
#define FAN_MARK_MOUNT               0x00000010
#define FAN_MARK_IGNORED_MASK        0x00000020
#define FAN_MARK_IGNORED_SURV_MODIFY 0x00000040
#define FAN_MARK_FLUSH               0x00000080
#define FAN_MARK_FILESYSTEM          0x00000100
#define FAN_MARK_EVICTABLE           0x00000200
#define FAN_MARK_IGNORE              0x00000400
#define FAN_MARK_INODE               0x00000000
#define FAN_MARK_IGNORE_SURV \
  (FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY)

#define FANOTIFY_METADATA_VERSION 3

#define FAN_EVENT_INFO_TYPE_FID       1
#define FAN_EVENT_INFO_TYPE_DFID_NAME 2
#define FAN_EVENT_INFO_TYPE_DFID      3
#define FAN_EVENT_INFO_TYPE_PIDFD     4
#define FAN_EVENT_INFO_TYPE_ERROR     5

#define FAN_ALLOW 0x01
#define FAN_DENY  0x02
#define FAN_AUDIT 0x10
#define FAN_INFO  0x20

#define FAN_NOFD    -1
#define FAN_NOPIDFD FAN_NOFD
#define FAN_EPIDFD  -2

struct fanotify_event_metadata {
  uint32_t event_len;
  uint8_t vers;
  uint8_t reserved;
  uint16_t metadata_len;
  uint64_t mask;
  int32_t fd;
  int32_t pid;
};

struct fanotify_event_info_header {
  uint8_t info_type;
  uint8_t pad;
  uint16_t len;
};

struct fanotify_event_info_pidfd {
  struct fanotify_event_info_header hdr;
  int32_t pidfd;
};

struct fanotify_event_info_error {
  struct fanotify_event_info_header hdr;
  int32_t error;
  uint32_t error_count;
};

struct fanotify_response {
  int32_t fd;
  uint32_t response;
};

#define FAN_EVENT_METADATA_LEN (sizeof(struct fanotify_event_metadata))
#define FAN_EVENT_OK(meta, len)                                   \
  ((long)(len) >= (long)FAN_EVENT_METADATA_LEN &&                 \
   (long)(meta)->event_len >= (long)FAN_EVENT_METADATA_LEN &&     \
   (long)(meta)->event_len <= (long)(len))
#define FAN_EVENT_NEXT(meta, len)                                 \
  ((len) -= (meta)->event_len,                                    \
   (struct fanotify_event_metadata *)(((char *)(meta)) +          \
                                      (meta)->event_len))

int fanotify_init(unsigned, unsigned);
int fanotify_mark(int, unsigned, uint64_t, int, const char *);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_FANOTIFY_H_ */
