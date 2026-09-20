#include "libc/system/plaincmd.internal.h"
#include "libc/ctype.h"
#include "libc/macros.h"
#include "libc/str/str.h"

// what _cocmd() runs itself rather than looking for a program
static const char kBuiltins[][8] = {
    "exit",  "exec",  "cd",    "rm",     "[",      "cat",    "env",
    "pwd",   "wait",  "echo",  "read",   "true",   "test",   "kill",
    "pause", "flock", "chmod", "touch",  "rmdir",  "mkdir",  "false",
    "mktemp", "usleep", "toupper", "tr", "sed",    "awk",    "curl",
};

/**
 * Splits command line that's nothing but a program and its arguments.
 *
 * Such a line can be spawned as is. Anything the command interpreter
 * would have to look at is turned down: quoting, redirection, globs,
 * variables, assignments, operators, and the names of its builtins.
 *
 * @param buf receives the words, and needs room for `strlen(cmdline)+1`
 * @param argv receives pointers into `buf` and a terminating null
 * @return number of arguments, or 0 if `cmdline` isn't that simple
 */
int __plaincmd(const char *cmdline, char *buf, char **argv, int maxargs) {
  int argc = 0;
  bool inword = false;
  for (;; ++cmdline, ++buf) {
    int c = *cmdline & 255;
    if (!c || c == ' ' || c == '\t') {
      *buf = 0;
      inword = false;
      if (!c)
        break;
    } else if (isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/' ||
               c == ':' || c == ',' || c == '+' || c == '@') {
      *buf = c;
      if (!inword) {
        if (argc + 1 >= maxargs)
          return 0;
        argv[argc++] = buf;
        inword = true;
      }
    } else {
      return 0;
    }
  }
  if (!argc)
    return 0;
  for (int i = 0; i < ARRAYLEN(kBuiltins); ++i)
    if (!strcmp(argv[0], kBuiltins[i]))
      return 0;
  argv[argc] = 0;
  return argc;
}
