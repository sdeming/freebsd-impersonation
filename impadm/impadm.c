/*
 * The MIT License
 *
 * Copyright (c) 2003 Scott Deming 
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/errno.h>
#include <pwd.h>

void usage(void)
{
  fprintf(stderr, "usage: %0 [options]\n");
  fprintf(stderr, "  add number rule\n");
  fprintf(stderr, "  del number\n");
  fprintf(stderr, "  clear\n");
  fprintf(stderr, "  show [rules|sessions]\n");
  return; 
}

char *strlower(char *s)
{
  char *o = s;
  while (*s++) {
    *s = tolower((int)*s);
  } 
  return o;
}

int add_rule(int rule_no, char *req_user, char *action, char *act_user)
{
  struct passwd *user_info;
  uid_t req_uid;
  uid_t act_uid;
  int action_cd;

  int syscall_num;
  struct module_stat stat;

  if (strncmp(req_user, "all", 3) == 0) {
    req_uid = -1;
  }
  else {
    user_info = getpwnam(req_user);
    if (user_info == NULL) {
      fprintf(stderr, "Cannot find user: %s\n", req_user);
      return ENOENT;
    }
    req_uid = user_info->pw_uid;
  }

  if (strncmp(act_user, "all", 3) == 0) {
    act_uid = -1;
  }
  else {
    user_info = getpwnam(act_user);
    if (user_info == NULL) {
      fprintf(stderr, "Cannot find user: %s\n", act_user);
      return ENOENT;
    }
    act_uid = user_info->pw_uid;
  }

  strlower(action);
  if (strncmp(action, "deny", 4) == 0) {
    action_cd = 0; 
  }
  else if (strncmp(action, "allow", 5) == 0) {
    action_cd = 1;
  }
  else {
    fprintf(stderr, "Unknown action: %s\n", action);
    return ENOENT;
  }

  stat.version = sizeof(stat);
  if (-1 == modstat(modfind("impersonate_add_rule"), &stat)) {
    perror("syscall(impersonate_add_rule)");
    fprintf(stderr, "Are you sure the impersonate module is loaded?\n");
    return ENOENT;
  }
  syscall_num = stat.data.intval;
  if (0 != syscall(syscall_num, rule_no, req_uid, action_cd, act_uid)) {
    perror("add_rule");
  }

  return 0;
}

int del_rule(int rule_no)
{
  int syscall_num;
  struct module_stat stat;

  stat.version = sizeof(stat);
  if (-1 == modstat(modfind("impersonate_del_rule"), &stat)) {
    perror("syscall(impersonate_del_rule)");
    fprintf(stderr, "Are you sure the impersonate module is loaded?\n");
    return ENOENT;
  }
  syscall_num = stat.data.intval;
  if (0 != syscall(syscall_num, rule_no)) {
    perror("del_rule");
  }

  return 0;
}

int clear()
{
  return 0;
}

int show()
{
  int syscall_num;
  struct module_stat stat;

  stat.version = sizeof(stat);
  if (-1 == modstat(modfind("impersonate_show"), &stat)) {
    perror("syscall(impersonate_show)");
    fprintf(stderr, "Are you sure the impersonate module is loaded?\n");
    return ENOENT;
  }
  syscall_num = stat.data.intval;
  if (0 != syscall(syscall_num)) {
    perror("show");
  }

  return 0;
}

int show_sessions()
{
  int syscall_num;
  struct module_stat stat;

  stat.version = sizeof(stat);
  if (-1 == modstat(modfind("impersonate_show_sessions"), &stat)) {
    perror("syscall(impersonate_show_sessions)");
    fprintf(stderr, "Are you sure the impersonate module is loaded?\n");
    return ENOENT;
  }
  syscall_num = stat.data.intval;
  if (0 != syscall(syscall_num)) {
    perror("show_sessions");
  }

  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    usage();
    return 1;
  } 

  strlower(argv[1]);

  if (strncmp(argv[1], "add", 3) == 0) {

    /* format: add 100 allow|deny req_username to_impersonate_username */

    if (argc < 6) {
      usage();
      return 1;
    }
    
    add_rule(atoi(argv[2]), argv[4], argv[3], argv[5]);
  }

  else if (strncmp(argv[1], "del", 3) == 0) {

    /* format: del 100 */
    if (argc < 3) {
      usage();
      return 1;
    }

    del_rule(atoi(argv[2]));
  }

  else if (strncmp(argv[1], "show", 4) == 0) {
    if (argc >= 3) {
      strlower(argv[2]);
    }

    if (argc < 3 || strncmp(argv[2], "rules", 5) == 0) {
      show(); 
    }
    else if (strncmp(argv[2], "sessions", 8) == 0) {
      show_sessions(); 
    }
    else {
      usage();
      return 1;
    }
  }

  return 0;
}
