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
#include <stdlib.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>

static int do_imp_findmod(struct module_stat *stat)
{
  int e, mod_id;
 
  stat->version = sizeof(struct module_stat);      
  mod_id = modfind("impersonate");
  if (-1 == mod_id) {
    perror("imp->modfind");
    return -1;
  }
 
  e = modstat(mod_id, stat);
  if (0 != e) {
    perror("imp->modstat");
    return -1;
  }
 
  return 0;
}

static int do_imp(uid_t uid, gid_t gid)
{
  struct module_stat stat;
  int e, call_num;
 
  if (0 == do_imp_findmod(&stat)) {
    call_num = stat.data.intval;
    e = syscall(call_num, uid, gid);
    if (-1 == e) {
      perror("imp->call");
    }
  }

  return 0;
}

int main()
{
  int x;
  int done=0;

  while (!done) {
    fprintf(stdout, "#");
    fflush(stdout);

    for (x=0; x<100; x++) {
      do_imp(501, 501);
      if (getuid() != 501) {
        fprintf(stdout, "\nimpersonate failed.\n");
        done = 1;
        break;
      }
      do_imp(0, 0);
    }
  }

  return 0;
}
