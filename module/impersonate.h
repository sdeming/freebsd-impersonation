/*
 * The MIT License
 *
 * Copyright (c) 2003 Scott Deming 
 * All rights reserved.
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/acct.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/pioctl.h>
#include <sys/resourcevar.h>

#define VERBOSE
#undef	SIMPLE
#define	COMPLETE

/* --------------------------------------------------------------------- */
/* impersonation rules                                                   */
/* --------------------------------------------------------------------- */
struct imp_ruleset {
  int rule_no;       /* rule number (not necessarily unique) */
  uid_t req_uid;     /* requestor user id (all=-1) */
  int action;        /* action (deny=0 allow=1) */
  uid_t act_uid;     /* action user id (all=-1) */ 

  struct imp_ruleset *next;
};
extern struct imp_ruleset *imp_rules;

