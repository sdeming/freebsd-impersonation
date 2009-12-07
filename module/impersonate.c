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
#include <sys/time.h>
#include <sys/resourcevar.h>

MALLOC_DEFINE(M_IMPERS, "Impersonate", "Impersonate Rules");

#define VERBOSE
#undef	SIMPLE
#define	COMPLETE
#define DEBUG

#define IMPERS_DEFAULT_TTL 60

/* --------------------------------------------------------------------- */
/* impersonation rules                                                   */
/* --------------------------------------------------------------------- */
struct imp_ruleset {
  int rule_no;       /* rule number (not necessarily unique) */
  uid_t req_uid;     /* requestor user id (all=-1) */
  int action;        /* action (deny=0 allow=1) */
  uid_t act_uid;     /* action user id (all=-1) */ 
  int count;         /* hit count */

  struct imp_ruleset *next;
};
struct imp_ruleset *imp_rules;

/* --------------------------------------------------------------------- */
/* utility function to fill a char buffer with rule description text     */
/* --------------------------------------------------------------------- */
static void imp_rule_text(char *buf, struct imp_ruleset *rule)
{
  snprintf(buf, 80, "%-6d %-5d => %-5d %s (hits: %d)\n", 
    rule->rule_no,
    rule->req_uid, 
    rule->act_uid,
    rule->action?"allow":"deny",
    rule->count);
}

/* --------------------------------------------------------------------- */
/* Internal function for clearing the entire rule set                    */
/* --------------------------------------------------------------------- */
static void imp_clear_rules(void)
{
  struct imp_ruleset *walk = imp_rules;
  while (walk != NULL) {
    struct imp_ruleset *me = walk;
    walk = walk->next; 
    free(me, M_IMPERS);
  }
}

/* --------------------------------------------------------------------- */
/* Internal function for adding a new rule.                              */
/* --------------------------------------------------------------------- */
static int imp_add_rule(struct imp_ruleset *rule)
{
  /* declare working ruleset structs */
  struct imp_ruleset *walk = imp_rules;
  struct imp_ruleset *prev;
  
  /* if this is our first rule, set imp_rules */
  if (walk == NULL) {
    imp_rules = rule; 
    return 0;
  }

  /* walk the rule set until the right place is found */
  prev = NULL;
  while (walk != NULL) {

    /* check for duplicate */
    if (walk->rule_no == rule->rule_no && 
        walk->req_uid == rule->req_uid &&
        walk->act_uid == rule->act_uid &&
        walk->action  == rule->action) {
      return EEXIST;
    }

    /* inserting at the head */
    if (walk->rule_no > rule->rule_no) {
      if (prev == NULL) {
        rule->next = imp_rules;
        imp_rules = rule;
        return 0;
      }

      rule->next = walk;
      prev->next = rule;
      return 0;
    }

    /* inserting at the tail */
    if (walk->next == NULL) {
      walk->next = rule;
      return 0;
    }

    /* inserting somewhere in between */
    if (walk->next->rule_no > rule->rule_no) {
      rule->next = walk->next;
      walk->next = rule;
      return 0;
    }

    prev = walk;
    walk = walk->next;
  } /* while walking rules */

  return 0;
}

/* --------------------------------------------------------------------- */
/* Internal function for deleting a rule.                                */
/* --------------------------------------------------------------------- */
static int imp_del_rule(int rule_no)
{
  struct imp_ruleset *walk = imp_rules;
  struct imp_ruleset *prev;

  prev = NULL;
  while (walk != NULL) {

    if (walk->rule_no == rule_no) {
      if (prev == NULL) {
        imp_rules = walk->next;
        free(walk, M_IMPERS);
        return 1;
      } 
      prev->next = walk->next;
      free(walk, M_IMPERS);
      return 1;
    }

    prev = walk;
    walk = walk->next;
  }

  /* nothing deleted */
  return 0;
}

/* --------------------------------------------------------------------- */
/* Internal function for locaing an action based on req/act_uid pair     */
/* --------------------------------------------------------------------- */
static int imp_find_action(uid_t req_uid, uid_t act_uid) 
{
  struct imp_ruleset *walk = imp_rules;

  while (walk != NULL) {

    if ((walk->req_uid == req_uid || walk->req_uid == -1) &&
        (walk->act_uid == act_uid || walk->act_uid == -1)) {
      walk->count++;
      return walk->action;
    }

    walk = walk->next;
  }

  /* default to deny */
  return 0;
}

/* --------------------------------------------------------------------- */
/* Internal function for dumping rules details to a user.                */
/* --------------------------------------------------------------------- */
static int imp_dump_rules(void)
{
  struct imp_ruleset *walk = imp_rules;
  char text[81];
  int count=0;

  while (walk != NULL) {
    count++;
    imp_rule_text(text, walk); 
    uprintf("%s", text);
    walk = walk->next;
  }

  return count;
}

/* --------------------------------------------------------------------- */
/* impersonate sessions                                                  */
/* --------------------------------------------------------------------- */
struct imp_session {
  pid_t pid;         /* key: pid //TODO: fix this with unique hash!!! */

  uid_t initial_uid; /* initial uid for process */
  gid_t initial_gid; /* initial uid for process */
  uid_t current_uid; /* current uid for process */
  uid_t current_gid; /* current uid for process */

  int count;         /* hit count */
  int ttl;           /* session ttl */
  time_t last_visit; /* last time this session was visited */

  struct imp_session *prev;
  struct imp_session *next;
};
struct imp_session *imp_sessions;

/* --------------------------------------------------------------------- */
/* utility function to remove a session from the list and free memory.   */
/* --------------------------------------------------------------------- */
static void imp_free_session(struct imp_session *sess)
{
  struct imp_session *prev = sess->prev;
  struct imp_session *next = sess->next;

  if (!prev) {
    imp_sessions = next;
  }
  else {
    prev->next = next;
  }

  if (next) { 
    next->prev = prev;
  }

  free(sess, M_IMPERS);
}

/* --------------------------------------------------------------------- */
/* utility function to tick down the ttl of a session and remove it if   */
/* it has expired.                                                       */
/* --------------------------------------------------------------------- */
static int imp_expire_session(struct imp_session *sess)
{
  static int last_visit = 0;
  int visit = time_second;
  int seconds;
  struct proc *pt;

  /* no use in doing this more than once per second */
  if (last_visit == visit) {
    return 0;
  }

  /* first we want to find out of the process is dead */
  pt = pfind(sess->pid);
  if (!pt) {
    imp_free_session(sess);
    return 1;
  } 

  /* we only care about sessions who are in original state */
  if (sess->initial_uid != sess->current_uid ||
      sess->initial_gid != sess->current_gid) {
    return 0;
  }

  /* find seconds elapsed since last visit */
  seconds = visit - sess->last_visit;

  /* if it's non zero, reduce ttl and check for removal */
  if (seconds) {
    sess->ttl -= seconds;
    sess->last_visit = visit;
    if (sess->ttl < 1) {
      imp_free_session(sess);
      return 1;
    }
  }

  return 0;
}

/* --------------------------------------------------------------------- */
/* utility function to scrub sessions and remove stale entries.          */
/* --------------------------------------------------------------------- */
static int imp_scrub_sessions(void)
{
  struct imp_session *walk = imp_sessions;
  int count=0;

  while (walk != NULL) {
    struct imp_session *next = walk->next;
    if (imp_expire_session(walk)) {
      walk = next;
      continue;
    }
    walk = walk->next;
  }

  return count;
}

/* --------------------------------------------------------------------- */
/* utility function to find a session for an existing process.           */
/* --------------------------------------------------------------------- */
static struct imp_session *imp_find_session(struct proc *p)
{
  struct imp_session *walk;
  imp_scrub_sessions();

  walk = imp_sessions;
  while (walk != NULL) {
    if (walk->pid == p->p_pid) {
      return walk;
    }
  
    walk = walk->next;
  }

  return NULL;
}

/* --------------------------------------------------------------------- */
/* utility function for creating or updating new session entry.          */
/* --------------------------------------------------------------------- */
static int imp_update_session(struct proc *p, uid_t new_uid, gid_t new_gid)
{
  struct imp_session *sess = imp_find_session(p);

  /* new session */
  if (sess == NULL) {
    sess = malloc(sizeof(struct imp_session), M_IMPERS, M_NOWAIT | M_ZERO);
    if (!sess) {
      return ENOMEM; 
    }

    sess->pid = p->p_pid;
    sess->count = 1;
    sess->ttl = IMPERS_DEFAULT_TTL;
    sess->last_visit = time_second;
    sess->initial_uid = p->p_cred->pc_ucred->cr_uid;
    sess->initial_gid = p->p_cred->pc_ucred->cr_gid;
    sess->current_uid = new_uid;
    sess->current_gid = new_gid;

    sess->prev = NULL;
    sess->next = imp_sessions;

    /* if sessions already exist, prepend to start of list */
    if (imp_sessions) {
      imp_sessions->prev = sess;
    }

    /* this is are new head */
    imp_sessions = sess;

    return 0;
  }

  /* existing session */
  sess->count++;
  sess->ttl = IMPERS_DEFAULT_TTL;
  sess->last_visit = time_second;
  sess->current_uid = new_uid;
  sess->current_gid = new_gid;

  return 0;
}

/* --------------------------------------------------------------------- */
/* utility function to fill a char buffer with session description text  */
/* --------------------------------------------------------------------- */
static void imp_session_text(char *buf, struct imp_session *s)
{
  snprintf(buf, 80, "%-6d %-5d/%-5d => %-5d/%-5d : ttl %-8d (hits: %-8d)\n", 
    s->pid, 
    s->initial_uid, s->initial_gid, 
    s->current_uid, s->current_gid,
    s->ttl,
    s->count);
}

/* --------------------------------------------------------------------- */
/* Internal function for display session details to a user.              */
/* --------------------------------------------------------------------- */
static int imp_dump_sessions(void)
{
  struct imp_session *walk;
  char text[81];
  int count=0;

  imp_scrub_sessions();

  walk = imp_sessions;
  while (walk != NULL) {
    count++;
    imp_session_text(text, walk);
    uprintf("%s", text);
    walk = walk->next;
  }

  return count;
}

/* --------------------------------------------------------------------- */
/* impersonate_add_rule() system call implementation                     */
/* --------------------------------------------------------------------- */
static int impersonate_add_rule_offset = NO_SYSCALL;
struct imp_add_rule_args {
  int rule_no;
  uid_t req_uid;
  int action;
  uid_t act_uid;
};

static int impersonate_add_rule(struct proc *p, struct imp_add_rule_args *uap)
{
  int err;
  int rule_no;
  int action;
  uid_t req_uid, act_uid;
  struct imp_ruleset *new_rule;

  /* must be root! */
  if (p->p_cred->pc_ucred->cr_uid != 0) {
    return EPERM;
  }

  /* grab args from uap */
  rule_no = uap->rule_no;
  req_uid = uap->req_uid;
  action = uap->action;
  act_uid = uap->act_uid;

  /* check action, return ENOENT if not valid */
  if (action != 0 && action != 1) {
    return ENOENT;
  }

  /* try to allocate space for new rule, return ENOMEM on failure */
  new_rule = malloc(sizeof(struct imp_ruleset), M_IMPERS, M_NOWAIT | M_ZERO);
  if (new_rule == NULL) {
    return ENOMEM;
  }

  /* copy parameters into rule */
  new_rule->rule_no = rule_no;
  new_rule->req_uid = req_uid;
  new_rule->action = action;
  new_rule->act_uid = act_uid;
  new_rule->next = NULL;

  err = imp_add_rule(new_rule);
  
  imp_dump_rules();

  return err;
}

static struct sysent impersonate_add_rule_sysent = {
  4,                   /* sy_narg */
  impersonate_add_rule /* sy_call */
};

static int load_impersonate_add_rule (struct module *module, int cmd, void *arg)
{
  int error = 0;

  switch (cmd) {
  case MOD_LOAD :
    imp_rules = NULL;
    imp_sessions = NULL;
    printf ("impersonate_add_rule loaded at %d\n", impersonate_add_rule_offset);
    break;

  case MOD_UNLOAD :
    imp_clear_rules();
    printf ("impersonate_add_rule unloaded from %d\n", impersonate_add_rule_offset);
    break;

  default :
    error = EINVAL;
    break;
  }

  return error;
}

/* --------------------------------------------------------------------- */
/* impersonate_del_rule() system call implementation                     */
/* --------------------------------------------------------------------- */
static int impersonate_del_rule_offset = NO_SYSCALL;
struct imp_del_rule_args {
  int rule_no;
};

static int impersonate_del_rule(struct proc *p, struct imp_del_rule_args *uap)
{
  int rule_no;

  /* must be root! */
  if (p->p_cred->pc_ucred->cr_uid != 0) {
    return EPERM;
  }

  /* grab args from uap */
  rule_no = uap->rule_no;

  if (0 == imp_del_rule(rule_no)) {
    imp_dump_rules();
    return ENOENT;
  }

  imp_dump_rules();

  return 0;
}

static struct sysent impersonate_del_rule_sysent = {
  1,                   /* sy_narg */
  impersonate_del_rule /* sy_call */
};

static int load_impersonate_del_rule (struct module *module, int cmd, void *arg)
{
  int error = 0;

  switch (cmd) {
  case MOD_LOAD :
    printf ("impersonate_del_rule loaded at %d\n", impersonate_del_rule_offset);
    break;

  case MOD_UNLOAD :
    printf ("impersonate_del_rule unloaded from %d\n", impersonate_del_rule_offset);
    break;

  default :
    error = EINVAL;
    break;
  }

  return error;
}

/* --------------------------------------------------------------------- */
/* impersonate_show() system call implementation                         */
/* --------------------------------------------------------------------- */
static int impersonate_show_offset = NO_SYSCALL;

static int impersonate_show(struct proc *p, void *args)
{
  /* must be root! */
  if (p->p_cred->pc_ucred->cr_uid != 0) {
    return EPERM;
  }

  imp_dump_rules();
  return 0;
}

static struct sysent impersonate_show_sysent = {
  0,                   /* sy_narg */
  impersonate_show     /* sy_call */
};

static int load_impersonate_show (struct module *module, int cmd, void *arg)
{
  int error = 0;

  switch (cmd) {
  case MOD_LOAD :
    printf ("impersonate_show loaded at %d\n", impersonate_show_offset);
    break;

  case MOD_UNLOAD :
    printf ("impersonate_show unloaded from %d\n", impersonate_show_offset);
    break;

  default :
    error = EINVAL;
    break;
  }

  return error;
}

/* --------------------------------------------------------------------- */
/* impersonate_show_sessions() system call implementation                */
/* --------------------------------------------------------------------- */
static int impersonate_show_sessions_offset = NO_SYSCALL;

static int impersonate_show_sessions(struct proc *p, void *args)
{
  /* must be root! */
  if (p->p_cred->pc_ucred->cr_uid != 0) {
    return EPERM;
  }

  imp_dump_sessions();
  return 0;
}

static struct sysent impersonate_show_sessions_sysent = {
  0,                   		/* sy_narg */
  impersonate_show_sessions     /* sy_call */
};

static int load_impersonate_show_sessions (struct module *module, int cmd, void *arg)
{
  int error = 0;

  switch (cmd) {
  case MOD_LOAD :
    printf ("impersonate_show_sessions loaded at %d\n", impersonate_show_sessions_offset);
    break;

  case MOD_UNLOAD :
    printf ("impersonate_show_sessions unloaded from %d\n", impersonate_show_sessions_offset);
    break;

  default :
    error = EINVAL;
    break;
  }

  return error;
}

/* --------------------------------------------------------------------- */
/* impersonate() system call implementation                              */
/* --------------------------------------------------------------------- */
static int impersonate_offset = NO_SYSCALL;
struct impersonate_args {
 uid_t new_uid;
 gid_t new_gid; 
};

static int impersonate (struct proc *p, struct impersonate_args *uap) 
{
  struct imp_session *sess = NULL;
  uid_t new_uid = uap->new_uid;
  gid_t new_gid = uap->new_gid;
  uid_t old_uid = p->p_cred->pc_ucred->cr_uid;
  gid_t old_gid = p->p_cred->pc_ucred->cr_gid;
  int action_cd = 0;
  int s;

  /* while it's always fun to impersonate ones own self, it is wholely
   * unnecessary. */
  if (old_uid == new_uid && old_gid == new_gid) {
    return 0;
  }

  s = splimp();

  /* look for an existing session and see if we're trying to return to
   * our original state */
  sess = imp_find_session(p);
  if (sess && new_uid == sess->initial_uid && new_gid == sess->initial_gid) {
    action_cd = 1;
  }

  /* check permissions */
  if (!action_cd) {
    action_cd = imp_find_action(old_uid, new_uid);
  }

  if (action_cd != 1) {
    printf("illegal attempt to impersonate(): %d => %d denied.\n",
      old_uid, new_uid);
    splx(s);
    return EPERM;
  }

  imp_update_session(p, new_uid, new_gid);

  /*printf("impersonate(): %d/%d => %d/%d allowed.\n",
   *old_uid, old_gid, new_uid, new_gid);
   */

#ifdef SIMPLE

  p->p_cred->pc_ucred->cr_uid = new_uid;
  p->p_cred->pc_ucred->cr_gid = new_gid;
#endif

#ifdef COMPLETE
  /* set uid */
  change_ruid(p, new_uid);
  setsugid(p);

  p->p_cred->p_svuid = new_uid;
  setsugid(p);

  change_euid(p, new_uid);
  setsugid(p);

  /* set gid */
  p->p_cred->p_rgid = new_gid;
  setsugid(p);

  p->p_cred->p_svgid = new_gid;
  setsugid(p);

  p->p_cred->pc_ucred = crcopy(p->p_cred->pc_ucred);
  p->p_cred->pc_ucred->cr_groups[0] = new_gid;
  setsugid(p);
#endif

  splx(s);
  return 0;
}

static struct sysent impersonate_sysent = {
  2,                   /* sy_narg */
  impersonate          /* sy_call */
};

static int load_impersonate (struct module *module, int cmd, void *arg)
{
  int error = 0;

  switch (cmd) {
  case MOD_LOAD :
    printf ("impersonate loaded at %d\n", impersonate_offset);
    break;

  case MOD_UNLOAD :
    printf ("impersonate unloaded from %d\n", impersonate_offset);
    break;

  default :
    error = EINVAL;
    break;
  }

  return error;
}


/* --------------------------------------------------------------------- */
/* register impersonate_add_rule                                         */
/* --------------------------------------------------------------------- */
SYSCALL_MODULE(
  impersonate_add_rule, 
  &impersonate_add_rule_offset, 
  &impersonate_add_rule_sysent, 
  load_impersonate_add_rule, 
  NULL);

/* --------------------------------------------------------------------- */
/* register impersonate_del_rule                                         */
/* --------------------------------------------------------------------- */
SYSCALL_MODULE(
  impersonate_del_rule, 
  &impersonate_del_rule_offset, 
  &impersonate_del_rule_sysent, 
  load_impersonate_del_rule, 
  NULL);

/* --------------------------------------------------------------------- */
/* register impersonate_show                                             */
/* --------------------------------------------------------------------- */
SYSCALL_MODULE(
  impersonate_show, 
  &impersonate_show_offset, 
  &impersonate_show_sysent, 
  load_impersonate_show,
  NULL);

/* --------------------------------------------------------------------- */
/* register impersonate_show_sessions                                    */
/* --------------------------------------------------------------------- */
SYSCALL_MODULE(
  impersonate_show_sessions, 
  &impersonate_show_sessions_offset, 
  &impersonate_show_sessions_sysent, 
  load_impersonate_show_sessions,
  NULL);

/* --------------------------------------------------------------------- */

/* --------------------------------------------------------------------- */
/* register impersonate                                                  */
/* --------------------------------------------------------------------- */
SYSCALL_MODULE(
  impersonate, 
  &impersonate_offset, 
  &impersonate_sysent, 
  load_impersonate, 
  NULL);


