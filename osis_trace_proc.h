/*
 * Created on Mon Dec 23 2024
 *
 *               Copyright (c) 2024 Owen Jiang
 *
 * This program is free software. You may use, modify, and redistribute it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 or (at your option) any
 * later version. This program is distributed without any warranty.  See
 * the file COPYING.gpl-v3 for details.
 *
 */
#ifndef __osis_trace_proc_H__
#define __osis_trace_proc_H__
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <list>
#include <string>

#include "osis_ptrace.h"
#include "osis_tools.h"
namespace OSIS
{
typedef long (*attach_callback_func)(void* psrv, pid_t tid, int64_t flag,int type);
class thread_info
{
   public:
    thread_info();
    ~thread_info();
    int tid;
    int t_flg;
      /* If this flag is set, we need to set the event request flags the
     next time we see this LWP stop.  */
    int must_set_ptrace_flags = 0;
    /* Non-zero if we sent this LWP a SIGSTOP (but the LWP didn't report
  it back yet).  */
    int signalled = 0;

    /* Non-zero if this LWP is stopped.  */
    int stopped = 0;

    /* Non-zero if this LWP will be/has been resumed.  Note that an LWP
       can be marked both as stopped and resumed at the same time.  This
       happens if we try to resume an LWP that has a wait status
       pending.  We shouldn't let the LWP run until that wait status has
       been processed, but we should not report that wait status if GDB
       didn't try to let the LWP run.  */
    int resumed = 0;
    int setvalue(int64_t value);
    OSIS::x86_64_all_reg X_all_reg;
};
class Osis_TraceProc
{
   public:
    Osis_TraceProc();
    ~Osis_TraceProc();
    long set_pid(pid_t pid);
    long get_pid(pid_t& pid);
    long set_m_stat(int v);
    long get_m_statd(int& pid);
    long safe_ptrace_attach_all();
    long init(void* p);
    static long osisProcAttachCallback(void* psrv, pid_t tid, int64_t flag,int type);
    static long osisThreadAttachCallback(void* psrv, pid_t tid, int64_t flag,int type);
    std::list<thread_info> m_threadInfoList;
    void test();
    long safe_detach_all();
    long stop_all_threade();
    long stop_one_thread(pid_t tid);
    long stop_wait_allthread();
    long stop_wait_onethrede(pid_t tid);
    void block_child_signals (sigset_t *prev_mask);
    void restore_child_signals_mask (sigset_t *prev_mask);
    long delete_threadinfo_by_tid(pid_t tid);
    long detach_allthread();
    long detach_one_thread(pid_t tid,thread_info ti);
    long save_allreg(pid_t tid);
    long restore_allreg(pid_t tid);
    long adjust_process_not_in_syscall();
    long adjust_not_in_syscall_pid(pid_t tid);
    long retrieve_base_address();
    long stop_wait_bp(pid_t pid);
   private:
    pid_t _pid;
    int m_stat;
    attach_callback_func pf_Procee_attch_cb;
    attach_callback_func pf_Thread_attch_cb;
    sigset_t blocked_mask;
    sigset_t suspend_mask;
    sigset_t pass_mask;
    Elf64_Addr base_addr;
    void* psrv;
};
}  // namespace OSIS

#endif