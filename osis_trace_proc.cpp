/*
 * Created on Tue Dec 24 2024
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
#include "osis_trace_proc.h"
OSIS::thread_info::thread_info()
{
    t_flg = -1;
    X_all_reg.pxstate_buff = NULL;
    X_all_reg.xstateBuff_len = 0;
}
OSIS::thread_info::~thread_info() {}
int OSIS::thread_info::setvalue(int64_t value)
{
    /**********bit:63 62.....
          7      6             5            4         3      2                  1        0********** */
    /*   sf       vofresumed    sf   valueofstopped    sf   value of signalled  sf   value of must_set_ptrace_flags */
    if (value & 0x02) {
        must_set_ptrace_flags = (value & 0x01);
    }
    if (value & 0x08) {
        signalled = (value & 0x04) >> 2;
    }
    if (value & 0x20) {
        stopped = (value & 0x10) >> 4;
    }
    if (value & 0x80) {
        resumed = (value & 0x40) >> 6;
    }
    return 0;
}
OSIS::Osis_TraceProc::Osis_TraceProc()
{
    _pid = -1;
    m_stat = -1;
    this->pf_Procee_attch_cb = osisProcAttachCallback;
    this->pf_Thread_attch_cb = osisThreadAttachCallback;
    psrv = NULL;
    sigemptyset(&blocked_mask);
    sigemptyset(&suspend_mask);  // suspend_mask
    sigprocmask(SIG_SETMASK, NULL, &suspend_mask);
    sigdelset(&suspend_mask, SIGCHLD);
    sigemptyset(&pass_mask);
    base_addr=0;
}

OSIS::Osis_TraceProc::~Osis_TraceProc() {}

long OSIS::Osis_TraceProc::set_pid(pid_t pid)
{
    this->_pid = pid;
    return 0;
}

long OSIS::Osis_TraceProc::get_pid(pid_t& pid)
{
    pid = this->_pid;
    return 0;
}
long OSIS::Osis_TraceProc::safe_ptrace_attach_all()
{
    long lRet = -1;
    if (m_stat == -1) return -1;
    if (_pid < 0) return -1;
    if (OSIS::osis_ptrace_attach(_pid, psrv, pf_Procee_attch_cb,false) == -1) {
        printf("ptrace_attach fail pid=%d", _pid);
        return -1;
    }
    m_stat=1; 
    OSIS::linux_proc_attach_tgid_threads(_pid, psrv, pf_Thread_attch_cb);
    for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); it != m_threadInfoList.end(); ++it) {
        printf("threadinfo:tid=%d,flag=%d\n", it->tid, it->t_flg);
    }

    return 0;
}
long OSIS::Osis_TraceProc::stop_all_threade()
{
    long lRet = 0;
    for (std::list<thread_info>::iterator it = this->m_threadInfoList.begin();\ 
     it != this->m_threadInfoList.end();
         ++it) {
        if (!it->stopped && !it->signalled) {
            lRet = stop_one_thread(it->tid);
            printf("kill pid(%d)tid(%d) **<SIGSTOP>** return =%d", _pid, it->tid, lRet);
            it->signalled = 1;
        }
    }
    return lRet;
}
long OSIS::Osis_TraceProc::stop_one_thread(pid_t tid)
{
    long lRet = -1;
    lRet = OSIS::kill_lwp(tid, SIGSTOP);

    return lRet;
}
long OSIS::Osis_TraceProc::stop_wait_allthread()
{
    long lRet = 0;
    std::list<thread_info> tmp_m_threadInfoList = m_threadInfoList;
    for (std::list<thread_info>::iterator it = tmp_m_threadInfoList.begin();\ 
     it != tmp_m_threadInfoList.end();
         ++it) {
        if (!it->stopped) {
            int status;
            status = stop_wait_onethrede(it->tid);
            if (status == 0) continue;
            if (WSTOPSIG(status) != SIGSTOP) {
            } else {
                for (std::list<thread_info>::iterator it_ = m_threadInfoList.begin(); it_ != m_threadInfoList.end();
                     ++it_) {
                    if (it_->tid == it->tid) {
                        it_->signalled = 0;
                    }
                }
            }
        }
    }
    return lRet;
}
long OSIS::Osis_TraceProc::stop_wait_onethrede(pid_t tid)
{
    long lRet = 0;
    sigset_t prev_mask;
    pid_t pid;
    int status = 0;
    int thread_dead = 0;
    /* Make sure SIGCHLD is blocked for sigsuspend avoiding a race below.  */
    block_child_signals(&prev_mask);
    for (;;) {
        pid = waitpid_no_EINTR(tid, &status, __WALL | WNOHANG);
        //  pid = my_waitpid (lp->ptid.lwp (), &status, __WALL | WNOHANG);
        if (pid == -1 && errno == ECHILD) {
            thread_dead = 1;
            printf("pid(%d) tid(%d) vanished.\n", _pid, tid);
        }
        if (pid != 0) break;
        if (_pid == tid && OSIS::linux_proc_pid_has_state(tid, PROC_STATE_ZOMBIE, 1)) {
            thread_dead = 1;
            printf("pid(%d) tid(%d) Thread group leader  vanished.\n", _pid, tid);
            break;
        }
        printf("about to sigsuspend\n");
 //       sigsuspend(&suspend_mask);
    }
    restore_child_signals_mask(&prev_mask);
    if (!thread_dead) {
        printf("waitpid pid(%d) tid(%d)  received %s \n", _pid, tid, status_to_str(status).c_str());
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (_pid == tid) {
                printf("LWP pid(%d) tid(%d) exited.", _pid, tid);
                for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); it != m_threadInfoList.end();
                     ++it) {
                    if (it->tid == tid) {
                        it->signalled = 0;
                        it->stopped = 1;
                        return 0;
                    }
                }
            }
            thread_dead = 1;
            printf(" pid(%d) tid(%d) exited.", _pid, tid);
        }
    }
    if (thread_dead) {
        delete_threadinfo_by_tid(tid);
        return 0;
    }
    if (!(lRet = WIFSTOPPED(status))) return -1;
    for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); it != m_threadInfoList.end(); ++it) {
        if (it->tid == tid) {
            if (it->must_set_ptrace_flags) it->must_set_ptrace_flags = 0;
        }
    }
    /* Handle GNU/Linux's syscall SIGTRAPs.  */
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SYSCALL_SIGTRAP) {
        status = W_STOPCODE(SIGTRAP);
        ptrace(PTRACE_CONT, tid, 0, 0);
        for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); it != m_threadInfoList.end(); ++it) {
            if (it->tid == tid) {
                it->stopped = 0;
            }
        }
        return stop_wait_onethrede(tid);
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        if ((status >> 16) != 0) {
            return 0;
        }
    }

    return status;
}

long OSIS::Osis_TraceProc::delete_threadinfo_by_tid(pid_t tid)
{
    for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); \ 
        it != m_threadInfoList.end();) {
        if (it->tid == tid) {
            it = m_threadInfoList.erase(it);
        } else
            ++it;
    }
    return 0;
}
void OSIS::Osis_TraceProc::block_child_signals(sigset_t* prev_mask)
{
    /* Make sure SIGCHLD is blocked.  */
    if (!sigismember(&blocked_mask, SIGCHLD)) sigaddset(&blocked_mask, SIGCHLD);

    sigprocmask(SIG_BLOCK, &blocked_mask, prev_mask);
}
void OSIS::Osis_TraceProc::restore_child_signals_mask(sigset_t* prev_mask)
{
    sigprocmask(SIG_SETMASK, prev_mask, NULL);
}
long OSIS::Osis_TraceProc::safe_detach_all()
{
    long lRet = 0;
    thread_info main_thread_info;
    if (m_stat == -1) return -1;
    if (_pid < 0) return -1;
    /* Stop all threads before detaching.  ptrace requires that the
     thread is stopped to successfully detach.  */
    lRet = stop_all_threade();
    lRet = stop_wait_allthread();
    lRet = detach_allthread();
    for (std::list<thread_info>::iterator it = m_threadInfoList.begin();\ 
     it != m_threadInfoList.end();
         ++it) {
        if (it->tid == _pid) {
            main_thread_info = *it;
            detach_one_thread(it->tid, main_thread_info);
            break;
        }
    }
    // lRet = detach_one_thread(_pid);
    m_stat=0; 
    return 0;
}
long OSIS::Osis_TraceProc::detach_allthread()
{
    long lRet = -1;
    std::list<thread_info> tmp_m_threadInfoList = m_threadInfoList;
    for (std::list<thread_info>::iterator it = tmp_m_threadInfoList.begin();\ 
     it != tmp_m_threadInfoList.end();
         ++it) {
        if (it->tid != _pid) {
            thread_info target_thread_info = *it;
            detach_one_thread(it->tid, target_thread_info);
        }
    }

    return 0;
}

long OSIS::Osis_TraceProc::detach_one_thread(pid_t tid, thread_info ti)
{
    if (ti.signalled) {
        kill_lwp(tid, SIGCONT);
        for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); it != m_threadInfoList.end(); ++it) {
            if (it->tid != tid) {
                it->signalled = 0;
            }
        }
    }
    OSIS::detach_one_pid(tid, NULL);
    delete_threadinfo_by_tid(tid);
    return 0;
}
long OSIS::Osis_TraceProc::set_m_stat(int v)
{
    m_stat = v;
    return 0;
}
long OSIS::Osis_TraceProc::get_m_statd(int& v)
{
    v = m_stat;
    return 0;
}
long OSIS::Osis_TraceProc::osisProcAttachCallback(void* psrv, pid_t tid, int64_t flag, int type)
{
    long lRet = -1;
    Osis_TraceProc* p_srv = (Osis_TraceProc*)psrv;
    if (!p_srv) return -1;
    if (type == 0) {
        p_srv->delete_threadinfo_by_tid(tid);
        p_srv->test();
        printf("into osisProcAttachCallback pid(%d)\n", tid);
        thread_info ti;
        ti.t_flg = flag;
        ti.tid = tid;
        p_srv->m_threadInfoList.push_back(ti);
    }
    if (type == 1) {
        // p_srv->m_threadInfoList.find
        for (std::list<thread_info>::iterator it = p_srv->m_threadInfoList.begin(); it != p_srv->m_threadInfoList.end();
             ++it) {
            if (it->tid == tid) {
                if (flag) it->setvalue(flag);
            }
        }
    }
    return lRet;
}
long OSIS::Osis_TraceProc::osisThreadAttachCallback(void* psrv, pid_t tid, int64_t flag, int type)
{
    long lRet = -1;
    Osis_TraceProc* p_srv = (Osis_TraceProc*)psrv;
    if (!p_srv) return -1;
    if (type == 0) {
        p_srv->delete_threadinfo_by_tid(tid);
        p_srv->test();
        for (std::list<thread_info>::iterator it = p_srv->m_threadInfoList.begin(); \ 
        it != p_srv->m_threadInfoList.end();) {
            if (it->tid == tid) {
                it = p_srv->m_threadInfoList.erase(it);
            } else
                ++it;
        }
        thread_info ti;
        ti.t_flg = flag;
        ti.tid = tid;
        p_srv->m_threadInfoList.push_back(ti);
    }
    if (type == 1) {
        // p_srv->m_threadInfoList.find
        for (std::list<thread_info>::iterator it = p_srv->m_threadInfoList.begin(); it != p_srv->m_threadInfoList.end();
             ++it) {
            if (it->tid == tid) {
                if (flag) it->setvalue(flag);
            }
        }
    }
    return lRet;
}
long OSIS::Osis_TraceProc::restore_allreg(pid_t tid)
{
    long lRet = -1;
    int found_flag = 0;
    thread_info* ptarget_ti = NULL;
    for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); it != m_threadInfoList.end(); ++it) {
        if (it->tid == tid) {
            ptarget_ti = &(*it);
            found_flag = 1;
            break;
        }
    }
    if (!found_flag) {
        printf("The thread  tid(%d) hasn't been found\n", tid);
        return -1;
    }
    lRet = OSIS::set_allreg(tid, &ptarget_ti->X_all_reg);
    return lRet;
}
long OSIS::Osis_TraceProc::save_allreg(pid_t tid)
{
    long lRet = -1;
    int found_flag = 0;
    thread_info* ptarget_ti = NULL;
    for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); it != m_threadInfoList.end(); ++it) {
        if (it->tid == tid) {
            ptarget_ti = &(*it);
            found_flag = 1;
            break;
        }
    }
    if (!found_flag) {
        printf("The thread  tid(%d) hasn't been found\n", tid);
        return -1;
    }
    struct xsave_info info = {0};
    lRet = OSIS::get_xsave_info(&info);
    if (lRet < 0) return lRet;
    printf("XSAVE area sizes:\n");
    printf("Total size: %u bytes\n", info.size);
    printf("User accessible size: %u bytes\n", info.user_size);
    printf("Supervisor size: %u bytes\n", info.supervisor_size);
    print_supported_features(info.features_supported);

    void* xsave_area = allocate_xsave_area(info.size);
    if (!xsave_area) {
        printf("Failed to allocate XSAVE area\n");
        return -1;
    }
    if (ptarget_ti->X_all_reg.xstateBuff_len > 0 && ptarget_ti->X_all_reg.pxstate_buff) {
        free(ptarget_ti->X_all_reg.pxstate_buff);
        ptarget_ti->X_all_reg.pxstate_buff = NULL;
        ptarget_ti->X_all_reg.xstateBuff_len = 0;
    }
    ptarget_ti->X_all_reg.xstateBuff_len = info.size;
    ptarget_ti->X_all_reg.pxstate_buff = xsave_area;
    lRet = OSIS::get_allreg(tid, &(ptarget_ti->X_all_reg));
    if (lRet < 0) {
        printf("Failed to get_allreg\n");
        goto to_exit;
    }
to_exit:
    if (ptarget_ti->X_all_reg.xstateBuff_len > 0 && ptarget_ti->X_all_reg.pxstate_buff) {
        free(ptarget_ti->X_all_reg.pxstate_buff);
        ptarget_ti->X_all_reg.pxstate_buff = NULL;
        ptarget_ti->X_all_reg.xstateBuff_len = 0;
    }
    return lRet;
}
long OSIS::Osis_TraceProc::adjust_process_not_in_syscall()
{
    long lRet = -1;
    pid_t new_pid;
    int status;
    if (m_stat != 1) {
        OSIS::output_debug_string(0, 1, "m_stat=%d return (%s:%d)\n", m_stat, __FILE__, __LINE__);
        return -1;
    }

    lRet=adjust_not_in_syscall_pid(_pid);
    if(lRet<0)
    {
        goto to_exit;
    }
    for (std::list<thread_info>::iterator it = m_threadInfoList.begin(); it != m_threadInfoList.end(); ++it) {
            if (it->tid != _pid) {
                lRet=adjust_not_in_syscall_pid(it->tid );
                if(lRet<0)
                {
                   OSIS::output_debug_string(0, 1, " adjust_not_in_syscall_pid(%d) return (%d) \
                   (%s:%d)\n", it->tid, lRet,__FILE__, __LINE__); 
                }
                it->stopped=1;
            }
            if(it->tid == _pid)
               it->stopped=1; 
        }
to_exit:
    return lRet;
}
long OSIS::Osis_TraceProc::adjust_not_in_syscall_pid(pid_t tid)
{
    long lRet = -1;
    int signal;
    while (1) {
        long syscall_number = 0;
      //  lRet = OSIS::get_syscall_number(tid, syscall_number);
        struct user_regs_struct regs;
        if (lRet=ptrace(PTRACE_GETREGS, tid, NULL, &regs) == -1) {
        perror("ptrace getregs");
        return -1;
        }
        syscall_number=regs.orig_rax;
        if (lRet == -1) return -1;  //
        if (syscall_number == -1) {
            printf("Process is not in syscall, ready for debugging\n");
            return 0;
        }
        printf("pid=%d,tid=%d is in syscall(%lld), continuing to next syscall exit...\n", _pid, tid, syscall_number);
        if (syscall_number== SYS_nanosleep || syscall_number == SYS_clock_nanosleep) 
        {
             regs.rax = -EINTR;

            // 设置新的寄存器状态
            if (ptrace(PTRACE_SETREGS, tid, NULL, &regs) == -1) {
                fprintf(stderr, "Failed to set registers: %s\n", strerror(errno));
                break;
            }
        }
       else if (syscall_number== SYS_select || syscall_number == SYS_pselect6) 
        {
             regs.rax = -EINTR;

            // 设置新的寄存器状态
            if (ptrace(PTRACE_SETREGS, tid, NULL, &regs) == -1) {
                fprintf(stderr, "Failed to set registers: %s\n", strerror(errno));
                break;
            }
        }
        else if(syscall_number== SYS_accept || syscall_number == SYS_poll \ 
        ||syscall_number== SYS_epoll_wait || syscall_number == SYS_recvfrom) {
             regs.rax = -EINTR;

            // 设置新的寄存器状态
            if (ptrace(PTRACE_SETREGS, tid, NULL, &regs) == -1) {
                fprintf(stderr, "Failed to set registers: %s\n", strerror(errno));
                break;
            }
        }
     //   if (ptrace(PTRACE_SYSCALL, tid, NULL, NULL) == -1) {
        if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL) == -1) {
            perror("ptrace syscall");
            return -1;
        }
        do {
            switch (signal = ptrace_wait_event(tid)) {
            case -1:
                return -1;
            case SIGCONT:
            case SIGSTOP:
                break;
            case SIGTRAP:
            case SYSCALL_SIGTRAP:
            break;
            default:
                if (ptrace_continue_signal(tid, signal) == -1)
                 return -1;
            }
        } while (signal != SIGSTOP && signal != SIGCONT && signal != SIGTRAP && signal != SYSCALL_SIGTRAP);
    }

    return lRet;
}
long OSIS::Osis_TraceProc::retrieve_base_address()
{
    long lRet = -1;
    base_addr = (Elf64_Addr)OSIS::ptrace_procfs_maps_find_exec(_pid);
    return base_addr; 
}
long stop_wait_bp(pid_t pid)
{
    long lRet = -1;
    return 0; 
}
long OSIS::Osis_TraceProc::init(void* p)
{
    this->pf_Procee_attch_cb = osisProcAttachCallback;
    this->pf_Thread_attch_cb = osisThreadAttachCallback;
    m_stat = 0;
    psrv = p;
    proc_mem_file_is_writable();
    proc_mem_file_is_writable();
}
void OSIS::Osis_TraceProc::test()
{
    printf("into test\n");
    return;
}