#include "osis_ptrace.h"
/************* As taken  from the libptrace source code**********/
FILE *OSIS::fopen_no_EINTR(const char *path, const char *mode)
{
    FILE *ret;

    do {
        ret = fopen(path, mode);
    } while (ret == NULL && errno == EINTR);

    return ret;
}
int OSIS::fclose_no_EINTR(FILE *fp)
{
    int ret;

    do {
        ret = fclose(fp);
    } while (ret == -1 && errno == EINTR);

    return ret;
}
/************* As taken  from the libptrace source code**********/
pid_t OSIS::waitpid_no_EINTR(pid_t pid, int *status, int options)
{
    pid_t ret;

    do {
        ret = waitpid(pid, status, options);
    } while (ret == -1 && errno == EINTR);

    return ret;
}
/************************************************/
static const char **signal_names;
static int num_signal_names = 0;
struct signal_info {
    const int value;        /* The numeric value from <signal.h> */
    const char *const name; /* The equivalent symbolic value */
#ifndef HAVE_SYS_SIGLIST
    const char *const msg; /* Short message about this value */
#endif
};
#ifndef HAVE_SYS_SIGLIST
#define ENTRY(value, name, msg) {value, name, msg}
#else
#define ENTRY(value, name, msg) {value, name}
#endif
static const struct signal_info signal_table[] = {
#if defined(SIGHUP)
    ENTRY(SIGHUP, "SIGHUP", "Hangup"),
#endif
#if defined(SIGINT)
    ENTRY(SIGINT, "SIGINT", "Interrupt"),
#endif
#if defined(SIGQUIT)
    ENTRY(SIGQUIT, "SIGQUIT", "Quit"),
#endif
#if defined(SIGILL)
    ENTRY(SIGILL, "SIGILL", "Illegal instruction"),
#endif
#if defined(SIGTRAP)
    ENTRY(SIGTRAP, "SIGTRAP", "Trace/breakpoint trap"),
#endif
/* Put SIGIOT before SIGABRT, so that if SIGIOT==SIGABRT then SIGABRT
   overrides SIGIOT.  SIGABRT is in ANSI and POSIX.1, and SIGIOT isn't. */
#if defined(SIGIOT)
    ENTRY(SIGIOT, "SIGIOT", "IOT trap"),
#endif
#if defined(SIGABRT)
    ENTRY(SIGABRT, "SIGABRT", "Aborted"),
#endif
#if defined(SIGEMT)
    ENTRY(SIGEMT, "SIGEMT", "Emulation trap"),
#endif
#if defined(SIGFPE)
    ENTRY(SIGFPE, "SIGFPE", "Arithmetic exception"),
#endif
#if defined(SIGKILL)
    ENTRY(SIGKILL, "SIGKILL", "Killed"),
#endif
#if defined(SIGBUS)
    ENTRY(SIGBUS, "SIGBUS", "Bus error"),
#endif
#if defined(SIGSEGV)
    ENTRY(SIGSEGV, "SIGSEGV", "Segmentation fault"),
#endif
#if defined(SIGSYS)
    ENTRY(SIGSYS, "SIGSYS", "Bad system call"),
#endif
#if defined(SIGPIPE)
    ENTRY(SIGPIPE, "SIGPIPE", "Broken pipe"),
#endif
#if defined(SIGALRM)
    ENTRY(SIGALRM, "SIGALRM", "Alarm clock"),
#endif
#if defined(SIGTERM)
    ENTRY(SIGTERM, "SIGTERM", "Terminated"),
#endif
#if defined(SIGUSR1)
    ENTRY(SIGUSR1, "SIGUSR1", "User defined signal 1"),
#endif
#if defined(SIGUSR2)
    ENTRY(SIGUSR2, "SIGUSR2", "User defined signal 2"),
#endif
/* Put SIGCLD before SIGCHLD, so that if SIGCLD==SIGCHLD then SIGCHLD
   overrides SIGCLD.  SIGCHLD is in POXIX.1 */
#if defined(SIGCLD)
    ENTRY(SIGCLD, "SIGCLD", "Child status changed"),
#endif
#if defined(SIGCHLD)
    ENTRY(SIGCHLD, "SIGCHLD", "Child status changed"),
#endif
#if defined(SIGPWR)
    ENTRY(SIGPWR, "SIGPWR", "Power fail/restart"),
#endif
#if defined(SIGWINCH)
    ENTRY(SIGWINCH, "SIGWINCH", "Window size changed"),
#endif
#if defined(SIGURG)
    ENTRY(SIGURG, "SIGURG", "Urgent I/O condition"),
#endif
#if defined(SIGIO)
    /* "I/O pending" has also been suggested, but is misleading since the
       signal only happens when the process has asked for it, not everytime
       I/O is pending. */
    ENTRY(SIGIO, "SIGIO", "I/O possible"),
#endif
#if defined(SIGPOLL)
    ENTRY(SIGPOLL, "SIGPOLL", "Pollable event occurred"),
#endif
#if defined(SIGSTOP)
    ENTRY(SIGSTOP, "SIGSTOP", "Stopped (signal)"),
#endif
#if defined(SIGTSTP)
    ENTRY(SIGTSTP, "SIGTSTP", "Stopped (user)"),
#endif
#if defined(SIGCONT)
    ENTRY(SIGCONT, "SIGCONT", "Continued"),
#endif
#if defined(SIGTTIN)
    ENTRY(SIGTTIN, "SIGTTIN", "Stopped (tty input)"),
#endif
#if defined(SIGTTOU)
    ENTRY(SIGTTOU, "SIGTTOU", "Stopped (tty output)"),
#endif
#if defined(SIGVTALRM)
    ENTRY(SIGVTALRM, "SIGVTALRM", "Virtual timer expired"),
#endif
#if defined(SIGPROF)
    ENTRY(SIGPROF, "SIGPROF", "Profiling timer expired"),
#endif
#if defined(SIGXCPU)
    ENTRY(SIGXCPU, "SIGXCPU", "CPU time limit exceeded"),
#endif
#if defined(SIGXFSZ)
    ENTRY(SIGXFSZ, "SIGXFSZ", "File size limit exceeded"),
#endif
#if defined(SIGWIND)
    ENTRY(SIGWIND, "SIGWIND", "SIGWIND"),
#endif
#if defined(SIGPHONE)
    ENTRY(SIGPHONE, "SIGPHONE", "SIGPHONE"),
#endif
#if defined(SIGLOST)
    ENTRY(SIGLOST, "SIGLOST", "Resource lost"),
#endif
#if defined(SIGWAITING)
    ENTRY(SIGWAITING, "SIGWAITING", "Process's LWPs are blocked"),
#endif
#if defined(SIGLWP)
    ENTRY(SIGLWP, "SIGLWP", "Signal LWP"),
#endif
#if defined(SIGDANGER)
    ENTRY(SIGDANGER, "SIGDANGER", "Swap space dangerously low"),
#endif
#if defined(SIGGRANT)
    ENTRY(SIGGRANT, "SIGGRANT", "Monitor mode granted"),
#endif
#if defined(SIGRETRACT)
    ENTRY(SIGRETRACT, "SIGRETRACT", "Need to relinguish monitor mode"),
#endif
#if defined(SIGMSG)
    ENTRY(SIGMSG, "SIGMSG", "Monitor mode data available"),
#endif
#if defined(SIGSOUND)
    ENTRY(SIGSOUND, "SIGSOUND", "Sound completed"),
#endif
#if defined(SIGSAK)
    ENTRY(SIGSAK, "SIGSAK", "Secure attention"),
#endif
    ENTRY(0, NULL, NULL)};
int OSIS::linux_proc_pid_has_state(pid_t pid, enum OSIS::proc_state state, int warn)
{
    int have_state;
    enum OSIS::proc_state cur_state;

    have_state = linux_proc_pid_get_state(pid, warn, &cur_state);
    return (have_state > 0 && cur_state == state);
}
int OSIS::linux_proc_pid_is_stopped(pid_t pid) { return linux_proc_pid_has_state(pid, PROC_STATE_STOPPED, 1); }
/************************************************** */
int OSIS::linux_proc_pid_get_state(pid_t pid, int warn, enum proc_state *state)
{
    int have_state;
    char buffer[100];

    snprintf(buffer, sizeof(buffer), "/proc/%d/status", (int)pid);
    FILE *procfile = fopen_no_EINTR(buffer, "r");
    if (procfile == NULL) {
        if (warn) printf("unable to open /proc file '%s'\n", buffer);
        return -1;
    }

    have_state = 0;
    while (fgets(buffer, sizeof(buffer), procfile) != NULL)
        if (!strncmp(buffer, "State:", 6)) {
            have_state = 1;
            *state = parse_proc_status_state(buffer + sizeof("State:") - 1);
            break;
        }
    fclose_no_EINTR(procfile);
    return have_state;
}

std::string OSIS::status_to_str(int status)
{
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) == SYSCALL_SIGTRAP)
            return string_printf("%s - %s (stopped at syscall)", strsigno(SIGTRAP), strsignal(SIGTRAP));
        else
            return string_printf("%s - %s (stopped)", strsigno(WSTOPSIG(status)), strsignal(WSTOPSIG(status)));
    } else if (WIFSIGNALED(status))
        return string_printf("%s - %s (terminated)", strsigno(WTERMSIG(status)), strsignal(WTERMSIG(status)));
    else
        return string_printf("%d (exited)", WEXITSTATUS(status));
}
static int sys_nsig;
static const char **sys_siglist;
static void init_signal_tables(void)
{
    const struct signal_info *eip;
    int nbytes;

    /* If we haven't already scanned the signal_table once to find the maximum
       signal value, then go find it now. */

    if (num_signal_names == 0) {
        for (eip = signal_table; eip->name != NULL; eip++) {
            if (eip->value >= num_signal_names) {
                num_signal_names = eip->value + 1;
            }
        }
    }

    /* Now attempt to allocate the signal_names table, zero it out, and then
       initialize it from the statically initialized signal_table. */

    if (signal_names == NULL) {
        nbytes = num_signal_names * sizeof(char *);
        if ((signal_names = (const char **)malloc(nbytes)) != NULL) {
            memset(signal_names, 0, nbytes);
            for (eip = signal_table; eip->name != NULL; eip++) {
                signal_names[eip->value] = eip->name;
            }
        }
    }

#ifndef HAVE_SYS_SIGLIST

    /* Now attempt to allocate the sys_siglist table, zero it out, and then
       initialize it from the statically initialized signal_table. */

    if (sys_siglist == NULL) {
        nbytes = num_signal_names * sizeof(char *);
        if ((sys_siglist = (const char **)malloc(nbytes)) != NULL) {
            memset(sys_siglist, 0, nbytes);
            sys_nsig = num_signal_names;
            for (eip = signal_table; eip->name != NULL; eip++) {
                sys_siglist[eip->value] = eip->msg;
            }
        }
    }

#endif
}
const char *OSIS::strsigno(int signo)
{
    const char *name;
    static char buf[32];

    if (signal_names == NULL) {
        init_signal_tables();
    }

    if ((signo < 0) || (signo >= num_signal_names)) {
        /* Out of range, just return NULL */
        name = NULL;
    } else if ((signal_names == NULL) || (signal_names[signo] == NULL)) {
        /* In range, but no signal_names or no entry at this index. */
        sprintf(buf, "Signal %d", signo);
        name = (const char *)buf;
    } else {
        /* In range, and a valid name.  Just return the name. */
        name = signal_names[signo];
    }

    return (name);
}

/* As taken and modified from the GDB source code*/
int OSIS::linux_nat_post_attach_wait(pid_t pid)
{
    pid_t new_pid;
    int status;

    if (linux_proc_pid_is_stopped(pid)) {
        printf("Attaching to a stopped process\n");

        /* The process is definitely stopped.  It is in a job control
       stop, unless the kernel predates the TASK_STOPPED /
       TASK_TRACED distinction, in which case it might be in a
       ptrace stop.  Make sure it is in a ptrace stop; from there we
       can kill it, signal it, et cetera.

       First make sure there is a pending SIGSTOP.  Since we are
       already attached, the process can not transition from stopped
       to running without a PTRACE_CONT; so we know this signal will
       go into the queue.  The SIGSTOP generated by PTRACE_ATTACH is
       probably already in the queue (unless this kernel is old
       enough to use TASK_STOPPED for ptrace stops); but since SIGSTOP
       is not an RT signal, it can only be queued once.  */
        kill_lwp(pid, SIGSTOP);

        /* Finally, resume the stopped process.  This will deliver the SIGSTOP
       (or a higher priority signal, just like normal PTRACE_ATTACH).  */
        ptrace(PTRACE_CONT, pid, 0, 0);
    }

    /* Make sure the initial process is stopped.  The user-level threads
       layer might want to poke around in the inferior, and that won't
       work if things haven't stabilized yet.  */
    new_pid = waitpid_no_EINTR(pid, &status, __WALL);
    if (new_pid != pid) {
        printf("waitpid_no_EINTR fastartswithil new_pid[%d],pid[%d]\n", new_pid, pid);
    }

    if (!WIFSTOPPED(status)) {
        /* The pid we tried to attach has apparently just exited.  */
        printf("Failed to stop %d: %s\n", pid, status_to_str(status).c_str());
        return status;
    }

    if (WSTOPSIG(status) != SIGSTOP) {
        //  *signalled = 1;
        printf("Received %s after attaching\n", status_to_str(status).c_str());
    }

    return status;
}
enum OSIS::proc_state OSIS::parse_proc_status_state(const char *state)
{
    state = skip_spaces(state);

    switch (state[0]) {
    case 't':
        return PROC_STATE_TRACING_STOP;
    case 'T':
        /* Before Linux 2.6.33, tracing stop used uppercase T.  */
        if (strcmp(state, "T (stopped)\n") == 0)
            return PROC_STATE_STOPPED;
        else /* "T (tracing stop)\n" */
            return PROC_STATE_TRACING_STOP;
    case 'X':
        return PROC_STATE_DEAD;
    case 'Z':
        return PROC_STATE_ZOMBIE;
    case 'S':
        return PROC_STATE_SLEEPING;
    case 'R':
        return PROC_STATE_RUNNING;
    }

    return PROC_STATE_UNKNOWN;
}
int OSIS::kill_lwp(int lwpid, int signo)
{
    int ret;

    errno = 0;
    ret = syscall(__NR_tkill, lwpid, signo);
    if (errno == ENOSYS) {
        /* If tkill fails, then we are not using nptl threads, a
       configuration we no longer support.  */
        printf(("tkill"));
    }
    return ret;
}
/**********************************************/
int OSIS::osis_ptrace_attach(pid_t tid, void *psrv, linux_proc_attach_callback_func attach_lwp,bool systrap_flag)
{
    int signal;
    int ret;
    int status;
    if (tid == getpid()) {
        printf("Process %d not found\n", tid);  // use PTRACE_TRACEME
        if (attach_lwp) attach_lwp(psrv, tid, -1, 0);
        return -1;
    }
    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) {
        if (errno == ESRCH) {
            printf("Process %d not found\n", tid);
            if (attach_lwp) attach_lwp(psrv, tid, -1, 0);
            return -1;
        }
        if (errno == EPERM) {
            printf("Permission denied for pid %d\n", tid);
            if (attach_lwp) attach_lwp(psrv, tid, -1, 0);
            return -1;
        }
        if (errno == EBUSY) {
            // 进程可能已经被跟踪
            printf("Process %d is already being traced\n", tid);
            if (attach_lwp) attach_lwp(psrv, tid, -1, 0);
            return -1;
        }

        printf("Failed to attach to process %d: %s\n", tid, strerror(errno));
        if (attach_lwp) attach_lwp(psrv, tid, -1, 0);
        return -1;
    }
    status = linux_nat_post_attach_wait(tid);
    if (!WIFSTOPPED(status)) {
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);

            if (exit_code == 0)
                printf("Unable to attach: program exited normally.\n");
            else
                printf("Unable to attach: program exited with code %d.\n", exit_code);
        } else if (WIFSIGNALED(status)) {
            printf(("Unable to attach: program terminated with signal  %d\n"), WTERMSIG(status));
        }

        printf("unexpected status %d for PID %ld\n", status, tid);
        goto out_detach;
    }
    if( systrap_flag)
    ptrace(PTRACE_SETOPTIONS, tid, NULL, PTRACE_O_TRACESYSGOOD) == 0;
    if (attach_lwp) attach_lwp(psrv, tid, 1, 0);
    if (attach_lwp) attach_lwp(psrv, tid, 0x80 | 0x40 | 0x20 | 0x10, 1);  // stopped=1;resumed=1
    return 0;
out_detach_error:
out_detach:

    ptrace(PTRACE_DETACH, tid, NULL, NULL);
    if (attach_lwp) attach_lwp(psrv, tid, -1, 0);
    return -1;
}
long OSIS::linux_proc_get_int(pid_t lwpid, const char *field, int warn)
{
    size_t field_len = strlen(field);
    char buf[100];
    int retval = -1;

    snprintf(buf, sizeof(buf), "/proc/%d/status", (int)lwpid);
    FILE *status_file = fopen_no_EINTR(buf, "r");
    if (status_file == NULL) {
        if (warn) printf("unable to open /proc file '%s'\n", buf);
        return -1;
    }

    while (fgets(buf, sizeof(buf), status_file))
        if (strncmp(buf, field, field_len) == 0 && buf[field_len] == ':') {
            retval = strtol(&buf[field_len + 1], NULL, 10);
            break;
        }

    return retval;
}
long OSIS::linux_proc_attach_tgid_threads(pid_t pid, void *psrv, linux_proc_attach_callback_func attach_lwp)
{
    long lRet = -1;
    char pathname[128];
    int new_threads_found;
    int iterations;

    if (linux_proc_get_int(pid, "Tgid", 1) != pid) return -1;
    snprintf(pathname, sizeof(pathname), "/proc/%ld/task", (long)pid);
    DIR *dir = opendir(pathname);
    if (dir == NULL) {
        printf("Could not open %s.\n", pathname);
        return -1;
    }
    /* Callable object to hash elements in visited_lpws.  */
    struct pair_hash {
        std::size_t operator()(const std::pair<unsigned long, ULONGEST> &v) const
        {
            return (std::hash<unsigned long>()(v.first) ^ std::hash<ULONGEST>()(v.second));
        }
    };

    /* Keeps track of the LWPs we have already visited in /proc,
       identified by their PID and starttime to detect PID reuse.  */
    std::unordered_set<std::pair<unsigned long, ULONGEST>, pair_hash> visited_lwps;
    /* Scan the task list for existing threads.  While we go through the
     threads, new threads may be spawned.  Cycle through the list of
     threads until we have done two iterations without finding new
     threads.  */
    for (iterations = 0; iterations < 2; iterations++) {
        struct dirent *dp;

        new_threads_found = 0;
        while ((dp = readdir(dir)) != NULL) {
            unsigned long lwp;

            /* Fetch one lwp.  */
            lwp = strtoul(dp->d_name, NULL, 10);
            if (lwp == pid) continue;
            if (lwp != 0) {
                ptid_t ptid = ptid_t(pid, lwp);
                ULONGEST starttime = linux_proc_get_starttime(ptid);
                if (starttime != 0) {
                    std::pair<unsigned long, ULONGEST> key(lwp, starttime);

                    /* If we already visited this LWP, skip it this time.  */
                    if (visited_lwps.find(key) != visited_lwps.cend()) continue;

                    visited_lwps.insert(key);
                }
                if (attach_proc_task_lwp(ptid)) {
                    attach_lwp(psrv, lwp, 1, 0);
                    attach_lwp(psrv, lwp, 0x01 | 0x02 | 0x04 | 0x08 | 0x40 | 0x80,
                               1);  // signalled=1//must_set_ptrace_flags=1,resumed=1
                }
            }
        }
    }
    closedir(dir);
    return 0;
}

OSIS::ULONGEST OSIS::linux_proc_get_starttime(ptid_t ptid)
{
    std::string field = linux_proc_get_stat_field(ptid, LINUX_PROC_STAT_STARTTIME);

    if (field.empty()) return 0;

    errno = 0;
    const char *trailer;
    ULONGEST starttime = strtoulst(field.c_str(), &trailer, 10);
    if (starttime == ULONGEST_MAX && errno == ERANGE)
        return {};
    else if (*trailer != '\0')
        /* There were unexpected characters.  */
        return {};

    return starttime;
}
std::string OSIS::linux_proc_get_stat_field(ptid_t ptid, int field)
{
    /* We never need to read PID from the stat file, and there's
       command_from_pid to read the comm field.  */
    if (field < LINUX_PROC_STAT_STATE) return "";

    std::string filename = string_printf("/proc/%ld/task/%ld/stat", (long)ptid.get_pid(), (long)ptid.get_lwp());

    std::string content = read_text_file_to_string(filename.c_str());
    if (content.empty()) return "";

    /* ps command also relies on no trailing fields ever containing ')'.  */
    std::string::size_type pos = content.find_last_of(')');
    if (pos == std::string::npos) return "";

    /* The first field after program name is LINUX_PROC_STAT_STATE.  */
    for (int i = LINUX_PROC_STAT_STATE; i <= field; ++i) {
        /* Find separator.  */
        pos = content.find_first_of(' ', pos);
        if (pos == std::string::npos) return {};

        /* Find beginning of field.  */
        pos = content.find_first_not_of(' ', pos);
        if (pos == std::string::npos) return {};
    }

    /* Find end of field.  */
    std::string::size_type end_pos = content.find_first_of(' ', pos);
    if (end_pos == std::string::npos)
        return content.substr(pos);
    else
        return content.substr(pos, end_pos - pos);
}

std::string OSIS::read_text_file_to_string(const char *path)
{
    FILE *file = fopen_no_EINTR(path, "r");
    if (file == NULL) return "";

    return read_remainder_of_file(file);
}
std::string OSIS::read_remainder_of_file(FILE *file)
{
    std::string res;
    for (;;) {
        std::string::size_type start_size = res.size();
        constexpr int chunk_size = 1024;

        /* Resize to accommodate CHUNK_SIZE bytes.  */
        res.resize(start_size + chunk_size);

        int n = fread(&res[start_size], 1, chunk_size, file);
        if (n == chunk_size) continue;

        if (n >= chunk_size)
            ;
        return "";

        /* Less than CHUNK means EOF or error.  If it's an error, return
       no value.  */
        if (ferror(file)) return {};

        /* Resize the string according to the data we read.  */
        res.resize(start_size + n);
        break;
    }

    return res;
}

int OSIS::attach_proc_task_lwp(ptid_t ptid)
{
    struct lwp_info *lp;

    /* Ignore LWPs we're already attached to.  */

    int lwpid = ptid.get_lwp();

    if (ptrace(PTRACE_ATTACH, lwpid, 0, 0) < 0) {
        int err = errno;

        /* Be quiet if we simply raced with the thread exiting.
           EPERM is returned if the thread's task still exists, and
           is marked as exited or zombie, as well as other
           conditions, so in that case, confirm the status in
           /proc/PID/status.  */
        if (err == ESRCH || (err == EPERM)) {
            printf("Cannot attach to lwp %d: thread is gone (%d: %s)\n", lwpid, err, safe_strerror(err));

        } else {
            printf("Cannot attach to lwp %d", lwpid);
        }
        return 0;
    } else {
        printf("PTRACE_ATTACH %d::%d::%d, 0, 0 (OK)", ptid.get_pid(), ptid.get_lwp(), ptid.get_tid());

        // lp = add_lwp(ptid);

        /* The next time we wait for this LWP we'll see a SIGSTOP as
           PTRACE_ATTACH brings it to a halt.  */
        // lp->signalled = 1;

        /* We need to wait for a stop before being able to make the
           next ptrace call on this LWP.  */
        //  lp->must_set_ptrace_flags = 1;

        /* So that wait collects the SIGSTOP.  */
        //  lp->resumed = 1;
    }

    return 1;
}
long OSIS::detach_one_pid(int pid, int signo)
{
    if (ptrace(PTRACE_DETACH, pid, 0, signo) < 0) {
        int save_errno = errno;

        /* We know the thread exists, so ESRCH must mean the lwp is
       zombie.  This can happen if one of the already-detached
       threads exits the whole thread group.  In that case we're
       still attached, and must reap the lwp.  */
        if (save_errno == ESRCH) {
            int ret, status;
            ret = waitpid_no_EINTR(pid, &status, __WALL);
            if (ret == -1) {
                printf("Couldn't reap LWP %d while detaching: %s \n", pid, safe_strerror(errno));
            } else if (!WIFEXITED(status) && !WIFSIGNALED(status)) {
                printf(("Reaping LWP %d while detaching "
                        "returned unexpected status 0x%x\n"),
                       pid, status);
            }
        } else {
            printf("Can't detach %d: %s\n", pid, safe_strerror(save_errno));
        }
    } else
        printf("PTRACE_DETACH (%d, %s, 0) (OK)\n", pid, strsignal(signo));
    return 0;
}
long OSIS::get_xsave_info(struct xsave_info *info)
{
    unsigned int eax, ebx, ecx, edx;

    // 检查 CPU 是否支持 XSAVE
    __cpuid(1, eax, ebx, ecx, edx);
    if (!(ecx & XSAVE_FEATURE_FLAG)) {
        printf("CPU does not support XSAVE\n");
        info->size = 0;
        return -1;
    }

    // 获取支持的特性掩码
    __cpuid_count(0xD, 0, eax, ebx, ecx, edx);
    info->features_supported = ((uint64_t)edx << 32) | eax;
    info->size = ebx;       // XSAVE 区域的总大小
    info->user_size = ecx;  // 用户态可访问部分的大小

    // 获取内核态大小
    __cpuid_count(0xD, 1, eax, ebx, ecx, edx);
    info->supervisor_size = ebx;
    return 0;
}
void OSIS::print_supported_features(uint64_t features)
{
    printf("Supported XSAVE features:\n");
    if (features & (1ULL << 0)) printf("- x87 FPU\n");
    if (features & (1ULL << 1)) printf("- SSE\n");
    if (features & (1ULL << 2)) printf("- AVX\n");
    if (features & (1ULL << 3)) printf("- MPX BNDREGS\n");
    if (features & (1ULL << 4)) printf("- MPX BNDCSR\n");
    if (features & (1ULL << 5)) printf("- AVX-512 opmask\n");
    if (features & (1ULL << 6)) printf("- AVX-512 ZMM_Hi256\n");
    if (features & (1ULL << 7)) printf("- AVX-512 Hi16_ZMM\n");
    if (features & (1ULL << 8)) printf("- PT\n");
    if (features & (1ULL << 9)) printf("- PKRU\n");
    if (features & (1ULL << 10)) printf("- PASID\n");
    // 可以继续添加更多特性...
}
long OSIS::get_allreg(pid_t pid, struct x86_64_all_reg *pstru_x8664_all_reg)
{
    if (pstru_x8664_all_reg == NULL) {
        printf("pstru_x8664_all_reg is null\n");
        return -1;
    }
    struct iovec iov;
    /*struct xsave_info info = { 0 };
    long lret=0;
    lret=get_xsave_info(&info);
    if(lret<0)
        return lret;

    printf("XSAVE area sizes:\n");
    printf("Total size: %u bytes\n", info.size);
    printf("User accessible size: %u bytes\n", info.user_size);
    printf("Supervisor size: %u bytes\n", info.supervisor_size);

    print_supported_features(info.features_supported);

    // 分配 XSAVE 区域
    void* xsave_area = allocate_xsave_area(info.size);
    if (!xsave_area) {
        printf("Failed to allocate XSAVE area\n");
        return -1;
    }
    pstru_x8664_all_reg->xstateBuff_len=info.size;
    pstru_x8664_all_reg->pxstate_buff=xsave_area;*/

    // 获取通用寄存器
    iov.iov_base = &(pstru_x8664_all_reg->regs);
    iov.iov_len = sizeof(pstru_x8664_all_reg->regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
        // free(pstru_x8664_all_reg->pxstate_buff);
        // pstru_x8664_all_reg->pxstate_buff=NULL;
        // pstru_x8664_all_reg->xstateBuff_len=0;
        printf("PTRACE_GETREGSET (NT_PRSTATUS) error -1\n");
        return -1;
    }
    printf("General Registers:\n");
    printf("RIP: %llx\n", (pstru_x8664_all_reg->regs.rip));

    // 获取浮点寄存器
    iov.iov_base = &pstru_x8664_all_reg->fpregs;
    iov.iov_len = sizeof(pstru_x8664_all_reg->fpregs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_FPREGSET, &iov) == -1) {
        // free(pstru_x8664_all_reg->pxstate_buff);
        // pstru_x8664_all_reg->pxstate_buff=NULL;
        // pstru_x8664_all_reg->xstateBuff_len=0;
        printf("PTRACE_GETREGSET (NT_FPREGSET) error -1\n");
        return -1;
    }
    printf("Floating Point Registers:\n");
    printf("MXCSR: %llx\n", pstru_x8664_all_reg->fpregs.mxcsr);

    // 获取扩展状态（包括 AVX、SSE等）
    if (pstru_x8664_all_reg->xstateBuff_len > 0 && pstru_x8664_all_reg->pxstate_buff) {
        iov.iov_base = pstru_x8664_all_reg->pxstate_buff;
        iov.iov_len = pstru_x8664_all_reg->xstateBuff_len;
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_X86_XSTATE, &iov) == -1) {
            //	free(pstru_x8664_all_reg->pxstate_buff);
            //	pstru_x8664_all_reg->pxstate_buff=NULL;
            //	pstru_x8664_all_reg->xstateBuff_len=0;
            printf("PTRACE_GETREGSET (NT_X86_XSTATE) error -1\n");
            return -1;
        }
        printf("Extended State Registers (XSTATE):\n");
        printf("XSTATE size: %zu bytes\n", iov.iov_len);
    }

    return 0;
}
long OSIS::set_allreg(pid_t pid, struct x86_64_all_reg *pstru_x8664_all_reg)
{
    if (pstru_x8664_all_reg == NULL) {
        printf("pstru_x8664_all_reg is null\n");
        return -1;
    }
    struct iovec iov;

    // 设置通用寄存器
    iov.iov_base = &(pstru_x8664_all_reg->regs);
    iov.iov_len = sizeof(pstru_x8664_all_reg->regs);
    // if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1)
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
        // free(pstru_x8664_all_reg->pxstate_buff);
        // pstru_x8664_all_reg->pxstate_buff=NULL;
        // pstru_x8664_all_reg->xstateBuff_len=0;
        printf("PTRACE_SETREGSET (NT_PRSTATUS) error -1\n");
        return -1;
    }
    printf("General Registers:\n");
    printf("RIP: %llx\n", (pstru_x8664_all_reg->regs.rip));

    // 设置浮点寄存器
    iov.iov_base = &pstru_x8664_all_reg->fpregs;
    iov.iov_len = sizeof(pstru_x8664_all_reg->fpregs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_FPREGSET, &iov) == -1) {
        // free(pstru_x8664_all_reg->pxstate_buff);
        // pstru_x8664_all_reg->pxstate_buff=NULL;
        // pstru_x8664_all_reg->xstateBuff_len=0;
        printf("PTRACE_GETREGSET (NT_FPREGSET) error -1\n");
        return -1;
    }
    printf("Floating Point Registers:\n");
    printf("MXCSR: %llx\n", pstru_x8664_all_reg->fpregs.mxcsr);

    // 设置扩展状态（包括 AVX、SSE等）
    if (pstru_x8664_all_reg->xstateBuff_len > 0 && pstru_x8664_all_reg->pxstate_buff) {
        iov.iov_base = pstru_x8664_all_reg->pxstate_buff;
        iov.iov_len = pstru_x8664_all_reg->xstateBuff_len;
        if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_X86_XSTATE, &iov) == -1) {
            //	free(pstru_x8664_all_reg->pxstate_buff);
            //	pstru_x8664_all_reg->pxstate_buff=NULL;
            //	pstru_x8664_all_reg->xstateBuff_len=0;
            printf("PTRACE_SETREGSET (NT_X86_XSTATE) error -1\n");
            return -1;
        }
        printf("Extended State Registers (XSTATE):\n");
        printf("XSTATE size: %zu bytes\n", iov.iov_len);
    }

    return 0;
}
// 分配对齐的 XSAVE 区域
void *OSIS::allocate_xsave_area(size_t size)
{
    // XSAVE 区域需要 64 字节对齐
    void *ptr;
    int ret = posix_memalign(&ptr, 64, size);
    if (ret != 0) {
        return NULL;
    }
    return ptr;
}
long OSIS::get_syscall_number(pid_t pid, long &syscall_number)
{
    long lRet;
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace getregs");
        return -1;
    }
    printf("tid=%d,get_syscall_number orig_rax=%lld,rip=0x%llx \n", pid, regs.orig_rax, regs.rip);
    // 检查orig_rax是否为-1
    syscall_number = regs.orig_rax;
    return 0;
}
int OSIS::ptrace_wait_event(pid_t pid)
{
    int status;

    if (waitpid_no_EINTR(pid, &status, 0) == -1) {
        // PTRACE_ERR_SET_EXTERNAL(pctx);
        return -1;
    }

    /* Child terminated normally */
    if (WIFEXITED(status)) {
        // PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
        return -1;
    }

    /* Child was terminated by a signal */
    if (WIFSIGNALED(status)) {
        // PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
        return -1;
    }

    /* The child was stopped by a signal; this is what we
     * expected.  If it is not the signal we're looking for,
     * delegate it to the child and continue.
     */
    if (WIFSTOPPED(status)) return WSTOPSIG(status);

    return 0;
}
int OSIS::ptrace_continue_signal(pid_t pid, int signum)
{
    unsigned long __signum = (unsigned long)signum;

    if (ptrace(PTRACE_CONT, pid, NULL, (void *)__signum) == -1) {
        // PTRACE_ERR_SET_EXTERNAL(pctx);
        return -1;
    }

    return 0;
}
FILE *OSIS::ptrace_procfs_maps_open(pid_t pid)
{
    char buf[128];

    snprintf(buf, sizeof(buf), PROC_DIR "/%u/" PROC_MAPS, pid);
    return fopen_no_EINTR(buf, "r");
}
static inline void skip_ws(FILE *fp)
{
    while (!feof(fp)) {
        int ch = fgetc(fp);

        if (ch == EOF || (ch != '\t' && ch != ' ')) {
            if (ch != EOF) ungetc(ch, fp);
            break;
        }
    }
}

static inline size_t file_strlen(FILE *fp)
{
    register int ch;
    register size_t len = 0;
    long offset = ftell(fp);

    if (offset == -1) return -1;

    while ((ch = fgetc(fp)) != EOF && ch != 0 && ch != '\n') len++;

    if (fseek(fp, offset, SEEK_SET) == -1) return -1;

    return len;
}
static inline void list_init(struct OSIS::list_head *lh)
{
    lh->next = lh;
    lh->prev = lh;
}
struct OSIS::proc_maps_entry *OSIS::ptrace_procfs_maps_read_entry(FILE *fp)
{
    struct OSIS::proc_maps_entry *entry;
    unsigned long long offset;
    void *vm_start, *vm_end;
    unsigned long inode;
    int major, minor;
    char flags[5];
    char *name;
    size_t len;
    int ch;

    /* read vma->vm_start and vma->vm_end */
    if (fscanf(fp, "%llx-%llx", &vm_start, &vm_end) != 2) return NULL;

    /* read flags */
    if (fscanf(fp, "%4s", flags) != 1) return NULL;

    /* read offset */
    if (fscanf(fp, "%llx", &offset) != 1) return NULL;

    /* read major and minor into dev_t */
    if (fscanf(fp, "%x:%x", &major, &minor) != 2) return NULL;

    /* read the inode */
    if (fscanf(fp, "%lu", &inode) != 1) return NULL;

    /* Finally we will read the filename, but this one is dynamic in
     * length, so we process the file twice.
     */
    skip_ws(fp);

    if ((len = file_strlen(fp)) == -1) return NULL;

    if ((name = (char *)malloc(len + 1)) == NULL) return NULL;

    if (len != 0 && fscanf(fp, "%s", name) != 1) {
        free(name);
        return NULL;
    }

    /* 0-terminate, in case len == 0 and we have an empty string. */
    name[len] = 0;
    if ((entry = (struct proc_maps_entry *)malloc(sizeof(*entry))) == NULL) {
        free(name);
        return NULL;
    }

    entry->flags = 0;
    if (flags[0] != '-') entry->flags |= VM_READ;
    if (flags[1] != '-') entry->flags |= VM_WRITE;
    if (flags[2] != '-') entry->flags |= VM_EXEC;
    if (flags[3] == 's') entry->flags |= VM_MAYSHARE;

    entry->start = vm_start;
    entry->end = vm_end;
    entry->offset = offset;
    entry->device = MKDEV(major, minor);
    entry->inode = inode;
    entry->name = name;
    list_init(&entry->list);

    return entry;
}
void OSIS::ptrace_procfs_map_entry_destroy(struct proc_maps_entry *entry)
{
    assert(entry != NULL);

    if (entry->name) free(entry->name);

    free(entry);
}
int OSIS::ptrace_procfs_maps_close(FILE *fp) { return fclose_no_EINTR(fp); }
void *OSIS::ptrace_procfs_maps_find_exec(pid_t pid)
{
    struct OSIS::proc_maps_entry *entry;
    long address;
    FILE *fp;

    /* errno already set here */
    if ((fp = ptrace_procfs_maps_open(pid)) == NULL) return (void *)-1;

    while ((entry = ptrace_procfs_maps_read_entry(fp)) != NULL) {
        if (entry->flags & VM_EXEC) {
            address = (long)entry->start;
            ptrace_procfs_map_entry_destroy(entry);
            ptrace_procfs_maps_close(fp);
            errno = 0;
            return (void *)address;
        }
        ptrace_procfs_map_entry_destroy(entry);
    }

    ptrace_procfs_maps_close(fp);
    errno = ENXIO; /* no such address */
    return (void *)-1;
}
bool OSIS::proc_mem_file_is_writable()
{
    static int writable = -1;

    if (writable != -1) return writable;

    writable = 0;
    /* We check whether /proc/pid/mem is writable by trying to write to
       one of our variables via /proc/self/mem.  */

    int fd = open("/proc/self/mem", O_RDWR | O_LARGEFILE, 0);

    if (fd == -1) {
        printf("opening /proc/self/mem file failed: %s (%d)", safe_strerror(errno), errno);
        return writable;
    }

    // SCOPE_EXIT { close (fd); };

    /* This is the variable we try to write to.  Note OFFSET below.  */
    volatile unsigned char test_var = 0;

    unsigned char writebuf[] = {0x55};
    ULONGEST offset = (uintptr_t)&test_var;
    ULONGEST xfered_len;

    enum target_xfer_status res =
        linux_proc_xfer_memory_partial_fd(fd, getpid(), nullptr, writebuf, offset, 1, &xfered_len);

    if (res == TARGET_XFER_OK) {
        // gdb_assert(xfered_len == 1);
        // gdb_assert(test_var == 0x55);
        if (xfered_len == 1 && test_var == 0x55) /* Success.  */
            writable = 1;
    }

    return writable;
}
enum OSIS::target_xfer_status OSIS::linux_proc_xfer_memory_partial_fd(int fd, int pid, unsigned char *readbuf,
                                                                      const unsigned char *writebuf, ULONGEST offset,
                                                                      LONGEST len, ULONGEST *xfered_len)
{
    ssize_t ret;
    ret = lseek(fd, offset, SEEK_SET);
    if (ret != -1) ret = (readbuf != nullptr ? read(fd, readbuf, len) : write(fd, writebuf, len));
    if (ret == -1) {
        printf("accessing fd %d for pid %d failed: %s (%d)\n", fd, pid, safe_strerror(errno), errno);
        return TARGET_XFER_E_IO;
    } else if (ret == 0) {
        /* EOF means the address space is gone, the whole process exited
       or execed.  */
        printf("accessing fd %d for pid %d got EOF\n", fd, pid);
        return TARGET_XFER_EOF;
    } else {
        *xfered_len = ret;
        return TARGET_XFER_OK;
    }
}
long OSIS::ptrace_peek_poke(pid_t pid, unsigned char *readbuf, const unsigned char *writebuf, ULONGEST addr,
                            ULONGEST len)
{
    ULONGEST n;
    unsigned int chunk;

    /* We transfer aligned words.  Thus align ADDR down to a word
       boundary and determine how many bytes to skip at the
       beginning.  */
    ULONGEST skip = addr & (sizeof(long) - 1);
    addr -= skip;
    for (n = 0; n < len; n += chunk, addr += sizeof(long), skip = 0) {
        /* Restrict to a chunk that fits in the current word.  */
        chunk = std::min(sizeof(long) - skip, len - n);

        /* Use a union for type punning.  */
        union {
            long word;
            unsigned char byte[sizeof(long)];
        } buf;

        /* Read the word, also when doing a partial word write.  */
        if (readbuf != NULL || chunk < sizeof(long)) {
            errno = 0;
            buf.word = ptrace(PT_READ_I, pid, (void *)addr, 0);
            if (errno != 0) break;
            if (readbuf != NULL) memcpy(readbuf + n, buf.byte + skip, chunk);
        }
        if (writebuf != NULL) {
            memcpy(buf.byte + skip, writebuf + n, chunk);
            errno = 0;
            ptrace(PT_WRITE_D, pid, (void *)addr, buf.word);
            if (errno != 0) {
                /* Using the appropriate one (I or D) is necessary for
               Gould NP1, at least.  */
                errno = 0;
                ptrace(PT_WRITE_I, pid, (void *)addr, buf.word);
                if (errno != 0) break;
            }
        }
    }

    return n;
}
int OSIS::create_fn_shellcode(void (*fn)(), uint8_t *shcodebuff, size_t len)
{
    /*(size_t i;
    uint8_t *shellcode = (uint8_t *)heapAlloc(len);
    uint8_t *p = (uint8_t *)fn;

    for (i = 0; i < len; i++)
        *(shellcode + i) = *p++;

    return shellcode;*/
    if (fn == NULL || shcodebuff == NULL) {
        output_debug_string(0, 1, "param check fail [fn,%p][shcodebuff,%p]  (%s:%d)\n",\ 
		fn,
                            shcodebuff, __FILE__, __LINE__);
        return -1;
        // OSIS::output_debug_string(1,1,)
    }
    uint8_t *p = (uint8_t *)fn;

    for (int i = 0; i < len; i++) *(shcodebuff + i) = *p++;
    return 0;
}
int OSIS::ptrace_wait_breakpoint(pid_t pid)
{
      return ptrace_wait_signal(pid, SIGTRAP);
}
int OSIS::ptrace_wait_signal(pid_t pid, int signum)
{
    int status;

    do {
        if (waitpid_no_EINTR(pid, &status, 0) == -1) {
            //	PTRACE_ERR_SET_EXTERNAL(pctx);
            return -1;
        }

        /* Child terminated normally */
        if (WIFEXITED(status)) {
            // PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
            return -1;
        }

        /* Child was terminated by a signal */
        if (WIFSIGNALED(status)) {
            //	PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
            return -1;
        }

        /* The child was stopped by a signal; this is what we
         * expected.  If it is not the signal we're looking for,
         * delegate it to the child and continue.
         */
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            // if (WSTOPSIG(status) == SIGCONT) {
            //	pctx->flags &= ~PTRACE_FLAG_SUSPENDED;
            // }
            if (sig == SYSCALL_SIGTRAP) {
                // 这是系统调用导致的停止
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);

                // 打印系统调用号
                printf("syscall: %lld\n", (long long)regs.orig_rax);
            } else if (sig == SIGTRAP) {
                // 这是断点或单步导致的停止
                printf("breakpoint or single-step\n");
            }

            if (WSTOPSIG(status) != signum && ptrace_continue_signal(pid, WSTOPSIG(status)) == -1) return -1;
        }
    } while (!WIFSTOPPED(status) || WSTOPSIG(status) != signum);

    return 0;
}
int OSIS::get_libc_info(pid_t pid, char *path, int size, unsigned long &addr)
{
    if (path == NULL || size > PATH_MAX) {
        output_debug_string(0, 1, "param check invalid! psth(%d),size(%d) (%s:%d)\n", path, size, __FILE__, __LINE__);
        return -1;
    }
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open maps file");
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        // 查找包含 libc 的行
        if (strstr(line, "libc.") && strstr(line, ".so")) {
            // 查找路径部分
            char *libc_path = strchr(line, '/');
            if (!libc_path) return -1;
            char *p = strchr(libc_path, '\n');
            if (p) {
                *p = '\0';
            }
            printf("libc path: %s", libc_path);
            snprintf(path, size - 1, "%s", libc_path);

            // 获取 libc 的起始地址
            sscanf(line, "%lx", &addr);
            printf("libc base address: 0x%lx\n", addr);

            fclose(file);
            return 0;
        }
    }

    printf("libc not found in the maps\n");
    fclose(file);
}
long OSIS::get_symvalue_from_libc(char *name, char *libc_path, Elf64_Addr &_sym_addr)
{
    OSIS::FileMmap t_libc_mmap;
    OSIS::Osis_elf t_libc_elf;
    uint8_t *p_mem_map = NULL;
    long mem_size = 0;
    long lret = 0;
    if (!name || !libc_path) {
        if (1)
            output_debug_string(0, 1, "param check invalid! name(%p),libc_path(%p) (%s:%d)\n", name, libc_path,
                                __FILE__, __LINE__);
        return -1;
    }

    t_libc_mmap.set_debug_flag(1);
    lret = t_libc_mmap.init(libc_path, O_RDWR, PROT_READ, MAP_PRIVATE);
    if (lret < 0) {
        printf("t_libc_mmap init fail\n");
        goto to_exit;
    }
    t_libc_elf.set_debug_flag(1);
    lret = t_libc_elf.set_mpath(libc_path, strlen(libc_path));
    if (lret < 0) {
        printf("t_libc_elf.set_mpath fail\n");
        goto to_exit;
    }
    t_libc_mmap.get_map_men(p_mem_map);

    t_libc_mmap.get_m_file_size(mem_size);
    t_libc_mmap.set_debug_flag(1);

    lret = t_libc_elf.load_from_Mem(p_mem_map, mem_size);
    if (lret < 0) {
        printf("t_libc_elf.load_from_Mem fail\n");
        goto to_exit;
    }
    t_libc_elf.find_section_dynamic();
    lret = t_libc_elf.parse_elf64();
    if (lret < 0) {
        printf("t_libc_elf.parse_elf64 fail\n");
        goto to_exit;
    }

    lret = t_libc_elf.find_symvalue_by_syname(name, _sym_addr);
    if (lret < 0) {
        printf("find_symvalue_by_syname( _libc_dlopen_mode fail\n");
        goto to_exit;
    }

    printf("__libc_dlopen_mode (%p)\n", _sym_addr);

    return 0;
to_exit:
    return -1;
}
long OSIS::ptrace_memset(pid_t pid, void *dest, u_int8_t _Val, size_t len)
{
    long lret = 0;
    int nullp_len = sizeof(void *);
    int sz = len / nullp_len;
    int ys = len % nullp_len;
    void *s = alloca(nullp_len);
    memset(s, _Val, nullp_len);
    void *d = dest;
    while (sz-- != 0) {
     //   lret = OSIS::ptrace_write(pid, (void *)d, (void *)s, nullp_len);
        lret = OSIS::ptrace_peek_poke(pid, NULL,(unsigned char *)s,(ULONGEST)d, nullp_len);
        if (lret < 0) {
            printf("Failed to ptrace_write origin_code\n");
            return -1;
        }
        d += nullp_len;
    }
    if (ys > 0) {
      //  lret = OSIS::ptrace_write(pid, (void *)d, (void *)s, ys);
        lret = OSIS::ptrace_peek_poke(pid, NULL,(unsigned char *)s,(ULONGEST)d, ys);
        if (lret < 0) {
            printf("Failed to ptrace_write origin_code\n");
            return -1;
        }
    }
    return 0;
}
long OSIS::get_so_baseaddr(pid_t pid, char *soname, char *path, int size, unsigned long &addr)
{
    if (path == NULL || size > PATH_MAX || soname == NULL) {
        output_debug_string(0, 1, "param check invalid!soname[%p] psth(%p),size(%d) (%s:%d)\n", soname, path, size,
                            __FILE__, __LINE__);
        return -1;
    }
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open maps file");
        return -1;
    }

    char line[1024];
    char *p = 0, *basename = 0;
    if ((p = strrchr(soname, '/')) != NULL)
        basename = strdup(p + 1);
    else
        basename = strdup(soname);
    while (fgets(line, sizeof(line), file)) {
        // 查找包含 libc 的行
        //  if (strstr(line, "libc.") && strstr(line, ".so")) {
        // 查找路径部分
        if (strstr(line, basename)) {
            char *libc_path = strchr(line, '/');
            if (!libc_path) {
                goto to_exit;
            }
            char *p = strchr(libc_path, '\n');
            if (p) {
                *p = '\0';
            }
            printf("libc path: %s", libc_path);
            snprintf(path, size - 1, "%s", libc_path);

            // 获取 libc 的起始地址
            sscanf(line, "%lx", &addr);
            printf("libc base address: 0x%lx\n", addr);
            if (basename) {
                free(basename);
            }
            fclose(file);
            return 0;
        }
    }
to_exit:
    printf("libc not found in the maps\n");
    fclose(file);
    if (basename) {
        free(basename);
    }
    return -1;
}

OSIS::ptid_t::ptid_t(pid_type pid, lwp_type lwp, tid_type tid) : pid_(pid), lwp_(lwp), tid_(tid) {}
OSIS::ptid_t::pid_type OSIS::ptid_t::get_pid() const { return pid_; }
OSIS::ptid_t::lwp_type OSIS::ptid_t::get_lwp() const { return lwp_; }
OSIS::ptid_t::tid_type OSIS::ptid_t::get_tid() const { return tid_; }