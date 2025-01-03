#ifndef __osis_ptrace_H__
#define __osis_ptrace_H__
#include <assert.h>
#include <cpuid.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kdev_t.h>
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

#include <iostream>
#include <string>
#include <unordered_set>
#include <utility>  // for std::pair

#include "osis_FileMmap.h"
#include "osis_tools.h"
#include "osis_elf.h"
namespace OSIS
{
#define PROC_DIR "/proc"
#define PROC_MAPS "maps"
#define PROC_STATUS "status"
#define VM_READ 0x00000001
#define VM_WRITE 0x00000002
#define VM_EXEC 0x00000004
#define VM_SHARED 0x00000008
#define VM_MAYSHARE 0x00000080
// XSAVE 特性标志位
#define XSAVE_FEATURE_FLAG 0x04000000
// 获取 XSTATE 大小和特性信息的结构
struct xsave_info {
    uint64_t features_supported;  // CPU 支持的特性掩码
    uint32_t size;                // 需要的总大小
    uint32_t user_size;           // 用户态可访问的大小
    uint32_t supervisor_size;     // 内核态可访问的大小
};
struct x86_64_all_reg {
    struct user_regs_struct regs;
    struct user_fpregs_struct fpregs;
    void *pxstate_buff;
    int xstateBuff_len;
};
#define MAZ_PAYLOAD_FUNC_ARGS 0X10
typedef enum { _PT_FUNCTION = 0, _PT_SYSCALL = 1 } ptype_t;
struct payload_call_function {
    uint8_t *shellcode;
    void *args[MAZ_PAYLOAD_FUNC_ARGS];
    uint64_t target;
    uint64_t retval;
    size_t size;
    int argc;
    ptype_t ptype;
    struct user_regs_struct regs;
};
struct list_head {
    struct list_head *next;
    struct list_head *prev;
};
struct proc_maps_entry {
    void *start;
    void *end;
    int flags;
    unsigned long long offset;
    dev_t device;
    unsigned long inode;
    char *name;

    struct list_head list;
};

enum proc_state {
    /* Some state we don't handle.  */
    PROC_STATE_UNKNOWN,

    /* Stopped on a signal.  */
    PROC_STATE_STOPPED,

    /* Tracing stop.  */
    PROC_STATE_TRACING_STOP,

    /* Dead.  */
    PROC_STATE_DEAD,

    /* Zombie.  */
    PROC_STATE_ZOMBIE,
    /*Sleeping*/
    PROC_STATE_SLEEPING,
    /*Running*/
    PROC_STATE_RUNNING,
    /*Uninterruptible Sleep.*/
    PROC_STATE_UNINTERRUPT_SLEEPING,
    /*idle*/
    PROC_STATE_IDLE,

};

class ptid_t
{
   public:
    using pid_type = int;       // 进程ID类型
    using lwp_type = long;      // 轻量级进程ID类型
    using tid_type = ULONGEST;  // 线程ID类型

    // 构造函数
    ptid_t(pid_type pid, lwp_type lwp = 0, tid_type tid = 0);

    // 访问函数
    pid_type get_pid() const;
    lwp_type get_lwp() const;
    tid_type get_tid() const;

   private:
    pid_type pid_;  // 进程ID
    lwp_type lwp_;  // 轻量级进程ID
    tid_type tid_;  // 线程ID
};
enum target_xfer_status {
    /* Some bytes are transferred.  */
    TARGET_XFER_OK = 1,

    /* No further transfer is possible.  */
    TARGET_XFER_EOF = 0,

    /* The piece of the object requested is unavailable.  */
    TARGET_XFER_UNAVAILABLE = 2,

    /* Generic I/O error.  Note that it's important that this is '-1',
       as we still have target_xfer-related code returning hardcoded
       '-1' on error.  */
    TARGET_XFER_E_IO = -1,

    /* Keep list in sync with target_xfer_status_to_string.  */
};


#define SYSCALL_SIGTRAP (SIGTRAP | 0x80)
#define LINUX_PROC_STAT_STATE 3
#define LINUX_PROC_STAT_STARTTIME 22
#define LINUX_PROC_STAT_PROCESSOR 39
typedef long (*linux_proc_attach_callback_func)(void *psrv, pid_t tid, int64_t flag, int type);
int osis_ptrace_attach(pid_t tid, void *psrv, linux_proc_attach_callback_func attach_lwp,bool systrap_flag);
FILE *fopen_no_EINTR(const char *path, const char *mode);
int fclose_no_EINTR(FILE *fp);
pid_t waitpid_no_EINTR(pid_t pid, int *status, int options);
int linux_proc_pid_is_stopped(pid_t pid);
int linux_proc_pid_has_state(pid_t pid, enum OSIS::proc_state state, int warn);
int linux_proc_pid_get_state(pid_t pid, int warn, enum proc_state *state);
int linux_nat_post_attach_wait(pid_t pid);
enum proc_state parse_proc_status_state(const char *state);
int kill_lwp(int lwpid, int signo);
std::string status_to_str(int status);
const char *strsigno(int signo);
long linux_proc_attach_tgid_threads(pid_t pid, void *psrv, linux_proc_attach_callback_func attach_lwp);
long linux_proc_get_int(pid_t lwpid, const char *field, int warn);
ULONGEST linux_proc_get_starttime(ptid_t ptid);
std::string linux_proc_get_stat_field(ptid_t ptid, int field);
std::string read_text_file_to_string(const char *path);
std::string read_remainder_of_file(FILE *file);
int attach_proc_task_lwp(ptid_t ptid);
long detach_one_pid(int pid, int signo);
long get_xsave_info(struct xsave_info *info);
void print_supported_features(uint64_t features);
void *allocate_xsave_area(size_t size);
long get_allreg(pid_t pid, struct x86_64_all_reg *pstru_x8664_all_reg);
long set_allreg(pid_t pid, struct x86_64_all_reg *pstru_x8664_all_reg);
long get_syscall_number(pid_t pid, long &syscall_number);
int ptrace_wait_event(pid_t pid);
int ptrace_continue_signal(pid_t pid, int signum);
void *ptrace_procfs_maps_find_exec(pid_t pid);
FILE *ptrace_procfs_maps_open(pid_t pid);
struct proc_maps_entry *ptrace_procfs_maps_read_entry(FILE *fp);
void ptrace_procfs_map_entry_destroy(struct proc_maps_entry *entry);
int ptrace_procfs_maps_close(FILE *fp);
bool proc_mem_file_is_writable();
enum target_xfer_status linux_proc_xfer_memory_partial_fd(int fd, int pid, unsigned char *readbuf,
                                                          const unsigned char *writebuf, ULONGEST offset, LONGEST len,
                                                          ULONGEST *xfered_len);
long ptrace_peek_poke(pid_t pid, unsigned char *readbuf, const unsigned char *writebuf, ULONGEST addr, ULONGEST len);
int create_fn_shellcode(void (*)(), uint8_t *shcodebuff, size_t len);
int ptrace_wait_breakpoint(pid_t pid);
int ptrace_wait_signal(pid_t pid, int signum);
int get_libc_info(pid_t pid,char * path ,int size,unsigned long &addr);
long get_symvalue_from_libc(char* name,char*libc_path,Elf64_Addr &_sym_addr);
long ptrace_memset(pid_t pid, void *dest, u_int8_t _Val, size_t len);
long get_so_baseaddr(pid_t pid,char*soname,char * path ,int size,unsigned long &addr);
}  // namespace OSIS

#endif