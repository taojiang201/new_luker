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
#include "osis_parasite.h"
OSIS::Osis_Parasite::Osis_Parasite()
{
    msa_state = OSIS_PT_DETACHED;
    parasite_type = 0;
}
OSIS::Osis_Parasite::~Osis_Parasite() {}

long OSIS::Osis_Parasite::load_parasite_file(char *path)
{
    long lret = -1;
    if (this->parasite_type == 0) lret = load_parasite_elffile(path);
    if (this->parasite_type == 1) lret = load_parasite_binfile(path);
    return lret;
}

long OSIS::Osis_Parasite::load_parasite_elffile(char *path)
{
    long lresult = 0;
    m_parasite_mmap.set_debug_flag(1);
    lresult = m_parasite_mmap.init(path, O_RDWR, PROT_READ | PROT_WRITE, MAP_PRIVATE);
    if (lresult < 0) return lresult;
    m_parasite_elf.set_debug_flag(1);
    lresult = m_parasite_elf.set_mpath(path, strlen(path));
    if (lresult < 0) return lresult;
    uint8_t *p_mem_map = NULL;
    m_parasite_mmap.get_map_men(p_mem_map);
    long mem_size = 0;
    m_parasite_mmap.get_m_file_size(mem_size);
    lresult = m_parasite_elf.load_from_Mem(p_mem_map, mem_size);
    if (lresult < 0) return lresult;
    m_parasite_elf.find_section_dynamic();
    lresult = m_parasite_elf.parse_elf64();
    if (lresult < 0) return lresult;
    return 0;
}
long OSIS::Osis_Parasite::load_parasite_binfile(char *path)
{
    long lresult = 0;
    m_parasite_mmap.set_debug_flag(1);
    lresult = m_parasite_mmap.init(path, O_RDWR, PROT_READ | PROT_WRITE, MAP_PRIVATE);
    if (lresult < 0) return lresult;

    return 0;
}
int OSIS::Osis_Parasite::injectCode_dlopen_so(pid_t pid)
{
    long lret = 0;
    int16_t ct_state = 0;
    int codesize = 0;
    void *origin_code = NULL;
    Elf64_Addr base_addr = 0;
    void *load_addr = NULL;
    void *common_addr = 0;
    void *stacktop_addr = 0;
    void *stack_addr = 0;
    int load_addr_len = 0;
    int common_addr_len = 0;
    int stacktop_addr_len = 0;

    this->get_msa_state(ct_state);
    if (!((ct_state ^ OSIS_PT_DETACHED) << 15)) {
        m_traceProc.init(&m_traceProc);
        m_traceProc.set_pid(pid);
        if (m_traceProc.safe_ptrace_attach_all() == -1) {
            printf("ptrace_attach fail pid=%d", pid);
            return -1;
        }
        ct_state = OSIS_PT_ATTACHED;
        this->set_msa_state(ct_state);
    }
    // { //test
    // lret=ptrace(PTRACE_CONT, pid, 0, 0);
    // m_traceProc.osisProcAttachCallback(&m_traceProc,pid,0x20,1);
    // }
    lret = m_traceProc.adjust_process_not_in_syscall();
    if (lret < 0) {
        printf("Failed to adjust_process_not_in_syscall\n");
        goto to_exit;
    }
    lret = m_traceProc.save_allreg(pid);
    if (lret < 0) {
        printf("Failed to get_allreg\n");
        goto to_exit;
    }
    lret = (Elf64_Addr)m_traceProc.retrieve_base_address();
    if (lret == -1) {
        printf("Failed to retrieve_base_address\n");
        goto to_exit;
    }
    base_addr = lret;
    codesize = ((uint64_t)osis_get_o_c_em_a_size - (uint64_t)osis_osisasm_create_exemem_align);
    origin_code = malloc(codesize);
    if (OSIS::ptrace_peek_poke(pid, (unsigned char *)origin_code, NULL, (ULONGEST)base_addr, codesize) == -1) {
        printf("ptrace_peek_poke-ptrace_read():origin_code fail \n");
        goto to_exit;
    }
    printf("the baseaddr= %p origin_code code:\n", base_addr);
    OSIS::print_hex((uint8_t *)origin_code, codesize);
    OSIS::payload_call_function payload_func_sc_b;
    lret = run_alloc_bootmap(pid, payload_func_sc_b, codesize, (void *)base_addr);
    if (lret < 0) {
        printf("Failed to run_alloc_bootmap\n");
        goto to_exit;
    }
     if (payload_func_sc_b.retval == -1) {
        printf("Failed to call_fn payload_func_sc_b.retval!=0\n");
        goto to_exit;
    }
    load_addr = (void *)payload_func_sc_b.regs.rdi;
    common_addr = (void *)payload_func_sc_b.regs.rsi;
    stack_addr = (void *)payload_func_sc_b.regs.rdx;
    load_addr_len = payload_func_sc_b.regs.r10;
    common_addr_len = payload_func_sc_b.regs.r8;
    stacktop_addr_len = payload_func_sc_b.regs.r9;
    stacktop_addr = stack_addr + stacktop_addr_len;

   // lret = OSIS::ptrace_write(pid, (void *)base_addr, (void *)origin_code, codesize);
    lret = OSIS::ptrace_peek_poke(pid, NULL,(unsigned char *)origin_code,base_addr, codesize);
     if (lret < 0) {
        printf("Failed to ptrace_write origin_code\n");
        goto to_exit;
    }
    printf("[+] calling exec_loader\n");
    printf("[+] dlopen elf exec_loader\n");
     {
        OSIS::payload_call_function payload_func_dl_e_l;
        lret = this->run_dlopen_so(pid, payload_func_dl_e_l, codesize, stacktop_addr, common_addr);
        if (lret < 0) {
            printf("Failed to run_dlopen_so\n");
            goto to_exit;
        }
    }

    {
        lret = OSIS::ptrace_memset(pid, stack_addr, 0, stacktop_addr_len);
        if (lret < 0) {
            printf("Failed to ptrace_memset\n");
            goto to_exit;
        }
        OSIS::payload_call_function payload_func_os_a_c;
        lret = run_sofunc_inthread(pid, payload_func_os_a_c, codesize, stacktop_addr, common_addr);
        if (lret < 0) {
            printf("Failed to run_sofunc_inthread\n");
            goto to_exit;
        }
    }
     lret =this->m_traceProc.restore_allreg(pid);
    if (lret < 0) {
        printf("Failed to set_allreg\n");
        goto to_exit;
    }

to_exit:
    if (origin_code) {
        free(origin_code);
    }
    m_traceProc.safe_detach_all();
    return lret;
}
long OSIS::Osis_Parasite::run_dlopen_so(pid_t pid, payload_call_function &p, int codesize, void *stacktop_addr,
                                        void *run_addr)
{
    long lret = 0;
    void *tascii_storage = stacktop_addr - 512;
    char *tparasite_path;
    int tmpath_len = 0;
    void *t_buffer = 0;
    Elf64_Addr t_dlopen_addr = 0;
    Elf64_Addr tlibc_addr = 0;
    uint64_t t_calladress = 0;
    uint64_t t_mode = 0;
    void *shellcode_dlopen_mode = 0;
    m_parasite_elf.get_mpath(tparasite_path);
    tmpath_len = strlen(tparasite_path) + 16;
    t_buffer = alloca(tmpath_len);  // malloc(tmpath_len);
    memset(t_buffer, 0, tmpath_len);
    // mpath
  //  lret = OSIS::ptrace_write(pid, (void *)tascii_storage, (void *)tparasite_path, tmpath_len);
    lret = OSIS::ptrace_peek_poke(pid, NULL,(unsigned char *)tparasite_path,(ULONGEST)tascii_storage, tmpath_len);
    if (lret < 0) {
        printf("Failed to ptrace_write tascii_storage\n");
        goto to_exit;
    }
    //if (OSIS::ptrace_read(pid, t_buffer, (void *)tascii_storage, tmpath_len) == -1) {
    if (OSIS::ptrace_peek_poke(pid, (unsigned char *)t_buffer, NULL,(ULONGEST)tascii_storage, tmpath_len) == -1) {
        printf("ptrace_read():tascii_storage \n");
        /// free(t_buffer);
        lret = -1;
        goto to_exit;
        // return -1;
    }
    printf("tparasite_path is %s\n", t_buffer);
    char tlibc_path[256];
    memset(tlibc_path, 0, 256);

    OSIS::get_libc_info(pid, (char *)tlibc_path, 256, tlibc_addr);
    printf("tlibc_path is %s,the libc entry is %p\n", tlibc_path, tlibc_addr);
    get_symvalue_from_libc("__libc_dlopen_mode", tlibc_path, t_dlopen_addr);
    printf("__libc_dlopen_mode (%p)\n", t_dlopen_addr);
    t_calladress = (uint64_t)(tlibc_addr + t_dlopen_addr);
    printf("__libc_dlopen_mode (%p) of pid(%d)\n", t_calladress, pid);
    codesize = ((uint64_t)osis_get_odl_m_s - (uint64_t)osis_dlopen_mode);
    shellcode_dlopen_mode = malloc(codesize);
    lret = OSIS::create_fn_shellcode((void (*)())osis_dlopen_mode, (uint8_t *)shellcode_dlopen_mode, codesize);
    if (lret < 0) {
        printf("Failed to create_fn_shellcode osis_dlopen_mode\n");
        goto to_exit;
    }
    printf("the shellcode_dlopen_mode code:\n");
    OSIS::print_hex((uint8_t *)shellcode_dlopen_mode, codesize);

    //  OSIS::payload_call_function payload_func_dl_e_l;

    t_mode = __RTLD_DLOPEN | RTLD_NOW | RTLD_GLOBAL;
    p.argc = 3;
    p.args[0] = tascii_storage;
    p.args[1] = (void *)t_calladress;  //(void *)(tlibc_addr + t_dlopen_addr);
    p.args[2] = (void *)t_mode;
    printf("payload_func_dl_e_l.args[0]=[%p],args[1]=[%p]\n", \ 
        p.args[0],
           p.args[1]);
    p.shellcode = (uint8_t *)shellcode_dlopen_mode;
    p.size = codesize;
    p.ptype = _PT_FUNCTION;
    p.retval = 0;
    lret == call_fn(pid, &p, (uint64_t)run_addr);
    if (lret = 0) {
        printf("Failed to call_fn\n");
        lret = -1;
        goto to_exit;
    }
to_exit:
    if (shellcode_dlopen_mode) {
        free(shellcode_dlopen_mode);
    }
    p.shellcode = 0;
    return lret;
}
long OSIS::Osis_Parasite::run_sofunc_inthread(pid_t pid, payload_call_function &p, int codesize, void *stacktop_addr,
                                              void *run_addr)
{
    long lret = 0;
    void *shellcode_osis_clone = 0;
    int flags = 0;
    Elf64_Addr _parasite_entry_addr = 0;
    Elf64_Addr _parasite_run_addr = 0;
    // lret = get_parasite_entry(pid, _parasite_entry_addr);
    char ttt___path[256];
    char *tparasite_path;
    m_parasite_elf.get_mpath(tparasite_path);

    lret = OSIS::get_so_baseaddr(pid, tparasite_path, ttt___path, 255, _parasite_entry_addr);
    if (lret < 0) {
        printf("get_parasite_entry( parasite_run_ fail\n");
        goto to_exit;
    }
    printf(" _parasite_entry_addr (%p) of pid(%d)\n", _parasite_entry_addr, pid);
    lret = m_parasite_elf.find_symvalue_by_syname("parasite_run_", _parasite_run_addr);
    if (lret < 0) {
        printf("find_symvalue_by_syname( parasite_run_ fail\n");
        goto to_exit;
    }
    printf(" _parasite_run_addr (%p) of pid(%d)\n", _parasite_run_addr, pid);
    _parasite_run_addr += _parasite_entry_addr;
    printf("new _parasite_run_addr (%p) of pid(%d)\n", _parasite_run_addr, pid);
    // codesize=osis_get_o_a_c_size-osis_asm_clone_;
    codesize = ((uint64_t)osis_get_o_a_c_size - (uint64_t)osis_asm_clone_);
    shellcode_osis_clone = malloc(codesize);
    lret = OSIS::create_fn_shellcode((void (*)())osis_asm_clone_, (uint8_t *)shellcode_osis_clone, codesize);
    if (lret < 0) {
        printf("Failed to create_fn_shellcode osis_asm_clone_\n");
        goto to_exit;
    }
    printf("the shellcode_dlopen_mode code:\n");
    OSIS::print_hex((uint8_t *)shellcode_osis_clone, codesize);
    flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | 0;
    p.size = codesize;
    p.shellcode = (uint8_t *)shellcode_osis_clone;
    p.argc = 4;
    p.retval = 0;
    p.ptype = _PT_FUNCTION;
    p.target = (uint64_t)run_addr;
    p.args[0] = (void *)_parasite_run_addr;
    p.args[1] = stacktop_addr;
    p.args[2] = (void *)flags;
    p.args[3] = (void *)123456;
    lret == call_fn(pid, &p, (uint64_t)run_addr);
    if (lret = 0) {
        printf("Failed to call_fn shellcode_osis_clone\n");
        lret = -1;
        goto to_exit;
    }

to_exit:
    if (shellcode_osis_clone) {
        free(shellcode_osis_clone);
    }
    return lret;
}

long OSIS::Osis_Parasite::run_alloc_bootmap(pid_t pid, payload_call_function &p, int codesize, void *base_addr)
{
    void *shellcode_boottrap = NULL;
    long lret = 0;
    shellcode_boottrap = malloc(codesize);
    lret = OSIS::create_fn_shellcode((void (*)())osis_osisasm_create_exemem_align, (uint8_t *)shellcode_boottrap,
                                     codesize);
    if (lret < 0) {
        printf("Failed to create_fn_shellcode\n");
        goto to_exit;
    }
    printf("the osisasm_create_exemem code:\n");
    OSIS::print_hex((uint8_t *)shellcode_boottrap, codesize);

    p.argc = 6;
    p.ptype = _PT_FUNCTION;
    p.shellcode = (uint8_t *)shellcode_boottrap;
    p.size = codesize;
    p.target = (uint64_t)base_addr;
    p.args[0] = (void *)(10 * 1024);
    p.args[1] = (void *)(16 * 1024);
    p.args[2] = (void *)(8 * 1024 * 1024);
    p.args[3] = 0;
    p.args[4] = 0;
    p.args[5] = 0;
    p.retval = 0;

    lret == call_fn(pid, &p, (uint64_t)base_addr);
    if (lret < 0) {
        printf("Failed to call_fn\n");
        goto to_exit;
    }

to_exit:
    if (shellcode_boottrap) {
        free(shellcode_boottrap);
    }
    p.shellcode = 0;
    return lret;
}
long OSIS::Osis_Parasite::call_fn(pid_t pid, struct payload_call_function *p, uint64_t ip)
{
    if (!p) {
        printf(
            "OSIS::Osis_Parasite::call_fn check param fail! \
        payload_call_function[%p] ip=%p pid=%d \n",
            p, ip, pid);
        return -1;
    }
    int16_t ct_state = 0;
    long lret = 0;
    this->get_msa_state(ct_state);
    if (!((ct_state ^ OSIS_PT_DETACHED) << 15)) {
        printf("OSIS::Osis_Parasite::call_fn check msa_state fail! msa_state[%d]  \n", ct_state);
        return -1;
    }

    uint8_t *shellcode;
    uint8_t *sc;
    size_t code_size;
    int argc, i;
    // struct user_regs_struct t_reg;
    Elf64_Addr entry_point;
    shellcode = p->shellcode;
    code_size = p->size;
    argc = p->argc;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &(p->regs)) < 0) {
        printf("OSIS::Osis_Parasite::call_fn ptrace PTRACE_GETREGS FAIL \n");
        return -1;
    }
    entry_point = ip ? ip : p->target;
    switch (p->ptype) {
    case _PT_FUNCTION:
        // if (pid_write(h->tasks.pid, (void *)entry_point, (void *)shellcode, code_size) < 0) return -1;
      //  if (OSIS::ptrace_write(pid, (void *)entry_point, (void *)shellcode, code_size) < 0) {
          if (OSIS::ptrace_peek_poke(pid, NULL, (const unsigned char *)shellcode,entry_point, code_size) < 0) { 
            printf("OSIS::Osis_Parasite::call_fn ptrace_write FAIL \n");
            return -1;
        }
        break;

    case _PT_SYSCALL:
        sc = (uint8_t *)alloca(ULONG_ROUND(code_size) + 16);
#if DEBUG
        for (i = 0; i < code_size + 8; i++) {
            printf("%02x", shellcode[i]);
            if (i % 32 == 0) printf("\n");
        }
#endif
        memcpy(sc, shellcode, code_size);
        for (i = 0; i < 4; i++) sc[code_size + i] = 0xCC;
        code_size += 4;
        // if (pid_write(h->tasks.pid, (void *)entry_point, (void *)sc, code_size) < 0) return -1;
      //  if (OSIS::ptrace_write(pid, (void *)entry_point, (void *)sc, code_size) < 0) {
          if (OSIS::ptrace_peek_poke(pid, NULL, (const unsigned char *)sc,entry_point, code_size) < 0) { 
            printf("OSIS::Osis_Parasite::call_fn ptrace_write 1 FAIL \n");
            return -1;
        }
        break;
    }
    (p->regs).rip = entry_point;
    switch (argc) {
    case 1:
        p->regs.rdi = (uintptr_t)p->args[0];
        break;
    case 2:
        p->regs.rdi = (uintptr_t)p->args[0];
        p->regs.rsi = (uintptr_t)p->args[1];
        break;
    case 3:
        p->regs.rdi = (uintptr_t)p->args[0];
        p->regs.rsi = (uintptr_t)p->args[1];
        p->regs.rdx = (uintptr_t)p->args[2];
        break;
    case 4:
        p->regs.rdi = (uintptr_t)p->args[0];
        p->regs.rsi = (uintptr_t)p->args[1];
        p->regs.rdx = (uintptr_t)p->args[2];
        p->regs.rcx = (uintptr_t)p->args[3];
        break;
    case 5:
        p->regs.rdi = (uintptr_t)p->args[0];
        p->regs.rsi = (uintptr_t)p->args[1];
        p->regs.rdx = (uintptr_t)p->args[2];
        p->regs.rcx = (uintptr_t)p->args[3];
        p->regs.r8 = (uintptr_t)p->args[4];
        break;
    case 6:
        p->regs.rdi = (uintptr_t)p->args[0];
        p->regs.rsi = (uintptr_t)p->args[1];
        p->regs.rdx = (uintptr_t)p->args[2];
        p->regs.rcx = (uintptr_t)p->args[3];
        p->regs.r8 = (uintptr_t)p->args[4];
        p->regs.r9 = (uintptr_t)p->args[5];
        break;
    }
    if (ptrace(PTRACE_SETREGS, pid, NULL, &(p->regs)) < 0) {
        printf("OSIS::Osis_Parasite::call_fn ptrace(PTRACE_SETREGS  1 FAIL \n");
        return -1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        printf("OSIS::Osis_Parasite::call_fn ptrace(PTRACE_CONT  1 FAIL \n");
        return -1;
    }
    this->m_traceProc.osisThreadAttachCallback(&this->m_traceProc,pid,0x28,1);//signalled=0,stopped =0
    // waitpid2(h->tasks.pid, &status, 0);
    lret = OSIS::ptrace_wait_breakpoint(pid);
   //lret =this->m_traceProc.stop_wait_onethrede(pid); 
    if (lret < 0) {
        printf("OSIS::Osis_Parasite::call_fn ptrace_wait_breakpoint FAIL \n");
        return -1;
    }
    /* Get return value */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &(p->regs)) < 0) {
        printf("OSIS::Osis_Parasite::call_fn PTRACE_GETREGS 2 FAIL \n");
        return -1;
    }
    this->m_traceProc.osisThreadAttachCallback(&this->m_traceProc,pid,0x30,1);//stopped =1
    p->retval = (p->regs).rax;

    return 0;
}
int OSIS::Osis_Parasite::injectCode_dlopen_bin(pid_t pid)
{
    long lret = 0;
    int16_t ct_state = 0;
    int codesize = 0;
    void *origin_code = NULL;
    Elf64_Addr base_addr = 0;
    void *load_addr = NULL;
    void *common_addr = 0;
    void *stacktop_addr = 0;
    void *stack_addr = 0;
    int load_addr_len = 0;
    int common_addr_len = 0;
    int stacktop_addr_len = 0;

    this->get_msa_state(ct_state);
    if (!((ct_state ^ OSIS_PT_DETACHED) << 15)) {
        m_traceProc.init(&m_traceProc);
        m_traceProc.set_pid(pid);
        if (m_traceProc.safe_ptrace_attach_all() == -1) {
            printf("ptrace_attach fail pid=%d", pid);
            return -1;
        }
        ct_state = OSIS_PT_ATTACHED;
        this->set_msa_state(ct_state);
    }
    // { //test
    // lret=ptrace(PTRACE_CONT, pid, 0, 0);
    // m_traceProc.osisProcAttachCallback(&m_traceProc,pid,0x20,1);
    // }
    lret = m_traceProc.adjust_process_not_in_syscall();
    if (lret < 0) {
        printf("Failed to adjust_process_not_in_syscall\n");
        goto to_exit;
    }
    lret = m_traceProc.save_allreg(pid);
    if (lret < 0) {
        printf("Failed to get_allreg\n");
        goto to_exit;
    }
    lret = (Elf64_Addr)m_traceProc.retrieve_base_address();
    if (lret == -1) {
        printf("Failed to retrieve_base_address\n");
        goto to_exit;
    }
    base_addr = lret;
    codesize = ((uint64_t)osis_get_o_c_em_a_size - (uint64_t)osis_osisasm_create_exemem_align);
    origin_code = malloc(codesize);
    if (OSIS::ptrace_peek_poke(pid, (unsigned char *)origin_code, NULL, (ULONGEST)base_addr, codesize) == -1) {
        printf("ptrace_peek_poke-ptrace_read():origin_code fail \n");
        goto to_exit;
    }
    printf("the baseaddr= %p origin_code code:\n", base_addr);
    OSIS::print_hex((uint8_t *)origin_code, codesize);
    OSIS::payload_call_function payload_func_sc_b;
    lret = run_alloc_bootmap(pid, payload_func_sc_b, codesize, (void *)base_addr);
    if (lret < 0) {
        printf("Failed to run_alloc_bootmap\n");
        goto to_exit;
    }
     if (payload_func_sc_b.retval == -1) {
        printf("Failed to call_fn payload_func_sc_b.retval!=0\n");
        goto to_exit;
    }
    load_addr = (void *)payload_func_sc_b.regs.rdi;
    common_addr = (void *)payload_func_sc_b.regs.rsi;
    stack_addr = (void *)payload_func_sc_b.regs.rdx;
    load_addr_len = payload_func_sc_b.regs.r10;
    common_addr_len = payload_func_sc_b.regs.r8;
    stacktop_addr_len = payload_func_sc_b.regs.r9;
    stacktop_addr = stack_addr + stacktop_addr_len;

   // lret = OSIS::ptrace_write(pid, (void *)base_addr, (void *)origin_code, codesize);
    lret = OSIS::ptrace_peek_poke(pid, NULL,(unsigned char *)origin_code,base_addr, codesize);
     if (lret < 0) {
        printf("Failed to ptrace_write origin_code\n");
        goto to_exit;
    }

    {
        long bin_len = -1;
        this->m_parasite_mmap.get_m_file_size(bin_len);
        if (bin_len > (common_addr_len - 16)) {
            printf("Failed to get_m_file_size\n");
            goto to_exit;
        }
        codesize = ((bin_len / 16) + 1) * 16;
        // inject_bin
        lret=inject_bin(pid,bin_len,common_addr);
        if (lret < 0) {
            printf("Failed to inject_bin\n");
            goto to_exit;
        }

        lret = OSIS::ptrace_memset(pid, stack_addr, 0, stacktop_addr_len);
        if (lret < 0) {
            printf("Failed to ptrace_memset\n");
            goto to_exit;
        }
        OSIS::payload_call_function payload_func_os_a_c;
        lret = run_bin_inthread(pid, payload_func_os_a_c, codesize, stacktop_addr, load_addr,common_addr);
        if (lret < 0) {
            printf("Failed to run_sofunc_inthread\n");
            goto to_exit;
        }
    }
    lret =this->m_traceProc.restore_allreg(pid);
    if (lret < 0) {
        printf("Failed to set_allreg\n");
        goto to_exit;
    }

    to_exit:
    if (origin_code) {
        free(origin_code);
    }
    m_traceProc.safe_detach_all();
    return lret;

}
long OSIS::Osis_Parasite::run_bin_inthread(pid_t pid,payload_call_function &p,int codesize,void * stacktop_addr,void *run_addr,void*bin_addr)
{
    long lret=0;
    void *shellcode_osis_clone = 0;
    int flags = 0;
   
    // codesize=osis_get_o_a_c_size-osis_asm_clone_;
    codesize = ((uint64_t)osis_get_o_a_c_size - (uint64_t)osis_asm_clone_);
    shellcode_osis_clone = malloc(codesize);
    lret = OSIS::create_fn_shellcode((void (*)())osis_asm_clone_, (uint8_t *)shellcode_osis_clone, codesize);
    if (lret < 0) {
        printf("Failed to create_fn_shellcode osis_asm_clone_\n");
        goto to_exit;
    }
    printf("the run_bin_inthread code:\n");
    OSIS::print_hex((uint8_t *)shellcode_osis_clone, codesize);
    flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | 0;
    p.size = codesize;
    p.shellcode = (uint8_t *)shellcode_osis_clone;
    p.argc = 4;
    p.retval = 0;
    p.ptype = _PT_FUNCTION;
    p.target = (uint64_t)run_addr;
    p.args[0] = (void *)bin_addr;
    p.args[1] = stacktop_addr;
    p.args[2] = (void *)flags;
    p.args[3] = (void *)123456;
    lret == call_fn(pid, &p, (uint64_t)run_addr);
    if (lret = 0) {
        printf("Failed to call_fn shellcode_osis_clone\n");
        lret = -1;
        goto to_exit;
    }

to_exit:
    if (shellcode_osis_clone) {
        free(shellcode_osis_clone);
    }
    return lret;

}
long OSIS::Osis_Parasite::inject_bin(pid_t pid, int bin_len, void *_addr)
{
    long lret = 0;
    void *shellcode_ = 0;
    long codesize = ((bin_len / 16) + 1) * 16;
    shellcode_ = malloc(codesize);
    memset(shellcode_, 0x90, codesize);  // fill nop
    u_int8_t *p_mem = 0;
    this->m_parasite_mmap.get_map_men(p_mem);
    memcpy(shellcode_, p_mem, bin_len);
    printf("the shellcode_ bin code:\n");
    OSIS::print_hex((uint8_t *)shellcode_, codesize);
   // lret = OSIS::ptrace_write(pid, _addr, shellcode_, codesize);
    lret =OSIS::ptrace_peek_poke(pid,NULL, (unsigned char *)shellcode_, (ULONGEST)_addr, codesize);
    if (lret < 0) {
        printf("Failed to ptrace_write tascii_storage\n");
        goto to_exit;
    }
to_exit:
    if (shellcode_) {
        free(shellcode_);
    }
    return lret;
}
long OSIS::Osis_Parasite::set_parasite_type(int32_t s)
{
    parasite_type = s;
    return 0;
}
long OSIS::Osis_Parasite::get_parasite_type(int32_t &g)
{
    g = parasite_type;
    return 0;
}
long OSIS::Osis_Parasite::set_msa_state(int16_t s)
{
    msa_state = s;
    return 0;
}
long OSIS::Osis_Parasite::get_msa_state(int16_t &g)
{
    g = msa_state;
    return 0;
}
