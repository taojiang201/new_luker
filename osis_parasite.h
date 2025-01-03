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
#ifndef __osis_Parasite_H__
#define __osis_Parasite_H__
#include <elf.h>
#include <dlfcn.h>
#include "osis_FileMmap.h"
#include "osis_tools.h"
#include "osis_elf.h"
#include "osis_ptrace.h"
#include "osis_trace_proc.h"
extern "C" long osis_osisasm_create_exemem_align(uint64_t, uint64_t , uint64_t,uint64_t*, uint64_t* , uint64_t*);
extern "C" int osis_get_o_c_em_a_size();
extern "C" int osis_dlopen_mode(uint64_t, uint64_t , uint64_t);
extern "C" int osis_get_odl_m_s();
extern "C" int osis_asm_clone_ (int (*fn)(void *arg), void *child_stack, int flags, void *arg);
extern "C" int osis_get_o_a_c_size();
namespace OSIS 
{
    #define OSIS_PT_DETACHED 0x00
    #define OSIS_PT_ATTACHED 0x01
    #define ULONG_ROUND(x) ((x + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))
    #define __RTLD_DLOPEN 0x80000000 //glibc internal dlopen flag emulates dlopen behaviour 
    class Osis_Parasite
    {
        public:
        Osis_Parasite(); 
        ~Osis_Parasite();
        long load_parasite_elffile(char *path);
        long load_parasite_binfile(char *path);
        int injectCode_dlopen_so(pid_t pid);
        int injectCode_dlopen_bin(pid_t pid);
        long set_parasite_type(int32_t s);
        long get_parasite_type(int32_t& g);
        long set_msa_state(int16_t s);
        long get_msa_state(int16_t& g);
        long load_parasite_file(char *path);
        
        private:
        int32_t parasite_type;
        OSIS::FileMmap m_parasite_mmap;
        OSIS::Osis_elf m_parasite_elf;
        int16_t msa_state;
        Osis_TraceProc m_traceProc;
        long run_alloc_bootmap(pid_t pid,payload_call_function &p,int codesize,void * base_addr);
        long call_fn(pid_t pid,struct payload_call_function* p,uint64_t ip);
        long run_dlopen_so(pid_t pid,payload_call_function &p,int codesize,void * stacktop_addr,void *run_addr);
        long run_sofunc_inthread(pid_t pid,payload_call_function &p,int codesize,void * stacktop_addr,void *run_addr);
        long run_bin_inthread(pid_t pid,payload_call_function &p,int codesize,void * stacktop_addr,void *run_addr,void*clone_addr);
        long inject_bin(pid_t pid,int bin_len,void * _addr);
    };


}

#endif