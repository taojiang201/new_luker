/*
 * Created on Thu Jan 02 2025
 *
 *               Copyright (c) 2025 Owen Jiang
 * 
 * This program is free software. You may use, modify, and redistribute it 
 * under the terms of the GNU General Public License as published by the   
 * Free Software Foundation, either version 3 or (at your option) any      
 * later version. This program is distributed without any warranty.  See   
 * the file COPYING.gpl-v3 for details.                                    
 *
 */

.section .data
.section .text
.type osis_dlopen_mode,@function
.globl osis_dlopen_mode
osis_dlopen_mode:
/*
%rdi= char *filename
%rsi= void* address of __libc_dlopen_mode
%rdx=mode
*/
push %rbp
movq %rsp,%rbp
andq $0xfffffffffffffff0,%rsp
movq %rsi,%rax
test %rdx,%rdx
jnz .L1
movq 0x02,%rdx
.L1:
movq %rdx,%rsi
callq *%rax
push %rax
#################test#########
movq $1,%rax
movq $1,%rdi
#movq $output2,%rsi
lea output2(%rip), %rsi
movq  $len2,%rdx
syscall
####################
pop %rax
int3
movq %rbp,%rsp
pop %rbp
ret
output2:.ascii "This is a test message by osis_dlopen_mode.\n"
output2_end:
.equ len2,output2_end-output2
.align 16
.L3:
.type osis_get_odl_m_s,@function
.globl osis_get_odl_m_s
osis_get_odl_m_s:
push %rbp
mov %rsp,%rbp
lea .L3-osis_dlopen_mode,%rax
mov %rbp,%rsp
pop %rbp
ret
.align 16

