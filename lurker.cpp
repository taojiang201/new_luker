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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "osis_parasite.h"
#include "osis_tools.h"
int inject_type = 0;
int help(int argc, char **argv) { printf("Usage: %s [--b | --s] <pid> <parasite>\n", argv[0]);return 0; }
long check_args(int argc, char **argv){
    if (argc != 4) {
        help(argc, argv);
        return -1;
    }
    if (!strcmp(argv[1], "--b")) {
        inject_type = 1;
        return 0;
    } 
    if (!strcmp(argv[1], "--s")) {
        inject_type = 0;
        return 0;
    }
    help(argc, argv);
    return -1;
}

int main(int argc, char **argv){
    long lret=-1;
    if(-1==check_args(argc, argv))
        return -1;
    
    pid_t pid;
    pid=atoi(argv[2]);
    char so_fullpath[PATH_MAX+1];
    memset(so_fullpath,0,PATH_MAX+1);
    char cwd_fullpath[PATH_MAX+1]; 
    memset(cwd_fullpath,0,PATH_MAX+1);
    char exe_name[NAME_MAX+1];
    memset(exe_name,0,NAME_MAX+1);
    
    if(-1==OSIS::get_current_cwd_pname(cwd_fullpath,PATH_MAX,exe_name,NAME_MAX))
      return -1;
    
    snprintf(so_fullpath,PATH_MAX,"%s%s",cwd_fullpath,argv[3]);
    OSIS::Osis_Parasite parasite;
    parasite.set_parasite_type(inject_type);
   // lret=parasite.load_parasite_file(so_fullpath);
     if(-1==parasite.load_parasite_file(so_fullpath))
      return -1;
    
     switch (inject_type) {
    case 0:
        if (lret = parasite.injectCode_dlopen_so(pid) < 0) {
            OSIS::output_debug_string(0, 1, "parasite.injectCode_dlopen(%d) ret(%d) (%s:%d)\n", pid, lret, __FILE__,
                                      __LINE__);
            exit(0);
        }
        break;
    case 1:
        if (lret = parasite.injectCode_dlopen_bin(pid) < 0) {
            OSIS::output_debug_string(0, 1, "parasite.injectCode_dlopen(%d) ret(%d) (%s:%d)\n", pid, lret, __FILE__,
                                      __LINE__);
            exit(0);
        }
        break;
    default:
        return -1;
        break;
    }
    return 0;
}
