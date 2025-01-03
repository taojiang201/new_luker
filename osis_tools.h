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
#ifndef __osis_tools_H__
#define __osis_tools_H__
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>

#include "SCS.h"
enum {
    /* In C99 */
    _sch_isblank = 0x0001,  /* space \t */
    _sch_iscntrl = 0x0002,  /* nonprinting characters */
    _sch_isdigit = 0x0004,  /* 0-9 */
    _sch_islower = 0x0008,  /* a-z */
    _sch_isprint = 0x0010,  /* any printing character including ' ' */
    _sch_ispunct = 0x0020,  /* all punctuation */
    _sch_isspace = 0x0040,  /* space \t \n \r \f \v */
    _sch_isupper = 0x0080,  /* A-Z */
    _sch_isxdigit = 0x0100, /* 0-9A-Fa-f */

    /* Extra categories useful to cpplib.  */
    _sch_isidst = 0x0200, /* A-Za-z_ */
    _sch_isvsp = 0x0400,  /* \n \r */
    _sch_isnvsp = 0x0800, /* space \t \f \v \0 */

    /* Combinations of the above.  */
    _sch_isalpha = _sch_isupper | _sch_islower, /* A-Za-z */
    _sch_isalnum = _sch_isalpha | _sch_isdigit, /* A-Za-z0-9 */
    _sch_isidnum = _sch_isidst | _sch_isdigit,  /* A-Za-z0-9_ */
    _sch_isgraph = _sch_isalnum | _sch_ispunct, /* isprint and not space */
    _sch_iscppsp = _sch_isvsp | _sch_isnvsp,    /* isspace + \0 */
    _sch_isbasic = _sch_isprint | _sch_iscppsp  /* basic charset of ISO C
                           (plus ` and @)  */
};
extern const unsigned short _sch_istable[256];
extern const unsigned char  _sch_toupper[256];
extern const unsigned char  _sch_tolower[256];
#define _sch_test(c, bit) (_sch_istable[(c) & 0xff] & (unsigned short)(bit))

#define ISALPHA(c) _sch_test(c, _sch_isalpha)
#define ISALNUM(c) _sch_test(c, _sch_isalnum)
#define ISBLANK(c) _sch_test(c, _sch_isblank)
#define ISCNTRL(c) _sch_test(c, _sch_iscntrl)
#define ISDIGIT(c) _sch_test(c, _sch_isdigit)
#define ISGRAPH(c) _sch_test(c, _sch_isgraph)
#define ISLOWER(c) _sch_test(c, _sch_islower)
#define ISPRINT(c) _sch_test(c, _sch_isprint)
#define ISPUNCT(c) _sch_test(c, _sch_ispunct)
#define ISSPACE(c) _sch_test(c, _sch_isspace)
#define ISUPPER(c) _sch_test(c, _sch_isupper)
#define ISXDIGIT(c) _sch_test(c, _sch_isxdigit)

#define ISIDNUM(c) _sch_test(c, _sch_isidnum)
#define ISIDST(c) _sch_test(c, _sch_isidst)
#define IS_ISOBASIC(c) _sch_test(c, _sch_isbasic)
#define IS_VSPACE(c) _sch_test(c, _sch_isvsp)
#define IS_NVSPACE(c) _sch_test(c, _sch_isnvsp)
#define IS_SPACE_OR_NUL(c) _sch_test(c, _sch_iscppsp)

#define TOUPPER(c) _sch_toupper[(c) & 0xff]
#define TOLOWER(c) _sch_tolower[(c) & 0xff]
namespace OSIS
{

typedef int64_t LONGEST;
typedef uint64_t ULONGEST;
#if !defined (TARGET_CHAR_BIT)
#define TARGET_CHAR_BIT 8
#endif

/* * If we picked up a copy of CHAR_BIT from a configuration file
   (which may get it by including <limits.h>) then use it to set
   the number of bits in a host char.  If not, use the same size
   as the target.  */

#if defined (CHAR_BIT)
#define HOST_CHAR_BIT CHAR_BIT
#else
#define HOST_CHAR_BIT TARGET_CHAR_BIT
#endif

/* * The largest CORE_ADDR value.  */
#define CORE_ADDR_MAX (~(CORE_ADDR) 0)

/* * The largest ULONGEST value, 0xFFFFFFFFFFFFFFFF for 64-bits.  */
#define ULONGEST_MAX (~(ULONGEST) 0)

/* * The largest LONGEST value, 0x7FFFFFFFFFFFFFFF for 64-bits.  */
#define LONGEST_MAX ((LONGEST) (ULONGEST_MAX >> 1))

/* * The smallest LONGEST value, 0x8000000000000000 for 64-bits.  */
#define LONGEST_MIN ((LONGEST) (~(LONGEST) 0 ^ LONGEST_MAX))
#define HIGH_BYTE_POSN ((sizeof (ULONGEST) - 1) * HOST_CHAR_BIT)

extern locker g_localtime_r_Locker;
typedef uint64_t ULONGEST;
class Osis_tools
{
   public:
    Osis_tools();
    ~Osis_tools();
};

long get_file_size(const char* path);
long get_file_size_fd(int fd);
void nolocks_localtime(struct tm* tmp, time_t t, time_t tz, int dst);
int GblLogMsg(int debugLevel, const char* format, ...);
int output_debug_string(int debug_level, int info_level, const char* format, ...);
void print_hex(const unsigned char* buff, size_t size);
size_t get_current_cwd_pname(char* processdir, size_t dirLen, char* processname, size_t nameLen);
char* skip_spaces(char* chp);
const char* skip_spaces(const char* chp);
std::string string_printf(const char* fmt, ...);
ULONGEST
strtoulst(const char* num, const char** trailer, int base);
int is_digit_in_base(unsigned char digit, int base);
 int
digit_to_int (unsigned char c);
const char *
safe_strerror (int errnum);
void print_hex(const unsigned char* buff, size_t size);
}  // namespace OSIS
#endif