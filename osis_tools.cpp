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
#include "osis_tools.h"
OSIS::Osis_tools::Osis_tools() {}

OSIS::Osis_tools::~Osis_tools() {}
locker OSIS::g_localtime_r_Locker;
/* Shorthand */
#define bl _sch_isblank
#define cn _sch_iscntrl
#define di _sch_isdigit
#define is _sch_isidst
#define lo _sch_islower
#define nv _sch_isnvsp
#define pn _sch_ispunct
#define pr _sch_isprint
#define sp _sch_isspace
#define up _sch_isupper
#define vs _sch_isvsp
#define xd _sch_isxdigit

/* Masks.  */
#define L (const unsigned short)(lo | is | pr)       /* lower case letter */
#define XL (const unsigned short)(lo | is | xd | pr) /* lowercase hex digit */
#define U (const unsigned short)(up | is | pr)       /* upper case letter */
#define XU (const unsigned short)(up | is | xd | pr) /* uppercase hex digit */
#define D (const unsigned short)(di | xd | pr)       /* decimal digit */
#define P (const unsigned short)(pn | pr)            /* punctuation */
#define _ (const unsigned short)(pn | is | pr)       /* underscore */

#define C (const unsigned short)(cn)                /* control character */
#define Z (const unsigned short)(nv | cn)           /* NUL */
#define M (const unsigned short)(nv | sp | cn)      /* cursor movement: \f \v */
#define V (const unsigned short)(vs | sp | cn)      /* vertical space: \r \n */
#define T (const unsigned short)(nv | sp | bl | cn) /* tab */
#define S (const unsigned short)(nv | sp | bl | pr) /* space */

/* Are we ASCII? */

const unsigned short _sch_istable[256] = {
    Z,
    C,
    C,
    C,
    C,
    C,
    C,
    C, /* NUL SOH STX ETX  EOT ENQ ACK BEL */
    C,
    T,
    V,
    M,
    M,
    V,
    C,
    C, /* BS  HT  LF  VT   FF  CR  SO  SI  */
    C,
    C,
    C,
    C,
    C,
    C,
    C,
    C, /* DLE DC1 DC2 DC3  DC4 NAK SYN ETB */
    C,
    C,
    C,
    C,
    C,
    C,
    C,
    C, /* CAN EM  SUB ESC  FS  GS  RS  US  */
    S,
    P,
    P,
    P,
    P,
    P,
    P,
    P, /* SP  !   "   #    $   %   &   '   */
    P,
    P,
    P,
    P,
    P,
    P,
    P,
    P, /* (   )   *   +    ,   -   .   /   */
    D,
    D,
    D,
    D,
    D,
    D,
    D,
    D, /* 0   1   2   3    4   5   6   7   */
    D,
    D,
    P,
    P,
    P,
    P,
    P,
    P, /* 8   9   :   ;    <   =   >   ?   */
    P,
    XU,
    XU,
    XU,
    XU,
    XU,
    XU,
    U, /* @   A   B   C    D   E   F   G   */
    U,
    U,
    U,
    U,
    U,
    U,
    U,
    U, /* H   I   J   K    L   M   N   O   */
    U,
    U,
    U,
    U,
    U,
    U,
    U,
    U, /* P   Q   R   S    T   U   V   W   */
    U,
    U,
    U,
    P,
    P,
    P,
    P,
    _, /* X   Y   Z   [    \   ]   ^   _   */
    P,
    XL,
    XL,
    XL,
    XL,
    XL,
    XL,
    L, /* `   a   b   c    d   e   f   g   */
    L,
    L,
    L,
    L,
    L,
    L,
    L,
    L, /* h   i   j   k    l   m   n   o   */
    L,
    L,
    L,
    L,
    L,
    L,
    L,
    L, /* p   q   r   s    t   u   v   w   */
    L,
    L,
    L,
    P,
    P,
    P,
    P,
    C, /* x   y   z   {    |   }   ~   DEL */

    /* high half of unsigned char is locale-specific, so all tests are
       false in "C" locale */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,

    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

const unsigned char _sch_tolower[256] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,
    22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,
    44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,

    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z',

    91,  92,  93,  94,  95,  96,

    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z',

    123, 124, 125, 126, 127,

    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171,
    172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,

    192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
    214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235,
    236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
};

const unsigned char _sch_toupper[256] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,
    22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,
    44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,

    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z',

    91,  92,  93,  94,  95,  96,

    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z',

    123, 124, 125, 126, 127,

    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171,
    172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,

    192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
    214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235,
    236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
};

long OSIS::get_file_size(const char* path)
{
    long filesize = -1;
    struct stat statbuff;
    if (stat(path, &statbuff) < 0) {
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }
    return filesize;
}
long OSIS::get_file_size_fd(int fd)
{
    long filesize = -1;
    struct stat statbuff;
    if (fstat(fd, &statbuff) < 0) {
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }
    return filesize;
}
int OSIS::GblLogMsg(int debugLevel, const char* format, ...)
{
    // ilevel = 0;

    return 0;
}

int OSIS::output_debug_string(int debug_level, int info_level, const char* format, ...)
{
    char tmpbuf[128], day[256], LogTxt[8192];
    char arg_buffer[9216];
    memset(tmpbuf, 0, 128);
    memset(day, 0, 256);
    memset(LogTxt, 0, 8192);
    memset(arg_buffer, 0, 9216);
    va_list arglist;
    struct tm* p1 = NULL;
    struct timespec ts;
    struct tm tm_info;
    struct tm* p = &tm_info;
    // 获取当前时间
    clock_gettime(CLOCK_REALTIME, &ts);
    // 转换为tm结构体
    p1 = localtime_r(&ts.tv_sec, &tm_info);
    if (p1 == NULL) {
        printf("localtime_r fail!\n");
    }
    // 格式化时间为年月日时分秒
    // strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    va_start(arglist, format);
    vsnprintf(LogTxt, 8192 - 1, format, arglist);
    va_end(arglist);
    sprintf(tmpbuf, "%d:%02d:%02d:%02d:%02d:%02d.%09.9d", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, p->tm_hour,
            p->tm_min, p->tm_sec, ts.tv_nsec);
    snprintf(arg_buffer, 9216 - 1, "%s--%s\n", tmpbuf, LogTxt);

    if (info_level == 0)
        fprintf(stdout, "%s%s", "[INFO]:", arg_buffer);
    else
        fprintf(stderr, "%s%s", "[ERR:]", arg_buffer);
    return 0;
}

void OSIS::nolocks_localtime(struct tm* tmp, time_t t, time_t tz, int dst) {}
void OSIS::print_hex(const unsigned char* buff, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        printf("0X%02X ", buff[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

size_t OSIS::get_current_cwd_pname(char* processdir, size_t dirLen, char* processname, size_t nameLen)

{
    char* path_end;

    if (readlink("/proc/self/exe", processdir, dirLen) <= 0) return -1;

    path_end = strrchr(processdir, '/');

    if (path_end == NULL) return -1;

    ++path_end;

    // strcpy(processname, path_end);
    strncpy(processname, path_end, nameLen);
    *path_end = '\0';

    return (size_t)(path_end - processdir);
}
char* OSIS::skip_spaces(char* chp)
{
    if (chp == NULL) return NULL;
    while (*chp && ISSPACE(*chp)) chp++;
    return chp;
}

/* A const-correct version of the above.  */

const char* OSIS::skip_spaces(const char* chp)
{
    if (chp == NULL) return NULL;
    while (*chp && ISSPACE(*chp)) chp++;
    return chp;
}

std::string OSIS::string_printf(const char* fmt, ...)
{
    va_list vp;
    int size;

    va_start(vp, fmt);
    size = vsnprintf(NULL, 0, fmt, vp);
    va_end(vp);

    std::string str(size, '\0');

    /* C++11 and later guarantee std::string uses contiguous memory and
       always includes the terminating '\0'.  */
    va_start(vp, fmt);
    vsprintf(&str[0], fmt, vp); /* ARI: vsprintf */
    va_end(vp);

    return str;
}

OSIS::ULONGEST OSIS::strtoulst(const char* num, const char** trailer, int base)
{
    unsigned int high_part;
    ULONGEST result;
    int minus = 0;
    int i = 0;

    /* Skip leading whitespace.  */
    while (ISSPACE(num[i])) i++;

    /* Handle prefixes.  */
    if (num[i] == '+')
        i++;
    else if (num[i] == '-') {
        minus = 1;
        i++;
    }

    if (base == 0 || base == 16) {
        if (num[i] == '0' && (num[i + 1] == 'x' || num[i + 1] == 'X')) {
            i += 2;
            if (base == 0) base = 16;
        }
    }

    if (base == 0 && num[i] == '0') base = 8;

    if (base == 0) base = 10;

    if (base < 2 || base > 36) {
        errno = EINVAL;
        return 0;
    }

    result = high_part = 0;
    for (; is_digit_in_base(num[i], base); i += 1) {
        result = result * base + digit_to_int(num[i]);
        high_part = high_part * base + (unsigned int)(result >> HIGH_BYTE_POSN);
        result &= ((ULONGEST)1 << HIGH_BYTE_POSN) - 1;
        if (high_part > 0xff) {
            errno = ERANGE;
            result = ~(ULONGEST)0;
            high_part = 0;
            minus = 0;
            break;
        }
    }

    if (trailer != NULL) *trailer = &num[i];

    result = result + ((ULONGEST)high_part << HIGH_BYTE_POSN);
    if (minus)
        return -result;
    else
        return result;
}
int OSIS::is_digit_in_base(unsigned char digit, int base)
{
    if (!ISALNUM(digit)) return 0;
    if (base <= 10)
        return (ISDIGIT(digit) && digit < base + '0');
    else
        return (ISDIGIT(digit) || TOLOWER(digit) < base - 10 + 'a');
}
int OSIS::digit_to_int(unsigned char c)
{
    if (ISDIGIT(c))
        return c - '0';
    else
        return TOLOWER(c) - 'a' + 10;
}
static char* select_strerror_r(int res, char* buf) { return res == 0 ? buf : nullptr; }

/* Called if we have a GNU strerror_r.  */
static char* select_strerror_r(char* res, char*) { return res; }
const char* OSIS::safe_strerror(int errnum)
{
    static thread_local char buf[1024];

    char* res = select_strerror_r(strerror_r(errnum, buf, sizeof(buf)), buf);
    if (res != nullptr) return res;

    snprintf(buf, sizeof buf, "(undocumented errno %d)", errnum);
    return buf;
}
