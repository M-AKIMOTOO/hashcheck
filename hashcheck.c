/*
 * M.AKIMOTO 
 * 2026/10/16
 *
 * hashcheck - cross-platform SHA-256 file/tree/range/block manifest / inspector / comparator
 *
 * Supported: Linux, macOS, Windows (MinGW-w64 / MSVC / Zig)
 * License: MIT-0 / public-domain style; use freely.
 *
 * Build examples
 * --------------
 * Linux / GCC:
 *   gcc -O3 -std=c11 -Wall -Wextra -D_FILE_OFFSET_BITS=64 hashcheck.c -ldl -o hashcheck
 *
 * Scientific Linux 6 / RHEL 6 (GCC 4.4.x):
 *   gcc -O3 -std=gnu99 -Wall -Wextra -D_FILE_OFFSET_BITS=64 hashcheck.c -ldl -o hashcheck
 *
 * Linux / Zig:
 *   zig cc -O3 -std=c11 hashcheck.c -o hashcheck
 *
 * macOS / Clang (cc):
 *   cc -O3 -std=c11 -Wall -Wextra hashcheck.c -o hashcheck
 *
 * Windows 11 x86_64 / Zig cross-compile:
 *   zig cc -O3 -std=c11 -target x86_64-windows-gnu -municode hashcheck.c -s -o hashcheck.exe
 *
 * Binary formats v1/v2 are explicitly serialized little-endian; no C structs
 * are written directly, so manifests are portable across OS/CPU ABI differences.
 *
 * v2 keeps the 64-byte header readable and compresses the record payload with a
 * small built-in raw-DEFLATE encoder (fixed Huffman codes). No zlib/miniz or
 * external compression command is required. v1 manifests remain readable.
 */

#define _CRT_SECURE_NO_WARNINGS 1
#define _FILE_OFFSET_BITS 64
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include <stdarg.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <wchar.h>
#  include <sys/stat.h>
#  include <io.h>
#  include <fcntl.h>
#else
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <sys/time.h>
#  include <dirent.h>
#  include <unistd.h>
#  include <limits.h>
#  if defined(__linux__) && !defined(HC_NO_LIBCRYPTO)
#    include <dlfcn.h>
#  endif
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

#define HC_VERSION_V1 1u
#define HC_VERSION_V2 2u
#define HC_HEADER_SIZE 64u
#define HC_HASH_SIZE 32u
#define HC_TRAILER_SIZE 40u
#define HC_MAX_PATH_BYTES (16u * 1024u * 1024u)

static const uint8_t HC_MAGIC_V1[8]  = {'H','C','H','K','B','N','1','\0'};
static const uint8_t HC_MAGIC_V2[8]  = {'H','C','H','K','B','N','2','\0'};
static const uint8_t HC_ENDMAG_V1[8] = {'H','C','H','K','E','N','D','1'};
static const uint8_t HC_ENDMAG_V2[8] = {'H','C','H','K','E','N','D','2'};

#define HC_FLAG_BINARY      0x00000001u
#define HC_FLAG_SHA256      0x00000002u
#define HC_FLAG_DIRHASH     0x00000004u
#define HC_FLAG_UTF8_PATHS  0x00000008u
#define HC_FLAG_RELPATHS    0x00000010u
#define HC_FLAG_COMPRESSED  0x00000020u
#define HC_FLAG_RANGE       0x00000040u
#define HC_FLAG_BLOCKS      0x00000080u
#define HC_FLAGS_BASE (HC_FLAG_BINARY|HC_FLAG_SHA256|HC_FLAG_DIRHASH|HC_FLAG_UTF8_PATHS|HC_FLAG_RELPATHS)
#define HC_FLAGS_V1 HC_FLAGS_BASE

#define HC_COMP_NONE          0u
#define HC_COMP_DEFLATE_FIXED 1u

#define HC_OS_UNKNOWN 0u
#define HC_OS_LINUX   1u
#define HC_OS_MACOS   2u
#define HC_OS_WINDOWS 3u
#define HC_HASH_SHA256 1u
#define HC_PATH_UTF8_SLASH 1u

#define RT_FILE 1u
#define RT_DIR  2u
#define RT_LINK 3u
#define RT_BLOCK 4u


static void dief(const char *fmt, ...);

/* ---------------- SHA-256 ---------------- */

typedef struct {
    uint32_t h[8];
    uint64_t total_len;
    uint8_t  buf[64];
    size_t   buf_len;
} sha256_ctx;

static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_transform(sha256_ctx *c, const uint8_t block[64]) {
    uint32_t w[64], a,b,cc,d,e,f,g,h;
    unsigned i;
    for (i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3]; e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
    for (i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_init(sha256_ctx *c) {
    static const uint32_t iv[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                                   0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    memcpy(c->h, iv, sizeof(iv));
    c->total_len = 0;
    c->buf_len = 0;
}

static void sha256_update(sha256_ctx *c, const void *data_, size_t len) {
    const uint8_t *data = (const uint8_t *)data_;
    size_t n;
    c->total_len += (uint64_t)len;

    /* Finish a partial block first. */
    if (c->buf_len) {
        n = 64u - c->buf_len;
        if (n > len) n = len;
        memcpy(c->buf + c->buf_len, data, n);
        c->buf_len += n; data += n; len -= n;
        if (c->buf_len == 64u) {
            sha256_transform(c, c->buf);
            c->buf_len = 0;
        }
    }

    /* Full blocks can be transformed directly from the caller's buffer. */
    while (len >= 64u) {
        sha256_transform(c, data);
        data += 64u;
        len  -= 64u;
    }

    if (len) {
        memcpy(c->buf, data, len);
        c->buf_len = len;
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bitlen = c->total_len * 8u;
    unsigned i;
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > 56) {
        while (c->buf_len < 64) c->buf[c->buf_len++] = 0;
        sha256_transform(c, c->buf);
        c->buf_len = 0;
    }
    while (c->buf_len < 56) c->buf[c->buf_len++] = 0;
    for (i = 0; i < 8; ++i) c->buf[63-i] = (uint8_t)(bitlen >> (i*8));
    sha256_transform(c, c->buf);
    for (i = 0; i < 8; ++i) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)c->h[i];
    }
}

/* ---------------- utilities ---------------- */

static void dief(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "hashcheck: error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(2);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) dief("out of memory");
    return p;
}
static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) dief("out of memory");
    return q;
}
static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)xmalloc(n);
    memcpy(p, s, n);
    return p;
}

static void hex32(const uint8_t h[32], char out[65]) {
    static const char hexd[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < 32; ++i) { out[i*2]=hexd[h[i]>>4]; out[i*2+1]=hexd[h[i]&15]; }
    out[64] = 0;
}

static void print_sha256(const uint8_t h[32], const char *label) {
    char digest[65];
    hex32(h, digest);
    printf("SHA-256  %s  %s\n", digest, label);
}

static void le16enc(uint8_t b[2], uint16_t v) { b[0]=(uint8_t)v; b[1]=(uint8_t)(v>>8); }
static void le32enc(uint8_t b[4], uint32_t v) { unsigned i; for(i=0;i<4;i++) b[i]=(uint8_t)(v>>(8*i)); }
static void le64enc(uint8_t b[8], uint64_t v) { unsigned i; for(i=0;i<8;i++) b[i]=(uint8_t)(v>>(8*i)); }
static uint16_t le16dec(const uint8_t b[2]) { return (uint16_t)b[0] | ((uint16_t)b[1]<<8); }
static uint32_t le32dec(const uint8_t b[4]) { return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24); }
static uint64_t le64dec(const uint8_t b[8]) { uint64_t v=0; int i; for(i=7;i>=0;i--) v=(v<<8)|b[i]; return v; }

static const char *os_name(uint8_t id) {
    switch (id) {
        case HC_OS_LINUX: return "Linux";
        case HC_OS_MACOS: return "macOS";
        case HC_OS_WINDOWS: return "Windows";
        default: return "Unknown";
    }
}
static uint8_t local_os_id(void) {
#ifdef _WIN32
    return HC_OS_WINDOWS;
#elif defined(__APPLE__)
    return HC_OS_MACOS;
#elif defined(__linux__)
    return HC_OS_LINUX;
#else
    return HC_OS_UNKNOWN;
#endif
}

static const char *type_name(uint8_t t) {
    switch (t) { case RT_FILE: return "FILE"; case RT_DIR: return "DIR "; case RT_LINK: return "LINK"; case RT_BLOCK: return "BLOCK"; default: return "????"; }
}

/* ---------------- record storage ---------------- */

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint64_t size;
    uint8_t hash[32];
    char *path;             /* UTF-8, slash-separated logical relative path */
} record;

typedef struct {
    record *v;
    size_t n, cap;
} record_vec;

static void records_push(record_vec *rv, uint8_t type, uint64_t size, const uint8_t hash[32], const char *path) {
    record *r;
    if (rv->n == rv->cap) {
        rv->cap = rv->cap ? rv->cap * 2 : 256;
        rv->v = (record *)xrealloc(rv->v, rv->cap * sizeof(*rv->v));
    }
    r = &rv->v[rv->n++];
    r->type = type; r->flags = 0; r->size = size; memcpy(r->hash, hash, 32); r->path = xstrdup(path);
}


static void records_free(record_vec *rv) {
    size_t i;
    for (i=0;i<rv->n;i++) free(rv->v[i].path);
    free(rv->v); rv->v=NULL; rv->n=rv->cap=0;
}

static int rec_path_cmp(const void *a, const void *b) {
    const record *ra=(const record *)a, *rb=(const record *)b;
    return strcmp(ra->path, rb->path);
}

/* ---------------- platform path helpers ---------------- */

#ifdef _WIN32

typedef wchar_t native_ch;
typedef wchar_t *native_str;

static char *wide_to_utf8(const wchar_t *w) {
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, NULL, 0, NULL, NULL);
    char *s;
    if (n <= 0) dief("cannot convert Windows path to UTF-8 (error %lu)", (unsigned long)GetLastError());
    s = (char *)xmalloc((size_t)n);
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, s, n, NULL, NULL)) dief("UTF-8 conversion failed");
    return s;
}

static wchar_t *wdup_(const wchar_t *s) {
    size_t n = wcslen(s)+1;
    wchar_t *p=(wchar_t *)xmalloc(n*sizeof(wchar_t));
    memcpy(p,s,n*sizeof(wchar_t)); return p;
}

static wchar_t *native_join(const wchar_t *a, const wchar_t *b) {
    size_t na=wcslen(a), nb=wcslen(b), sep=(na && a[na-1]!=L'\\' && a[na-1]!=L'/');
    wchar_t *p=(wchar_t *)xmalloc((na+sep+nb+1)*sizeof(wchar_t));
    memcpy(p,a,na*sizeof(wchar_t)); if(sep) p[na++]=L'\\'; memcpy(p+na,b,(nb+1)*sizeof(wchar_t)); return p;
}

static wchar_t *native_basename_dup(const wchar_t *p) {
    size_t n=wcslen(p), start;
    while (n>0 && (p[n-1]==L'\\' || p[n-1]==L'/')) n--;
    start=n; while(start>0 && p[start-1]!=L'\\' && p[start-1]!=L'/') start--;
    if (n==0 || n==start) {
        /* Drive/root input: use a stable readable synthetic name. */
        if (n>=2 && p[1]==L':') {
            wchar_t tmp[8] = L"drive-C"; tmp[6]=p[0]; return wdup_(tmp);
        }
        return wdup_(L"root");
    }
    {
        wchar_t *r=(wchar_t *)xmalloc((n-start+1)*sizeof(wchar_t));
        memcpy(r,p+start,(n-start)*sizeof(wchar_t)); r[n-start]=0; return r;
    }
}

static int path_is_manifest_native(const wchar_t *p) {
    FILE *f=_wfopen(p,L"rb"); uint8_t m[8]; size_t n;
    if(!f) return 0;
    n=fread(m,1,8,f);
    fclose(f);
    return n==8 && (memcmp(m,HC_MAGIC_V1,8)==0 || memcmp(m,HC_MAGIC_V2,8)==0);
}

static FILE *native_fopen_rb(const wchar_t *p) { return _wfopen(p,L"rb"); }

#else

typedef char native_ch;
typedef char *native_str;

static char *native_join(const char *a, const char *b) {
    size_t na=strlen(a), nb=strlen(b), sep=(na && a[na-1]!='/');
    char *p=(char *)xmalloc(na+sep+nb+1);
    memcpy(p,a,na); if(sep) p[na++]='/'; memcpy(p+na,b,nb+1); return p;
}

static char *native_basename_dup(const char *p) {
    size_t n=strlen(p), start;
    while(n>1 && p[n-1]=='/') n--;
    start=n; while(start>0 && p[start-1]!='/') start--;
    if(n==0 || n==start) return xstrdup("root");
    {
        char *r=(char *)xmalloc(n-start+1); memcpy(r,p+start,n-start); r[n-start]=0; return r;
    }
}

static int path_is_manifest_native(const char *p) {
    FILE *f=fopen(p,"rb"); uint8_t m[8]; size_t n;
    if(!f) return 0;
    n=fread(m,1,8,f);
    fclose(f);
    return n==8 && (memcmp(m,HC_MAGIC_V1,8)==0 || memcmp(m,HC_MAGIC_V2,8)==0);
}

static FILE *native_fopen_rb(const char *p) { return fopen(p,"rb"); }

#endif

static char *logical_join(const char *a, const char *b) {
    size_t na=strlen(a), nb=strlen(b);
    char *p=(char *)xmalloc(na+1+nb+1);
    memcpy(p,a,na); p[na]='/'; memcpy(p+na+1,b,nb+1); return p;
}


/* ---------------- accelerated file SHA-256 backend ----------------
 *
 * Large regular files/ranges dominate hashcheck runtime.  On Linux, try the
 * system OpenSSL/libcrypto EVP SHA-256 implementation first.  This normally
 * uses CPU SHA extensions (SHA-NI/ARM crypto) when available.  No OpenSSL
 * headers are required: symbols are resolved at runtime so old systems such
 * as Scientific Linux 6 can still build this single source file.  If no
 * compatible libcrypto is present, hashcheck falls back to the built-in
 * portable SHA-256 above.
 */
#if defined(__linux__) && !defined(HC_NO_LIBCRYPTO)
typedef struct {
    int tried;
    int available;
    void *lib;
    void *(*ctx_new)(void);
    void (*ctx_free)(void *);
    const void *(*sha256_md)(void);
    int (*digest_init_ex)(void *, const void *, void *);
    int (*digest_update)(void *, const void *, size_t);
    int (*digest_final_ex)(void *, unsigned char *, unsigned int *);
} hc_evp_api;

static hc_evp_api g_hc_evp;

static void *hc_dlsym_any(void *lib, const char *name) {
    return dlsym(lib, name);
}

static int hc_evp_load(void) {
    static const char *const names[] = {
        "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so.10",
        "libcrypto.so.1.0.0", "libcrypto.so", NULL
    };
    size_t i;
    void *lib = NULL;
    if(g_hc_evp.tried) return g_hc_evp.available;
    memset(&g_hc_evp, 0, sizeof(g_hc_evp));
    g_hc_evp.tried = 1;
    for(i=0; names[i]; ++i) {
        lib = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
        if(lib) break;
    }
    if(!lib) return 0;
    g_hc_evp.lib = lib;
    g_hc_evp.ctx_new = (void *(*)(void))hc_dlsym_any(lib, "EVP_MD_CTX_new");
    g_hc_evp.ctx_free = (void (*)(void *))hc_dlsym_any(lib, "EVP_MD_CTX_free");
    if(!g_hc_evp.ctx_new || !g_hc_evp.ctx_free) {
        g_hc_evp.ctx_new = (void *(*)(void))hc_dlsym_any(lib, "EVP_MD_CTX_create");
        g_hc_evp.ctx_free = (void (*)(void *))hc_dlsym_any(lib, "EVP_MD_CTX_destroy");
    }
    g_hc_evp.sha256_md = (const void *(*)(void))hc_dlsym_any(lib, "EVP_sha256");
    g_hc_evp.digest_init_ex = (int (*)(void *, const void *, void *))hc_dlsym_any(lib, "EVP_DigestInit_ex");
    g_hc_evp.digest_update = (int (*)(void *, const void *, size_t))hc_dlsym_any(lib, "EVP_DigestUpdate");
    g_hc_evp.digest_final_ex = (int (*)(void *, unsigned char *, unsigned int *))hc_dlsym_any(lib, "EVP_DigestFinal_ex");
    if(!g_hc_evp.ctx_new || !g_hc_evp.ctx_free || !g_hc_evp.sha256_md ||
       !g_hc_evp.digest_init_ex || !g_hc_evp.digest_update || !g_hc_evp.digest_final_ex) {
        dlclose(lib);
        memset(&g_hc_evp, 0, sizeof(g_hc_evp));
        g_hc_evp.tried = 1;
        return 0;
    }
    g_hc_evp.available = 1;
    return 1;
}

typedef struct {
    int use_evp;
    void *evp_ctx;
    sha256_ctx scalar;
} hc_file_hash_ctx;

static int hc_file_hash_init(hc_file_hash_ctx *c) {
    memset(c, 0, sizeof(*c));
    if(hc_evp_load()) {
        c->evp_ctx = g_hc_evp.ctx_new();
        if(c->evp_ctx && g_hc_evp.digest_init_ex(c->evp_ctx, g_hc_evp.sha256_md(), NULL) == 1) {
            c->use_evp = 1;
            return 0;
        }
        if(c->evp_ctx) g_hc_evp.ctx_free(c->evp_ctx);
        c->evp_ctx = NULL;
    }
    sha256_init(&c->scalar);
    return 0;
}

static int hc_file_hash_update(hc_file_hash_ctx *c, const void *data, size_t n) {
    if(c->use_evp) return g_hc_evp.digest_update(c->evp_ctx, data, n) == 1 ? 0 : -1;
    sha256_update(&c->scalar, data, n);
    return 0;
}

static int hc_file_hash_final(hc_file_hash_ctx *c, uint8_t out[32]) {
    if(c->use_evp) {
        unsigned int n = 0;
        int ok = g_hc_evp.digest_final_ex(c->evp_ctx, out, &n);
        g_hc_evp.ctx_free(c->evp_ctx);
        c->evp_ctx = NULL;
        return (ok == 1 && n == 32u) ? 0 : -1;
    }
    sha256_final(&c->scalar, out);
    return 0;
}
#else
typedef struct { sha256_ctx scalar; } hc_file_hash_ctx;
static int hc_file_hash_init(hc_file_hash_ctx *c) { sha256_init(&c->scalar); return 0; }
static int hc_file_hash_update(hc_file_hash_ctx *c, const void *data, size_t n) { sha256_update(&c->scalar,data,n); return 0; }
static int hc_file_hash_final(hc_file_hash_ctx *c, uint8_t out[32]) { sha256_final(&c->scalar,out); return 0; }
#endif

/* ---------------- progress ---------------- */

typedef struct {
    uint64_t total;
    uint64_t done;
    uint64_t units_total;
    uint64_t units_done;
    double start_sec;
    double last_sec;
    int tty;
    int active;
    const char *label;
} hc_progress;

static double hc_now_sec(void) {
#ifdef _WIN32
    return (double)GetTickCount64() / 1000.0;
#else
    struct timeval tv;
    if(gettimeofday(&tv,NULL)!=0) return (double)time(NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
#endif
}

static int hc_stderr_isatty(void) {
#ifdef _WIN32
    return _isatty(_fileno(stderr));
#else
    return isatty(fileno(stderr));
#endif
}

static void hc_fmt_bytes(double bytes, char *out, size_t n) {
    static const char *u[] = {"B","KiB","MiB","GiB","TiB","PiB"};
    int i=0;
    while(bytes>=1024.0 && i<5) { bytes/=1024.0; i++; }
    if(i==0) snprintf(out,n,"%.0f %s",bytes,u[i]);
    else snprintf(out,n,"%.1f %s",bytes,u[i]);
}

static void hc_fmt_eta(double sec, char *out, size_t n) {
    uint64_t s;
    unsigned h,m;
    if(sec < 0.0 || sec > 315360000.0) { snprintf(out,n,"--:--:--"); return; }
    s=(uint64_t)(sec+0.5); h=(unsigned)(s/3600u); m=(unsigned)((s%3600u)/60u);
    snprintf(out,n,"%02u:%02u:%02u",h,m,(unsigned)(s%60u));
}

static void hc_progress_begin(hc_progress *p, const char *label, uint64_t total, uint64_t units_total) {
    memset(p,0,sizeof(*p));
    p->total=total; p->units_total=units_total; p->start_sec=hc_now_sec(); p->last_sec=p->start_sec;
    p->tty=hc_stderr_isatty(); p->active=(total>0); p->label=label?label:"Hashing";
}

static void hc_progress_draw(hc_progress *p, int force) {
    double now,elapsed,speed,eta,pct;
    char done_s[32],total_s[32],eta_s[32];
    if(!p->active) return;
    now=hc_now_sec();
    /* Interactive terminal: refresh about 4 times/s. Redirected stderr: one line every 10 s. */
    if(!force) {
        double interval=p->tty?0.25:10.0;
        if(now-p->last_sec < interval) return;
    }
    p->last_sec=now; elapsed=now-p->start_sec;
    speed=(elapsed>0.0)?((double)p->done/elapsed):0.0;
    eta=(speed>0.0 && p->done<p->total)?((double)(p->total-p->done)/speed):0.0;
    pct=p->total?100.0*(double)p->done/(double)p->total:100.0;
    hc_fmt_bytes((double)p->done,done_s,sizeof(done_s));
    hc_fmt_bytes((double)p->total,total_s,sizeof(total_s));
    hc_fmt_eta(eta,eta_s,sizeof(eta_s));
    if(p->tty) fputc('\r',stderr);
    fprintf(stderr,"%s %6.2f%%  %s/%s  %7.1f MiB/s  ETA %s",
            p->label,pct,done_s,total_s,speed/(1024.0*1024.0),eta_s);
    if(p->units_total) fprintf(stderr,"  blocks %" PRIu64 "/%" PRIu64,p->units_done,p->units_total);
    if(p->tty) { fputs("        ",stderr); fflush(stderr); }
    else fputc('\n',stderr);
    if(force && p->tty) fputc('\n',stderr);
}

static void hc_progress_add(hc_progress *p, uint64_t n) {
    if(!p->active) return;
    p->done+=n; if(p->done>p->total) p->done=p->total;
    hc_progress_draw(p,0);
}

static void hc_progress_unit_done(hc_progress *p) {
    if(!p->active) return;
    if(p->units_done<p->units_total) p->units_done++;
    hc_progress_draw(p,0);
}

static void hc_progress_end(hc_progress *p) {
    if(!p->active) return;
    p->done=p->total; p->units_done=p->units_total;
    hc_progress_draw(p,1); p->active=0;
}

/* ---------------- hashing filesystem ---------------- */

static int hash_file_native(const native_ch *path, uint8_t out[32], uint64_t *size_out) {
    FILE *f = native_fopen_rb(path);
    uint8_t *buf;
    size_t n;
    uint64_t total=0;
    hc_file_hash_ctx c;
    hc_progress prog;
    uint64_t file_size=0;
    const size_t bufsz = 16u*1024u*1024u;
    if(!f) return -1;
#ifdef _WIN32
    if(_fseeki64(f,0,SEEK_END)==0) { __int64 z=_ftelli64(f); if(z>=0) file_size=(uint64_t)z; (void)_fseeki64(f,0,SEEK_SET); }
#else
    if(fseeko(f,(off_t)0,SEEK_END)==0) { off_t z=ftello(f); if(z>=0) file_size=(uint64_t)z; (void)fseeko(f,(off_t)0,SEEK_SET); }
#endif
    buf=(uint8_t *)xmalloc(bufsz);
    hc_file_hash_init(&c);
    hc_progress_begin(&prog,"Hashing",file_size,0);
    while((n=fread(buf,1,bufsz,f))>0) {
        if(hc_file_hash_update(&c,buf,n)!=0) { free(buf); fclose(f); return -1; }
        total+=(uint64_t)n; hc_progress_add(&prog,(uint64_t)n);
    }
    if(ferror(f)) { free(buf); fclose(f); return -1; }
    hc_progress_end(&prog);
    free(buf); fclose(f);
    if(hc_file_hash_final(&c,out)!=0) return -1;
    *size_out=total; return 0;
}

/* Hash exactly LENGTH bytes beginning at byte OFFSET.  No temporary split file
 * is created.  Return -2 when the requested range is outside the file. */
static int hash_file_range_native(const native_ch *path, uint64_t offset, uint64_t length,
                                  uint8_t out[32]) {
    FILE *f=native_fopen_rb(path);
    uint8_t *buf=NULL;
    uint64_t file_size,remaining=length;
    hc_file_hash_ctx c;
    hc_progress prog;
    const size_t bufsz = 16u*1024u*1024u;
    if(!f) return -1;
#ifdef _WIN32
    if(offset > (uint64_t)INT64_MAX || length > (uint64_t)INT64_MAX) { fclose(f); return -2; }
    if(_fseeki64(f,0,SEEK_END)!=0) { fclose(f); return -1; }
    { __int64 n=_ftelli64(f); if(n<0){fclose(f);return -1;} file_size=(uint64_t)n; }
    if(offset>file_size || length>file_size-offset) { fclose(f); return -2; }
    if(_fseeki64(f,(__int64)offset,SEEK_SET)!=0) { fclose(f); return -1; }
#else
    if(offset > (uint64_t)INT64_MAX || length > (uint64_t)INT64_MAX) { fclose(f); errno=EOVERFLOW; return -2; }
    if(fseeko(f,(off_t)0,SEEK_END)!=0) { fclose(f); return -1; }
    { off_t n=ftello(f); if(n<0){fclose(f);return -1;} file_size=(uint64_t)n; }
    if(offset>file_size || length>file_size-offset) { fclose(f); return -2; }
    if(fseeko(f,(off_t)offset,SEEK_SET)!=0) { fclose(f); return -1; }
#endif
    buf=(uint8_t *)xmalloc(bufsz);
    hc_file_hash_init(&c);
    hc_progress_begin(&prog,"Hashing",length,0);
    while(remaining>0) {
        size_t want=(remaining>(uint64_t)bufsz)?bufsz:(size_t)remaining;
        size_t n=fread(buf,1,want,f);
        if(n==0) { free(buf); fclose(f); return -1; }
        if(hc_file_hash_update(&c,buf,n)!=0) { free(buf); fclose(f); return -1; }
        remaining-=(uint64_t)n; hc_progress_add(&prog,(uint64_t)n);
    }
    hc_progress_end(&prog);
    free(buf);
    if(fclose(f)!=0) return -1;
    if(hc_file_hash_final(&c,out)!=0) return -1;
    return 0;
}


/* Hash a file/range as independent fixed-size blocks in one sequential pass.
 * Each record path is the byte offset RELATIVE to the selected range, so a
 * source range can be compared directly with a received file split with the
 * same --block size. */
static int hash_file_blocks_native(const native_ch *path, uint64_t offset, uint64_t length,
                                   uint64_t block_size, record_vec *rv) {
    FILE *f=native_fopen_rb(path);
    uint8_t *buf=NULL;
    uint64_t file_size,remaining=length,rel=0,total_blocks;
    hc_progress prog;
    const size_t bufsz=16u*1024u*1024u;
    if(!f || block_size==0) { if(f) fclose(f); return -1; }
#ifdef _WIN32
    if(offset>(uint64_t)INT64_MAX || length>(uint64_t)INT64_MAX) { fclose(f); return -2; }
    if(_fseeki64(f,0,SEEK_END)!=0) { fclose(f); return -1; }
    { __int64 n=_ftelli64(f); if(n<0){fclose(f);return -1;} file_size=(uint64_t)n; }
    if(offset>file_size || length>file_size-offset) { fclose(f); return -2; }
    if(_fseeki64(f,(__int64)offset,SEEK_SET)!=0) { fclose(f); return -1; }
#else
    if(offset>(uint64_t)INT64_MAX || length>(uint64_t)INT64_MAX) { fclose(f); errno=EOVERFLOW; return -2; }
    if(fseeko(f,(off_t)0,SEEK_END)!=0) { fclose(f); return -1; }
    { off_t n=ftello(f); if(n<0){fclose(f);return -1;} file_size=(uint64_t)n; }
    if(offset>file_size || length>file_size-offset) { fclose(f); return -2; }
    if(fseeko(f,(off_t)offset,SEEK_SET)!=0) { fclose(f); return -1; }
#endif
    buf=(uint8_t *)xmalloc(bufsz);
    total_blocks=(length + block_size - 1u) / block_size;
    hc_progress_begin(&prog,"Hashing",length,total_blocks);
    while(remaining>0) {
        uint64_t this_block=remaining<block_size?remaining:block_size;
        uint64_t br=this_block;
        uint8_t h[32]; char key[64]; hc_file_hash_ctx c;
        hc_file_hash_init(&c);
        while(br>0) {
            size_t want=(br>(uint64_t)bufsz)?bufsz:(size_t)br;
            size_t n=fread(buf,1,want,f);
            if(n==0) { free(buf); fclose(f); return -1; }
            if(hc_file_hash_update(&c,buf,n)!=0) { free(buf); fclose(f); return -1; }
            br-=(uint64_t)n; hc_progress_add(&prog,(uint64_t)n);
        }
        if(hc_file_hash_final(&c,h)!=0) { free(buf); fclose(f); return -1; }
        snprintf(key,sizeof(key),"+%020" PRIu64,rel);
        records_push(rv,RT_BLOCK,this_block,h,key);
        rel+=this_block;
        remaining-=this_block;
        hc_progress_unit_done(&prog);
    }
    hc_progress_end(&prog);
    free(buf);
    if(fclose(f)!=0) return -1;
    return 0;
}

typedef struct {
#ifdef _WIN32
    wchar_t *native_name;
#else
    char *native_name;
#endif
    char *utf8_name;
    uint8_t child_type;
    uint64_t child_size;
    uint8_t child_hash[32];
} child_item;

typedef struct { child_item *v; size_t n, cap; } child_vec;

static void child_push(child_vec *cv,
#ifdef _WIN32
                       const wchar_t *native_name,
#else
                       const char *native_name,
#endif
                       const char *utf8_name) {
    child_item *x;
    if(cv->n==cv->cap){cv->cap=cv->cap?cv->cap*2:64;cv->v=(child_item *)xrealloc(cv->v,cv->cap*sizeof(*cv->v));}
    x=&cv->v[cv->n++]; memset(x,0,sizeof(*x));
#ifdef _WIN32
    x->native_name=wdup_(native_name);
#else
    x->native_name=xstrdup(native_name);
#endif
    x->utf8_name=xstrdup(utf8_name);
}
static void child_free(child_vec *cv){size_t i;for(i=0;i<cv->n;i++){free(cv->v[i].native_name);free(cv->v[i].utf8_name);}free(cv->v);memset(cv,0,sizeof(*cv));}
static int child_cmp(const void *a,const void *b){return strcmp(((const child_item*)a)->utf8_name,((const child_item*)b)->utf8_name);}

#define HC_EXCLUDE_EXTENSION 1
#define HC_EXCLUDE_BASENAME 2
#define HC_EXCLUDE_PATH 3
typedef struct { int kind; char *pattern; } exclude_rule;
typedef struct { exclude_rule *v; size_t n, cap; } exclude_vec;
static void exclude_add(exclude_vec *ev,const char *value) {
    const char *p=value; int kind; size_t i; exclude_rule *r;
    if(!value || !*value) dief("--exclude value must not be empty");
    if(strncmp(p,"ext:",4)==0) { kind=HC_EXCLUDE_EXTENSION; p+=4; if(p[0]!=46 || !p[1] || strchr(p,47) || strchr(p,92)) dief("extension exclusions must look like ext:.tmp"); }
    else if(strncmp(p,"file:",5)==0) { kind=HC_EXCLUDE_BASENAME; p+=5; if(!*p || strchr(p,47) || strchr(p,92)) dief("file exclusions must name a basename"); }
    else if(strncmp(p,"path:",5)==0) { kind=HC_EXCLUDE_PATH; p+=5; if(!*p) dief("path exclusion must not be empty"); }
    else if(p[0]==46 && !strchr(p,47) && !strchr(p,92)) { kind=HC_EXCLUDE_EXTENSION; if(!p[1]) dief("invalid extension exclusion"); }
    else if(strchr(p,47) || strchr(p,92)) kind=HC_EXCLUDE_PATH; else kind=HC_EXCLUDE_BASENAME;
    if(ev->n==ev->cap) { ev->cap=ev->cap?ev->cap*2:8; ev->v=(exclude_rule *)xrealloc(ev->v,ev->cap*sizeof(*ev->v)); }
    r=&ev->v[ev->n++]; r->kind=kind; r->pattern=xstrdup(p);
    if(kind==HC_EXCLUDE_PATH) { for(i=0;r->pattern[i];i++) if((unsigned char)r->pattern[i]==92) r->pattern[i]=47; if(r->pattern[0]==46 && r->pattern[1]==47) memmove(r->pattern,r->pattern+2,strlen(r->pattern+2)+1); }
}
static int exclude_file_match(const char *logical,const char *root,const exclude_vec *ev) {
    const char *relative,*name,*dot; size_t n,i,j;
    if(!ev || !ev->n) return 0;
    n=strlen(root);
    if(strcmp(logical,root)==0) relative=logical; else if(strncmp(logical,root,n)==0 && logical[n]==47) relative=logical+n+1; else relative=logical;
    name=strrchr(relative,47); name=name?name+1:relative;
    for(i=0;i<ev->n;i++) { const exclude_rule *r=&ev->v[i];
        if(r->kind==HC_EXCLUDE_BASENAME && strcmp(name,r->pattern)==0) return 1;
        if(r->kind==HC_EXCLUDE_PATH && strcmp(relative,r->pattern)==0) return 1;
        if(r->kind==HC_EXCLUDE_EXTENSION) { dot=strrchr(name,46); if(!dot || dot==name || strlen(dot)!=strlen(r->pattern)) continue;
            for(j=0;dot[j] && r->pattern[j];j++) { unsigned char a=(unsigned char)dot[j],b=(unsigned char)r->pattern[j]; if(a>=65&&a<=90)a=(unsigned char)(a+32); if(b>=65&&b<=90)b=(unsigned char)(b+32); if(a!=b)break; }
            if(!dot[j] && !r->pattern[j]) return 1;
        }
    } return 0;
}

static void dir_hash_begin(sha256_ctx *c) {
    static const char tag[]="HASHCHECK-DIR-v1\0";
    sha256_init(c); sha256_update(c,tag,sizeof(tag)-1);
}
static void dir_hash_add(sha256_ctx *c, uint8_t type, const char *name, const uint8_t hash[32]) {
    uint8_t l[4]; size_t n=strlen(name);
    if(n>0xffffffffu) dief("path component too long");
    sha256_update(c,&type,1); le32enc(l,(uint32_t)n); sha256_update(c,l,4); sha256_update(c,name,n); sha256_update(c,hash,32);
}

#ifdef _WIN32

static int walk_native(const wchar_t *native_path, const char *logical_path, record_vec *rv, const char *root_logical, const exclude_vec *excludes,
                       uint8_t *type_out, uint8_t hash_out[32], uint64_t *size_out, unsigned depth) {
    DWORD attr=GetFileAttributesW(native_path);
    if(attr==INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr,L"hashcheck: cannot stat: %ls (Win32 error %lu)\n",native_path,(unsigned long)GetLastError()); return -1;
    }
    if(attr & FILE_ATTRIBUTE_REPARSE_POINT) {
        fwprintf(stderr,L"hashcheck: reparse point/symlink is not supported on Windows v1: %ls\n",native_path); return -1;
    }
    if(!(attr & FILE_ATTRIBUTE_DIRECTORY) && exclude_file_match(logical_path,root_logical,excludes)) return 1;
    if(attr & FILE_ATTRIBUTE_DIRECTORY) {
        wchar_t *pattern=native_join(native_path,L"*");
        WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(pattern,&fd); child_vec cv; size_t i; sha256_ctx dc;
        memset(&cv,0,sizeof(cv));
        free(pattern);
        if(h==INVALID_HANDLE_VALUE) {
            DWORD e=GetLastError();
            if(e!=ERROR_FILE_NOT_FOUND) { fwprintf(stderr,L"hashcheck: cannot enumerate: %ls (error %lu)\n",native_path,(unsigned long)e); return -1; }
        } else {
            do {
                char *u8;
                if(wcscmp(fd.cFileName,L".")==0 || wcscmp(fd.cFileName,L"..")==0) continue;
                u8=wide_to_utf8(fd.cFileName);
                child_push(&cv,fd.cFileName,u8); free(u8);
            } while(FindNextFileW(h,&fd));
            FindClose(h);
        }
        qsort(cv.v,cv.n,sizeof(cv.v[0]),child_cmp);
        dir_hash_begin(&dc);
        for(i=0;i<cv.n;i++) {
            wchar_t *np=native_join(native_path,cv.v[i].native_name);
            char *lp=logical_join(logical_path,cv.v[i].utf8_name);
            if(walk_native(np,lp,rv,root_logical,excludes,&cv.v[i].child_type,cv.v[i].child_hash,&cv.v[i].child_size,depth+1)<0){free(np);free(lp);child_free(&cv);return -1;}
            if(cv.v[i].child_type==0){free(np);free(lp);continue;}
            dir_hash_add(&dc,cv.v[i].child_type,cv.v[i].utf8_name,cv.v[i].child_hash);
            free(np); free(lp);
        }
        sha256_final(&dc,hash_out); records_push(rv,RT_DIR,0,hash_out,logical_path); child_free(&cv);
        *type_out=RT_DIR; *size_out=0; return 0;
    } else {
        if(hash_file_native(native_path,hash_out,size_out)!=0) { fwprintf(stderr,L"hashcheck: cannot read file: %ls\n",native_path); return -1; }
        records_push(rv,RT_FILE,*size_out,hash_out,logical_path); *type_out=RT_FILE; return 0;
    }
}

#else

static int hash_symlink_native(const char *path, uint8_t out[32], uint64_t *size_out) {
    struct stat st; char *buf; ssize_t n; sha256_ctx c; size_t cap;
    if(lstat(path,&st)!=0) return -1;
    cap=(st.st_size>0)?(size_t)st.st_size+1:PATH_MAX;
    if(cap<256) cap=256;
    buf=(char *)xmalloc(cap);
    n=readlink(path,buf,cap);
    if(n<0 || (size_t)n==cap){free(buf);return -1;}
    sha256_init(&c); sha256_update(&c,"HASHCHECK-LINK-v1\0",18); sha256_update(&c,buf,(size_t)n); sha256_final(&c,out); *size_out=(uint64_t)n; free(buf); return 0;
}

static int walk_native(const char *native_path, const char *logical_path, record_vec *rv, const char *root_logical, const exclude_vec *excludes,
                       uint8_t *type_out, uint8_t hash_out[32], uint64_t *size_out, unsigned depth) {
    struct stat st;
    if(lstat(native_path,&st)!=0){fprintf(stderr,"hashcheck: cannot stat '%s': %s\n",native_path,strerror(errno));return -1;}
    if((S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) && exclude_file_match(logical_path,root_logical,excludes)) return 1;
    if(S_ISREG(st.st_mode)) {
        if(hash_file_native(native_path,hash_out,size_out)!=0){fprintf(stderr,"hashcheck: cannot read '%s': %s\n",native_path,strerror(errno));return -1;}
        records_push(rv,RT_FILE,*size_out,hash_out,logical_path); *type_out=RT_FILE; return 0;
    }
    if(S_ISLNK(st.st_mode)) {
        if(hash_symlink_native(native_path,hash_out,size_out)!=0){fprintf(stderr,"hashcheck: cannot read symlink '%s'\n",native_path);return -1;}
        records_push(rv,RT_LINK,*size_out,hash_out,logical_path); *type_out=RT_LINK; return 0;
    }
    if(S_ISDIR(st.st_mode)) {
        DIR *d=opendir(native_path); struct dirent *de; child_vec cv; size_t i; sha256_ctx dc;
        memset(&cv,0,sizeof(cv));
        if(!d){fprintf(stderr,"hashcheck: cannot open directory '%s': %s\n",native_path,strerror(errno));return -1;}
        while((de=readdir(d))!=NULL){
            if(strcmp(de->d_name,".")==0||strcmp(de->d_name,"..")==0)continue;
            child_push(&cv,de->d_name,de->d_name);
        }
        closedir(d); qsort(cv.v,cv.n,sizeof(cv.v[0]),child_cmp); dir_hash_begin(&dc);
        for(i=0;i<cv.n;i++){
            char *np=native_join(native_path,cv.v[i].native_name); char *lp=logical_join(logical_path,cv.v[i].utf8_name);
            if(walk_native(np,lp,rv,root_logical,excludes,&cv.v[i].child_type,cv.v[i].child_hash,&cv.v[i].child_size,depth+1)<0){free(np);free(lp);child_free(&cv);return -1;}
            if(cv.v[i].child_type==0){free(np);free(lp);continue;}
            dir_hash_add(&dc,cv.v[i].child_type,cv.v[i].utf8_name,cv.v[i].child_hash); free(np);free(lp);
        }
        sha256_final(&dc,hash_out); records_push(rv,RT_DIR,0,hash_out,logical_path); child_free(&cv); *type_out=RT_DIR; *size_out=0; return 0;
    }
    fprintf(stderr,"hashcheck: unsupported special file: %s\n",native_path); return -1;
}

#endif

/* ---------------- manifest writer/reader ---------------- */

typedef struct {
    uint8_t *p;
    size_t n, cap;
} bytebuf;

static void bb_reserve(bytebuf *b, size_t extra) {
    size_t need;
    if (extra > SIZE_MAX - b->n) dief("buffer too large");
    need = b->n + extra;
    if (need <= b->cap) return;
    if (b->cap == 0) b->cap = 4096;
    while (b->cap < need) {
        size_t next = b->cap + b->cap/2 + 1024;
        if (next < b->cap || next < need) next = need;
        b->cap = next;
    }
    b->p = (uint8_t *)xrealloc(b->p, b->cap);
}

static void bb_put(bytebuf *b, const void *p, size_t n) {
    bb_reserve(b,n);
    memcpy(b->p+b->n,p,n);
    b->n += n;
}

static void bb_free(bytebuf *b) { free(b->p); memset(b,0,sizeof(*b)); }

/* ---- tiny raw-DEFLATE fixed-Huffman encoder/decoder ----
 * This is intentionally small: v2 only needs one final fixed-Huffman block.
 * The emitted payload is standards-compliant raw DEFLATE (RFC 1951).
 */

typedef struct { bytebuf out; uint64_t bits; unsigned nbits; int ok; } bitwriter;

static uint32_t revbits(uint32_t v, unsigned n) {
    uint32_t r=0;
    while(n--){r=(r<<1)|(v&1u);v>>=1;}
    return r;
}

static void bw_putbits(bitwriter *w, uint32_t v, unsigned n) {
    if(!w->ok || n>24) { w->ok=0; return; }
    w->bits |= ((uint64_t)v) << w->nbits;
    w->nbits += n;
    while(w->nbits >= 8) {
        uint8_t c=(uint8_t)w->bits;
        bb_put(&w->out,&c,1);
        w->bits >>= 8; w->nbits -= 8;
    }
}

static void bw_finish(bitwriter *w) {
    if(w->nbits){uint8_t c=(uint8_t)w->bits;bb_put(&w->out,&c,1);w->bits=0;w->nbits=0;}
}

static void def_fixed_symbol(bitwriter *w, unsigned sym) {
    uint32_t code; unsigned n;
    if(sym<=143){code=0x30u+sym;n=8;}
    else if(sym<=255){code=0x190u+(sym-144u);n=9;}
    else if(sym<=279){code=sym-256u;n=7;}
    else {code=0xc0u+(sym-280u);n=8;}
    bw_putbits(w,revbits(code,n),n);
}

static const uint16_t def_len_base[29]={
    3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,
    67,83,99,115,131,163,195,227,258
};
static const uint8_t def_len_extra[29]={
    0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
};
static const uint16_t def_dist_base[30]={
    1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
    1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
};
static const uint8_t def_dist_extra[30]={
    0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
};

static void def_emit_match(bitwriter *w, size_t len, size_t dist) {
    unsigned i;
    for(i=0;i<29;i++){
        size_t max=(size_t)def_len_base[i] + (def_len_extra[i] ? (((size_t)1u<<def_len_extra[i])-1u) : 0u);
        if(len<=max){
            def_fixed_symbol(w,257u+i);
            if(def_len_extra[i]) bw_putbits(w,(uint32_t)(len-def_len_base[i]),def_len_extra[i]);
            break;
        }
    }
    for(i=0;i<30;i++){
        size_t max=(size_t)def_dist_base[i] + (def_dist_extra[i] ? (((size_t)1u<<def_dist_extra[i])-1u) : 0u);
        if(dist<=max){
            bw_putbits(w,revbits(i,5),5);
            if(def_dist_extra[i]) bw_putbits(w,(uint32_t)(dist-def_dist_base[i]),def_dist_extra[i]);
            break;
        }
    }
}

#define DEF_WIN 32768u
#define DEF_HASH 65536u
#define DEF_CHAIN_LIMIT 96u

static unsigned def_hash3(const uint8_t *p) {
    return (unsigned)(((uint32_t)p[0]*251u*251u + (uint32_t)p[1]*251u + p[2]) & 0xffffu);
}

static void def_insert(const uint8_t *src, size_t n, size_t pos, size_t *head, size_t *prev, size_t *slotpos) {
    unsigned h; size_t slot;
    if(pos+2>=n) return;
    h=def_hash3(src+pos); slot=pos&(DEF_WIN-1u);
    prev[slot]=head[h]; slotpos[slot]=pos; head[h]=pos;
}

static int deflate_fixed_compress(const uint8_t *src, size_t n, bytebuf *dst) {
    size_t *head=NULL,*prev=NULL,*slotpos=NULL,pos=0,i; bitwriter w;
    memset(&w,0,sizeof(w)); w.ok=1;
    head=(size_t *)xmalloc(DEF_HASH*sizeof(size_t));
    prev=(size_t *)xmalloc(DEF_WIN*sizeof(size_t));
    slotpos=(size_t *)xmalloc(DEF_WIN*sizeof(size_t));
    for(i=0;i<DEF_HASH;i++) head[i]=SIZE_MAX;
    for(i=0;i<DEF_WIN;i++){prev[i]=SIZE_MAX;slotpos[i]=SIZE_MAX;}

    bw_putbits(&w,1,1); /* BFINAL */
    bw_putbits(&w,1,2); /* BTYPE=01, fixed Huffman */

    while(pos<n){
        size_t best_len=0,best_dist=0;
        if(pos+2<n){
            unsigned h=def_hash3(src+pos); size_t cand=head[h]; unsigned tries=0;
            while(cand!=SIZE_MAX && cand<pos && pos-cand<=DEF_WIN && tries++<DEF_CHAIN_LIMIT){
                size_t slot=cand&(DEF_WIN-1u), maxlen=n-pos, l=0, next;
                if(slotpos[slot]!=cand) break;
                if(maxlen>258) maxlen=258;
                if(src[cand]==src[pos] && src[cand+1]==src[pos+1] && src[cand+2]==src[pos+2]){
                    l=3; while(l<maxlen && src[cand+l]==src[pos+l]) l++;
                    if(l>best_len){best_len=l;best_dist=pos-cand;if(l==258)break;}
                }
                next=prev[slot]; if(next>=cand) break; cand=next;
            }
        }
        if(best_len>=3){
            def_emit_match(&w,best_len,best_dist);
            for(i=0;i<best_len;i++) def_insert(src,n,pos+i,head,prev,slotpos);
            pos += best_len;
        } else {
            def_fixed_symbol(&w,src[pos]);
            def_insert(src,n,pos,head,prev,slotpos);
            pos++;
        }
    }
    def_fixed_symbol(&w,256);
    bw_finish(&w);
    free(head);free(prev);free(slotpos);
    if(!w.ok){bb_free(&w.out);return -1;}
    *dst=w.out; return 0;
}

typedef struct { const uint8_t *p; size_t n,pos; uint64_t bits; unsigned nbits; int ok; } bitreader;

static uint32_t br_bits(bitreader *r,unsigned n){
    uint32_t v;
    while(r->nbits<n){
        if(r->pos>=r->n){r->ok=0;return 0;}
        r->bits |= ((uint64_t)r->p[r->pos++]) << r->nbits; r->nbits+=8;
    }
    v=(uint32_t)(r->bits & ((((uint64_t)1u)<<n)-1u));
    r->bits >>= n; r->nbits-=n; return v;
}

typedef struct { uint16_t sym; uint8_t nbits; } fixed_ent;

static void fixed_table_build(fixed_ent tab[512]) {
    unsigned sym; memset(tab,0,512*sizeof(*tab));
    for(sym=0;sym<=287;sym++){
        uint32_t code; unsigned n,j;
        if(sym<=143){code=0x30u+sym;n=8;}
        else if(sym<=255){code=0x190u+(sym-144u);n=9;}
        else if(sym<=279){code=sym-256u;n=7;}
        else {code=0xc0u+(sym-280u);n=8;}
        code=revbits(code,n);
        for(j=code;j<512u;j+=(1u<<n)){tab[j].sym=(uint16_t)sym;tab[j].nbits=(uint8_t)n;}
    }
}

static int br_fixed_symbol(bitreader *r,const fixed_ent tab[512],unsigned *sym){
    uint32_t idx; fixed_ent e;
    while(r->nbits<9 && r->pos<r->n){r->bits|=((uint64_t)r->p[r->pos++])<<r->nbits;r->nbits+=8;}
    if(r->nbits<7){r->ok=0;return -1;}
    idx=(uint32_t)(r->bits&511u); e=tab[idx];
    if(e.nbits==0 || e.nbits>r->nbits){r->ok=0;return -1;}
    r->bits>>=e.nbits;r->nbits-=e.nbits;*sym=e.sym;return 0;
}

static int deflate_fixed_decompress(const uint8_t *src,size_t n,uint8_t *out,size_t outn){
    bitreader r; fixed_ent tab[512]; size_t op=0; uint32_t bfinal,btype;
    memset(&r,0,sizeof(r));r.p=src;r.n=n;r.ok=1;fixed_table_build(tab);
    bfinal=br_bits(&r,1);btype=br_bits(&r,2);
    if(!r.ok || bfinal!=1 || btype!=1) return -1;
    for(;;){
        unsigned sym;
        if(br_fixed_symbol(&r,tab,&sym)!=0)return -1;
        if(sym<256){if(op>=outn)return -1;out[op++]=(uint8_t)sym;continue;}
        if(sym==256)break;
        if(sym<257 || sym>285)return -1;
        {
            unsigned li=sym-257, dsym; size_t len=def_len_base[li],dist,k; uint32_t dc;
            if(def_len_extra[li])len+=br_bits(&r,def_len_extra[li]);
            dc=br_bits(&r,5);if(!r.ok)return -1;dsym=revbits(dc,5);if(dsym>=30)return -1;
            dist=def_dist_base[dsym];if(def_dist_extra[dsym])dist+=br_bits(&r,def_dist_extra[dsym]);
            if(!r.ok || dist==0 || dist>op || len>outn-op)return -1;
            for(k=0;k<len;k++)out[op]=out[op-dist],op++;
        }
    }
    return op==outn?0:-1;
}

static int serialize_records(record_vec *rv, bytebuf *raw) {
    size_t i;
    qsort(rv->v,rv->n,sizeof(rv->v[0]),rec_path_cmp);
    for(i=0;i<rv->n;i++){
        uint8_t rh[48]={0}; size_t plen=strlen(rv->v[i].path);
        if(plen==0 || plen>0xffffffffu)return -1;
        rh[0]=rv->v[i].type;rh[1]=rv->v[i].flags;le32enc(rh+4,(uint32_t)plen);
        le64enc(rh+8,rv->v[i].size);memcpy(rh+16,rv->v[i].hash,32);
        bb_put(raw,rh,sizeof(rh));bb_put(raw,rv->v[i].path,plen);
    }
    return 0;
}

static int write_manifest_FILE_ex(FILE *f, record_vec *rv, uint32_t root_count, uint32_t extra_flags, uint64_t range_offset) {
    bytebuf raw,cmp; const uint8_t *stored; size_t stored_n; uint8_t comp=HC_COMP_NONE;
    memset(&raw,0,sizeof(raw)); memset(&cmp,0,sizeof(cmp));
    uint8_t h[HC_HEADER_SIZE]={0},dig[32]; sha256_ctx sc; uint32_t flags=HC_FLAGS_BASE|extra_flags;
    if(serialize_records(rv,&raw)!=0)return -1;
    if(raw.n && deflate_fixed_compress(raw.p,raw.n,&cmp)==0 && cmp.n<raw.n){
        stored=cmp.p;stored_n=cmp.n;comp=HC_COMP_DEFLATE_FIXED;flags|=HC_FLAG_COMPRESSED;
    }else{stored=raw.p;stored_n=raw.n;}
    memcpy(h,HC_MAGIC_V2,8);le16enc(h+8,HC_VERSION_V2);le16enc(h+10,HC_HEADER_SIZE);le32enc(h+12,flags);
    h[16]=local_os_id();h[17]=HC_HASH_SHA256;h[18]=HC_PATH_UTF8_SLASH;h[19]=comp;
    le64enc(h+20,(uint64_t)time(NULL));le64enc(h+28,(uint64_t)rv->n);le32enc(h+36,root_count);
    le64enc(h+40,(uint64_t)raw.n);le64enc(h+48,(uint64_t)stored_n);
    if(extra_flags&HC_FLAG_RANGE) le64enc(h+56,range_offset); else memcpy(h+56,"hc-v2",5);
    sha256_init(&sc);sha256_update(&sc,h,sizeof(h));sha256_update(&sc,stored,stored_n);sha256_final(&sc,dig);
    if(fwrite(h,1,sizeof(h),f)!=sizeof(h) || (stored_n && fwrite(stored,1,stored_n,f)!=stored_n) ||
       fwrite(HC_ENDMAG_V2,1,8,f)!=8 || fwrite(dig,1,32,f)!=32){bb_free(&raw);bb_free(&cmp);return -1;}
    bb_free(&raw);bb_free(&cmp);return 0;
}

static int write_manifest_utf8_ex(const char *out_path, record_vec *rv, uint32_t root_count, uint32_t extra_flags, uint64_t range_offset) {
    FILE *f=fopen(out_path,"wb");int r;
    if(!f){fprintf(stderr,"hashcheck: cannot create '%s': %s\n",out_path,strerror(errno));return -1;}
    r=write_manifest_FILE_ex(f,rv,root_count,extra_flags,range_offset);
    if(fclose(f)!=0)r=-1;
    if(r!=0)fprintf(stderr,"hashcheck: write error '%s'\n",out_path);
    return r;
}
static int write_manifest_utf8(const char *out_path, record_vec *rv, uint32_t root_count) {
    return write_manifest_utf8_ex(out_path,rv,root_count,0,0);
}

#ifdef _WIN32
static int write_manifest_native_ex(const wchar_t *out_path, record_vec *rv, uint32_t root_count, uint32_t extra_flags, uint64_t range_offset) {
    FILE *f=_wfopen(out_path,L"wb");int r;
    if(!f){fwprintf(stderr,L"hashcheck: cannot create '%ls'\n",out_path);return -1;}
    r=write_manifest_FILE_ex(f,rv,root_count,extra_flags,range_offset);if(fclose(f)!=0)r=-1;return r;
}
static int write_manifest_native(const wchar_t *out_path, record_vec *rv, uint32_t root_count) {
    return write_manifest_native_ex(out_path,rv,root_count,0,0);
}
#endif

typedef struct {
    uint16_t version;
    uint32_t flags;
    uint8_t os_id, hash_alg, path_fmt, compression;
    uint64_t created, record_count, raw_payload_size, stored_payload_size, range_offset;
    uint32_t root_count;
    record_vec records;
    int checksum_ok;
} manifest;

static int parse_record_payload(const uint8_t *p,size_t n,manifest *m){
    uint64_t i;size_t off=0;
    if(m->record_count>(uint64_t)(SIZE_MAX/sizeof(record)))return -4;
    for(i=0;i<m->record_count;i++){
        const uint8_t *rh;uint32_t plen;char *path;uint8_t type;uint64_t sz;
        if(n-off<48) return -5;
        rh=p+off; off+=48; type=rh[0]; plen=le32dec(rh+4); sz=le64dec(rh+8);
        if(plen==0||plen>HC_MAX_PATH_BYTES||n-off<plen)return -6;
        path=(char *)xmalloc((size_t)plen+1);memcpy(path,p+off,plen);path[plen]=0;off+=plen;
        records_push(&m->records,type,sz,rh+16,path);m->records.v[m->records.n-1].flags=rh[1];free(path);
    }
    return off==n?0:-7;
}

static int read_manifest_v1(FILE *f,const uint8_t h[HC_HEADER_SIZE],manifest *m){
    uint8_t stored[32],calc[32],endm[8];sha256_ctx sc;uint64_t i;
    m->version=HC_VERSION_V1;m->flags=le32dec(h+12);m->os_id=h[16];m->hash_alg=h[17];m->path_fmt=h[18];m->compression=HC_COMP_NONE;
    m->created=le64dec(h+20);m->record_count=le64dec(h+28);m->root_count=le32dec(h+36);sha256_init(&sc);sha256_update(&sc,h,HC_HEADER_SIZE);
    for(i=0;i<m->record_count;i++){
        uint8_t rh[48];uint32_t plen;char *path;uint8_t type;uint64_t sz;
        if(fread(rh,1,48,f)!=48) return -5;
        sha256_update(&sc,rh,48); type=rh[0]; plen=le32dec(rh+4); sz=le64dec(rh+8);
        if(plen==0||plen>HC_MAX_PATH_BYTES) return -6;
        path=(char *)xmalloc((size_t)plen+1);
        if(fread(path,1,plen,f)!=plen){free(path);return -7;}sha256_update(&sc,path,plen);path[plen]=0;
        records_push(&m->records,type,sz,rh+16,path);m->records.v[m->records.n-1].flags=rh[1];free(path);
    }
    if(fread(endm,1,8,f)!=8||fread(stored,1,32,f)!=32) return -8;
    if(memcmp(endm,HC_ENDMAG_V1,8)!=0) return -9;
    sha256_final(&sc,calc);m->checksum_ok=(memcmp(calc,stored,32)==0);m->raw_payload_size=0;m->stored_payload_size=0;m->range_offset=0;
    qsort(m->records.v,m->records.n,sizeof(m->records.v[0]),rec_path_cmp);return 0;
}

static int read_manifest_v2(FILE *f,const uint8_t h[HC_HEADER_SIZE],manifest *m){
    uint64_t raw64=le64dec(h+40),stored64=le64dec(h+48);size_t raw_n,stored_n;uint8_t *stored=NULL,*raw=NULL,endm[8],want[32],got[32];sha256_ctx sc;int pr;
    m->version=HC_VERSION_V2;m->flags=le32dec(h+12);m->os_id=h[16];m->hash_alg=h[17];m->path_fmt=h[18];m->compression=h[19];
    m->created=le64dec(h+20);m->record_count=le64dec(h+28);m->root_count=le32dec(h+36);m->raw_payload_size=raw64;m->stored_payload_size=stored64;m->range_offset=(m->flags&HC_FLAG_RANGE)?le64dec(h+56):0;
    if(raw64>SIZE_MAX||stored64>SIZE_MAX) return -10;
    raw_n=(size_t)raw64; stored_n=(size_t)stored64;
    stored=(uint8_t *)xmalloc(stored_n?stored_n:1);if(stored_n&&fread(stored,1,stored_n,f)!=stored_n){free(stored);return -11;}
    if(fread(endm,1,8,f)!=8||fread(want,1,32,f)!=32){free(stored);return -12;}if(memcmp(endm,HC_ENDMAG_V2,8)!=0){free(stored);return -13;}
    sha256_init(&sc);sha256_update(&sc,h,HC_HEADER_SIZE);sha256_update(&sc,stored,stored_n);sha256_final(&sc,got);m->checksum_ok=(memcmp(want,got,32)==0);
    raw=(uint8_t *)xmalloc(raw_n?raw_n:1);
    if(m->compression==HC_COMP_NONE){if(raw_n!=stored_n){free(stored);free(raw);return -14;}if(raw_n)memcpy(raw,stored,raw_n);}
    else if(m->compression==HC_COMP_DEFLATE_FIXED){if(deflate_fixed_decompress(stored,stored_n,raw,raw_n)!=0){free(stored);free(raw);return -15;}}
    else {free(stored);free(raw);return -16;}
    pr=parse_record_payload(raw,raw_n,m);free(stored);free(raw);if(pr!=0)return pr;
    qsort(m->records.v,m->records.n,sizeof(m->records.v[0]),rec_path_cmp);return 0;
}

static int read_manifest_FILE(FILE *f, manifest *m) {
    uint8_t h[HC_HEADER_SIZE];uint16_t ver,hs;int r;memset(m,0,sizeof(*m));
    if(fread(h,1,sizeof(h),f)!=sizeof(h)) return -1;
    ver=le16dec(h+8); hs=le16dec(h+10);
    if(hs!=HC_HEADER_SIZE) return -3;
    if(memcmp(h,HC_MAGIC_V1,8)==0&&ver==HC_VERSION_V1)r=read_manifest_v1(f,h,m);
    else if(memcmp(h,HC_MAGIC_V2,8)==0&&ver==HC_VERSION_V2)r=read_manifest_v2(f,h,m);
    else r=-2;
    if(r!=0){records_free(&m->records);memset(m,0,sizeof(*m));}return r;
}

#ifdef _WIN32
static int read_manifest_native(const wchar_t *path, manifest *m) { FILE *f=_wfopen(path,L"rb"); int r; if(!f)return -1;r=read_manifest_FILE(f,m);fclose(f);return r; }
#else
static int read_manifest_native(const char *path, manifest *m) { FILE *f=fopen(path,"rb"); int r; if(!f)return -1;r=read_manifest_FILE(f,m);fclose(f);return r; }
#endif

static void manifest_free(manifest *m){records_free(&m->records);memset(m,0,sizeof(*m));}

static void print_manifest(const manifest *m) {
    size_t i; char hh[65]; char tbuf[64]={0}; time_t tt=(time_t)m->created; struct tm *tmv=localtime(&tt);
    if(tmv) strftime(tbuf,sizeof(tbuf),"%Y-%m-%d %H:%M:%S",tmv);
    printf("hashcheck binary manifest\n");
    printf("  version      : %u\n",(unsigned)m->version);
    printf("  source OS    : %s\n",os_name(m->os_id));
    printf("  flags        : 0x%08" PRIx32 "\n",m->flags);
    printf("  algorithm    : SHA-256\n");
    printf("  path format  : UTF-8, '/' separated, relative logical roots\n");
    if(m->version>=2){
        const char *cn=m->compression==HC_COMP_DEFLATE_FIXED?"DEFLATE (fixed Huffman)":"none";
        printf("  compression  : %s\n",cn);
        printf("  payload      : %" PRIu64 " -> %" PRIu64 " bytes",m->raw_payload_size,m->stored_payload_size);
        if(m->raw_payload_size)printf(" (%.1f%%)",100.0*(double)m->stored_payload_size/(double)m->raw_payload_size);
        putchar('\n');
    }
    printf("  created      : %s\n",tbuf[0]?tbuf:"unknown");
    printf("  roots        : %u\n",m->root_count);
    printf("  records      : %" PRIu64 "\n",m->record_count);
    if(m->flags&HC_FLAG_RANGE) {
        uint64_t total=0;
        for(i=0;i<m->records.n;i++) total+=m->records.v[i].size;
        printf("  range offset : %" PRIu64 " bytes\n",m->range_offset);
        printf("  range length : %" PRIu64 " bytes\n",total);
    }
    if((m->flags&HC_FLAG_BLOCKS) && m->records.n) {
        printf("  block size   : %" PRIu64 " bytes",m->records.v[0].size);
        if(m->records.n>1 && m->records.v[m->records.n-1].size!=m->records.v[0].size)
            printf(" (last=%" PRIu64 ")",m->records.v[m->records.n-1].size);
        putchar('\n');
    }
    printf("  manifest SHA : %s\n\n",m->checksum_ok?"OK":"FAILED");
    for(i=0;i<m->records.n;i++){
        hex32(m->records.v[i].hash,hh);
        if(m->records.v[i].type==RT_FILE) {
            const char *tn=((m->flags&HC_FLAG_RANGE) && m->records.n==1)?"RANGE ":"FILE  ";
            printf("%s  %s  %12" PRIu64 "  %s\n",tn,hh,m->records.v[i].size,m->records.v[i].path);
        } else if(m->records.v[i].type==RT_BLOCK) {
            printf("BLOCK  %s  %12" PRIu64 "  %s\n",hh,m->records.v[i].size,m->records.v[i].path);
        } else printf("%s  %s  %12s  %s\n",type_name(m->records.v[i].type),hh,"-",m->records.v[i].path);
    }
}

static const char *single_root_name(const manifest *m) {
    size_t i;
    const char *best=NULL;
    if(m->root_count!=1 || m->records.n==0) return NULL;
    for(i=0;i<m->records.n;i++) {
        const char *p=m->records.v[i].path;
        if(strchr(p,'/')==NULL) {
            if(best==NULL || strlen(p)<strlen(best)) best=p;
        }
    }
    return best;
}

static const char *compare_key(const manifest *m, const char *root, const char *path) {
    size_t n;
    (void)m;
    if(!root) return path;
    n=strlen(root);
    if(strcmp(path,root)==0) return ".";
    if(strncmp(path,root,n)==0 && path[n]=='/') return path+n+1;
    return path;
}

static int compare_manifest(const manifest *a, const manifest *b) {
    size_t i=0,j=0; uint64_t same=0,changed=0,onlya=0,onlyb=0,typechg=0; int mismatch=0;
    const char *aroot=single_root_name(a), *broot=single_root_name(b);
    printf("A: %s, %" PRIu64 " records, manifest=%s",os_name(a->os_id),a->record_count,a->checksum_ok?"OK":"BAD");
    if(aroot) printf(", root=%s",aroot);
    putchar('\n');
    printf("B: %s, %" PRIu64 " records, manifest=%s",os_name(b->os_id),b->record_count,b->checksum_ok?"OK":"BAD");
    if(broot) printf(", root=%s",broot);
    printf("\n\n");
    if(!a->checksum_ok || !b->checksum_ok) { printf("ERROR: one or both manifest files are corrupted.\n"); return 2; }
    while(i<a->records.n || j<b->records.n) {
        int c; const char *ka=NULL,*kb=NULL;
        if(i<a->records.n) ka=compare_key(a,aroot,a->records.v[i].path);
        if(j<b->records.n) kb=compare_key(b,broot,b->records.v[j].path);
        if(i==a->records.n) c=1; else if(j==b->records.n) c=-1; else c=strcmp(ka,kb);
        if(c<0){printf("ONLY-A   %s\n",ka);onlya++;mismatch=1;i++;}
        else if(c>0){printf("ONLY-B   %s\n",kb);onlyb++;mismatch=1;j++;}
        else {
            const record *ra=&a->records.v[i], *rb=&b->records.v[j];
            if(ra->type!=rb->type){printf("TYPE      %s  (%s -> %s)\n",ka,type_name(ra->type),type_name(rb->type));typechg++;mismatch=1;}
            else if(memcmp(ra->hash,rb->hash,32)!=0 || ((ra->type==RT_FILE || ra->type==RT_BLOCK) && ra->size!=rb->size)){
                char ha[65],hb[65];hex32(ra->hash,ha);hex32(rb->hash,hb);
                printf("CHANGED   %s\n          A %s  size=%" PRIu64 "\n          B %s  size=%" PRIu64 "\n",ka,ha,ra->size,hb,rb->size);changed++;mismatch=1;
            } else same++;
            i++;j++;
        }
    }
    printf("\nSummary: SAME=%" PRIu64 " CHANGED=%" PRIu64 " TYPE=%" PRIu64 " ONLY-A=%" PRIu64 " ONLY-B=%" PRIu64 "\n",same,changed,typechg,onlya,onlyb);
    printf("Result : %s\n",mismatch?"DIFFERENT":"IDENTICAL");
    return mismatch?1:0;
}


/* ---------------- DRG -> 1-second block-hash shell generator ---------------- */

#define HC_MKSH_DATA_RATE UINT64_C(256000000)

static int hc_is_leap_year(int y) {
    return (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
}

static int hc_parse_ndigits(const char *s, size_t n, int *out) {
    size_t i; int v=0;
    for(i=0;i<n;i++) {
        if(s[i]<'0' || s[i]>'9') return -1;
        v=v*10+(s[i]-'0');
    }
    *out=v; return 0;
}

/* Accept YYDOYhhmmss (11 digits) or YYYYDOYhhmmss (13 digits). */
static int hc_parse_ydoyhms(const char *s, size_t n, int64_t *sec_out, char canonical13[14]) {
    int year,doy,hh,mm,ss,y;
    int64_t days=0;
    if(n==11) {
        int yy;
        if(hc_parse_ndigits(s,2,&yy)!=0 || hc_parse_ndigits(s+2,3,&doy)!=0 ||
           hc_parse_ndigits(s+5,2,&hh)!=0 || hc_parse_ndigits(s+7,2,&mm)!=0 ||
           hc_parse_ndigits(s+9,2,&ss)!=0) return -1;
        year=2000+yy;
    } else if(n==13) {
        if(hc_parse_ndigits(s,4,&year)!=0 || hc_parse_ndigits(s+4,3,&doy)!=0 ||
           hc_parse_ndigits(s+7,2,&hh)!=0 || hc_parse_ndigits(s+9,2,&mm)!=0 ||
           hc_parse_ndigits(s+11,2,&ss)!=0) return -1;
    } else return -1;
    if(year<1970 || year>9999 || doy<1 || doy>(hc_is_leap_year(year)?366:365) ||
       hh<0 || hh>23 || mm<0 || mm>59 || ss<0 || ss>60) return -1;
    for(y=1970;y<year;y++) days += hc_is_leap_year(y)?366:365;
    days += (int64_t)(doy-1);
    *sec_out = ((days*24 + hh)*60 + mm)*60 + ss;
    snprintf(canonical13,14,"%04d%03d%02d%02d%02d",year,doy,hh,mm,ss);
    return 0;
}

static int hc_contains_ci(const char *hay, const char *needle) {
    size_t nh=strlen(hay), nn=strlen(needle),i,j;
    if(nn==0) return 1;
    if(nh<nn) return 0;
    for(i=0;i+nn<=nh;i++) {
        for(j=0;j<nn;j++) {
            unsigned char a=(unsigned char)hay[i+j], b=(unsigned char)needle[j];
            if(a>='a'&&a<='z') a=(unsigned char)(a-'a'+'A');
            if(b>='a'&&b<='z') b=(unsigned char)(b-'a'+'A');
            if(a!=b) break;
        }
        if(j==nn) return 1;
    }
    return 0;
}

static int hc_extract_time_from_line(const char *line, int64_t *sec_out, char canonical13[14]) {
    size_t i=0,n=strlen(line);
    while(i<n) {
        size_t j;
        while(i<n && (line[i]<'0'||line[i]>'9')) i++;
        if(i>=n) break;
        j=i;
        while(j<n && line[j]>='0'&&line[j]<='9') j++;
        if((j-i==13 || j-i==11) && hc_parse_ydoyhms(line+i,j-i,sec_out,canonical13)==0) return 0;
        i=j;
    }
    return -1;
}

static int hc_find_record_start_FILE(FILE *f, int64_t *sec_out, char canonical13[14]) {
    char line[8192];
    while(fgets(line,sizeof(line),f)) {
        if(hc_contains_ci(line,"REQRECSTART") || hc_contains_ci(line,"RECSTART") ||
           (hc_contains_ci(line,"RECORD") && hc_contains_ci(line,"START"))) {
            if(hc_extract_time_from_line(line,sec_out,canonical13)==0) return 0;
        }
    }
    return -1;
}

static int hc_duration_to_bytes(const char *s, uint64_t *bytes_out) {
    char *end=NULL; double d, b;
    errno=0; d=strtod(s,&end);
    if(errno!=0 || end==s || *end!='\0' || d<=0.0) return -1;
    b=d*(double)HC_MKSH_DATA_RATE;
    if(b>(double)UINT64_MAX) return -1;
    *bytes_out=(uint64_t)(b+0.5);
    return 0;
}

static char *hc_basename_stem_dup(const char *path) {
    const char *p=path,*base=path,*dot; size_t n; char *r;
    for(;*p;p++) if(*p=='/' || *p=='\\') base=p+1;
    dot=strrchr(base,'.');
    n=(dot && dot!=base)?(size_t)(dot-base):strlen(base);
    r=(char *)xmalloc(n+1); memcpy(r,base,n); r[n]='\0'; return r;
}

static char *hc_default_mksh_out_u8(const char *drg_path) {
    char *stem=hc_basename_stem_dup(drg_path); size_t n=strlen(stem); char *r=(char *)xmalloc(n+15);
    strcpy(r,"hashcheck_"); strcat(r,stem); strcat(r,".sh"); free(stem); return r;
}

static int hc_write_mksh_FILE(FILE *out, FILE *drg, const char *drg_name, const char *log_name,
                              int64_t rec_sec, const char rec13[14]) {
    char line[8192]; int in_sked=0, scan_count=0;
    fprintf(out,"#!/bin/sh\nset -eu\n\n");
    fprintf(out,"# Generated by hashcheck --mksh\n# DRG: %s\n# LOG: %s\n",drg_name,log_name);
    fprintf(out,"# Recording start: %s\n# Data rate: %" PRIu64 " bytes/s\n\n",rec13,(uint64_t)HC_MKSH_DATA_RATE);
    fputs("if [ \"$#\" -lt 1 ] || [ \"$#\" -gt 2 ]; then\n"
          "    echo \"Usage: $0 DATAFILE [PREFIX]\" >&2\n"
          "    echo \"  DATAFILE : original recorded file\" >&2\n"
          "    echo \"  PREFIX   : output hash prefix (default: DATAFILE basename)\" >&2\n"
          "    exit 2\n"
          "fi\n\n"
          "INPUT=$1\n"
          "PREFIX=${2:-}\n"
          "if [ -z \"$PREFIX\" ]; then\n"
          "    base=${INPUT##*/}\n"
          "    PREFIX=${base%.*}\n"
          "fi\n"
          "HASHCHECK=${HASHCHECK:-hashcheck}\n"
          "command -v \"$HASHCHECK\" >/dev/null 2>&1 || { echo \"hashcheck not found: $HASHCHECK\" >&2; exit 2; }\n"
          "[ -f \"$INPUT\" ] || { echo \"input file not found: $INPUT\" >&2; exit 2; }\n\n",out);

    rewind(drg);
    while(fgets(line,sizeof(line),drg)) {
        char work[8192], *tok[32], *p; int nt=0; int64_t scan_sec,delta;
        char start13[14]; uint64_t offset,length;
        if(!in_sked) {
            p=line; while(*p==' '||*p=='\t') p++;
            if(strncmp(p,"$SKED",5)==0) in_sked=1;
            continue;
        }
        p=line; while(*p==' '||*p=='\t') p++;
        if(*p=='$') break;
        if(*p=='\0'||*p=='\n'||*p=='\r'||*p=='*') continue;
        strncpy(work,p,sizeof(work)-1); work[sizeof(work)-1]='\0';
        p=strtok(work," \t\r\n");
        while(p && nt<(int)(sizeof(tok)/sizeof(tok[0]))) { tok[nt++]=p; p=strtok(NULL," \t\r\n"); }
        if(nt<6) continue;
        if(hc_parse_ydoyhms(tok[4],strlen(tok[4]),&scan_sec,start13)!=0) {
            fprintf(stderr,"hashcheck: invalid DRG START '%s'\n",tok[4]); return -1;
        }
        if(hc_duration_to_bytes(tok[5],&length)!=0) {
            fprintf(stderr,"hashcheck: invalid DRG DUR '%s'\n",tok[5]); return -1;
        }
        delta=scan_sec-rec_sec;
        if(delta<0) {
            fprintf(stderr,"hashcheck: DRG scan %s starts before recording start %s\n",start13,rec13); return -1;
        }
        if((uint64_t)delta > UINT64_MAX/HC_MKSH_DATA_RATE) {
            fprintf(stderr,"hashcheck: DRG offset overflow at %s\n",start13); return -1;
        }
        offset=(uint64_t)delta*HC_MKSH_DATA_RATE;
        scan_count++;
        fprintf(out,"# scan %d  target=%s  start=%s  dur=%s s\n",scan_count,tok[0],start13,tok[5]);
        fprintf(out,"\"$HASHCHECK\" -o \"${PREFIX}_%s.hash\" --offset %" PRIu64 " --length %" PRIu64 " --block %" PRIu64 " \"$INPUT\"\n\n",
                start13,offset,length,(uint64_t)HC_MKSH_DATA_RATE);
    }
    if(scan_count==0) {
        fprintf(stderr,"hashcheck: no scans found in $SKED section of %s\n",drg_name); return -1;
    }
    fprintf(out,"echo \"hashcheck: completed %d scan ranges (1-second SHA-256 blocks)\"\n",scan_count);
    return scan_count;
}

#ifndef _WIN32
static int hc_generate_mksh_u8(const char *out_path, const char *drg_path, const char *log_path) {
    FILE *df=NULL,*lf=NULL,*of=NULL; int64_t rec_sec; char rec13[14]; int n;
    df=fopen(drg_path,"rb"); if(!df){fprintf(stderr,"hashcheck: cannot open DRG '%s': %s\n",drg_path,strerror(errno));return 2;}
    lf=fopen(log_path,"rb"); if(!lf){fprintf(stderr,"hashcheck: cannot open log '%s': %s\n",log_path,strerror(errno));fclose(df);return 2;}
    if(hc_find_record_start_FILE(lf,&rec_sec,rec13)!=0) {
        fprintf(stderr,"hashcheck: recording start not found in log '%s' (REQRECSTART/RECSTART required)\n",log_path);
        fclose(lf);fclose(df);return 2;
    }
    fclose(lf);
    of=fopen(out_path,"wb"); if(!of){fprintf(stderr,"hashcheck: cannot create '%s': %s\n",out_path,strerror(errno));fclose(df);return 2;}
    n=hc_write_mksh_FILE(of,df,drg_path,log_path,rec_sec,rec13);
    if(fclose(of)!=0 && n>=0) n=-1;
    fclose(df);
    if(n<0){remove(out_path);return 2;}
    chmod(out_path,0755);
    printf("Wrote %s : %d scan ranges (1-second blocks), recording start=%s, data rate=%" PRIu64 " bytes/s\n",
           out_path,n,rec13,(uint64_t)HC_MKSH_DATA_RATE);
    return 0;
}
#else
static wchar_t *hc_default_mksh_out_w(const wchar_t *drg_path) {
    wchar_t *bn=native_basename_dup(drg_path), *dot=wcsrchr(bn,L'.'), *r; size_t n;
    if(dot && dot!=bn) *dot=0; n=wcslen(bn);
    r=(wchar_t *)xmalloc((n+15)*sizeof(wchar_t)); wcscpy(r,L"hashcheck_"); wcscat(r,bn); wcscat(r,L".sh"); free(bn); return r;
}
static int hc_generate_mksh_w(const wchar_t *out_path, const wchar_t *drg_path, const wchar_t *log_path) {
    FILE *df=NULL,*lf=NULL,*of=NULL; int64_t rec_sec; char rec13[14]; int n; char *du,*lu,*ou;
    df=_wfopen(drg_path,L"rb"); if(!df){fwprintf(stderr,L"hashcheck: cannot open DRG '%ls'\n",drg_path);return 2;}
    lf=_wfopen(log_path,L"rb"); if(!lf){fwprintf(stderr,L"hashcheck: cannot open log '%ls'\n",log_path);fclose(df);return 2;}
    if(hc_find_record_start_FILE(lf,&rec_sec,rec13)!=0) {fwprintf(stderr,L"hashcheck: recording start not found in log '%ls'\n",log_path);fclose(lf);fclose(df);return 2;}
    fclose(lf); of=_wfopen(out_path,L"wb"); if(!of){fwprintf(stderr,L"hashcheck: cannot create '%ls'\n",out_path);fclose(df);return 2;}
    du=wide_to_utf8(drg_path);lu=wide_to_utf8(log_path);ou=wide_to_utf8(out_path);
    n=hc_write_mksh_FILE(of,df,du,lu,rec_sec,rec13);
    if(fclose(of)!=0 && n>=0) n=-1; fclose(df);
    if(n<0){_wremove(out_path);free(du);free(lu);free(ou);return 2;}
    printf("Wrote %s : %d scan ranges (1-second blocks), recording start=%s, data rate=%" PRIu64 " bytes/s\n",ou,n,rec13,(uint64_t)HC_MKSH_DATA_RATE);
    free(du);free(lu);free(ou);return 0;
}
#endif

/* ---------------- command-line ---------------- */

static void usage_to(FILE *fp) {
    fputs("hashcheck v2.9 - cross-platform SHA-256 file/tree/range/block manifest\n"
         "\n"
         "Usage:\n"
         "  hashcheck\n"
         "      Show this help; no hashing is performed.\n"
         "\n"
         "  hashcheck PATH\n"
         "      Hash one whole file or directory and create <basename>.hash.\n"
         "\n"
         "  hashcheck -o OUTPUT.hash PATH [PATH ...]\n"
         "      Hash one or more whole files/directories into OUTPUT.hash.\n"
         "\n"
         "  hashcheck [ -o OUTPUT.hash ] --offset OFFSET --length LENGTH FILE\n"
         "      Hash only FILE[OFFSET, OFFSET+LENGTH). OFFSET/LENGTH are bytes.\n"
         "\n"
         "  hashcheck [ -o OUTPUT.hash ] [--offset OFFSET --length LENGTH] --block BYTES FILE\n"
         "      Hash the selected data as consecutive independent BYTES-sized blocks.\n"
         "\n"
         "  hashcheck --mksh SCHEDULE.DRG --log RECORD.log [ -o OUTPUT.sh ]\n"
         "      Generate one block-hash command per $SKED scan (1 second = 256000000 bytes).\n"
         "      Recording start is REQUIRED from --log; fixed data rate is 256000000 bytes/s.\n"
         "\n"
         "  hashcheck MANIFEST.hash\n"
         "      Inspect a manifest.\n"
         "\n"
         "  hashcheck A.hash B.hash\n"
         "  hashcheck -c A.hash B.hash\n"
         "      Compare two manifests.\n"
         "\n"
         "Options:\n"
         "  -o FILE             Output manifest; with --mksh, output shell script.\n"
         "  -c, --compare       Explicit manifest comparison mode.\n"
         "  --offset N          Start byte offset for range hashing; requires --length.\n"
         "  --length N          Number of bytes to hash; requires --offset.\n"
         "  --block N           Split selected file/range into consecutive N-byte SHA-256 blocks.\n"
         "  --exclude RULE     Exclude extension (.tmp), basename (name.tmp), or root-relative path (sub/name.tmp); repeatable.\n"
         "                      Use file:.gitignore for a dotfile or ext:.gz for an explicit extension.\n"
         "  --mksh DRG          Generate 1-second block-hash shell commands from DRG $SKED.\n"
         "  --log LOG           Recording log for --mksh; REQRECSTART/RECSTART is mandatory.\n"
         "  -h, --help          Show this help.\n"
         "\n"
         "Generated --mksh script:\n"
         "  ./hashcheck_<DRG>.sh DATAFILE [PREFIX]\n"
         "      DATAFILE is the original recorded file. PREFIX defaults to its basename.\n"
         "      Example PREFIX=YAMAGU32 creates YAMAGU32_YYYYDOYhhmmss.hash.\n"
         "\n"
         "Rules:\n"
         "  * regular files, ranges, and blocks are hashed as raw bytes with SHA-256\n"
         "  * --mksh uses --block 256000000, producing one independent hash per second\n"
         "  * directories get their own SHA-256 from sorted child name/type/hash\n"
         "  * timestamps, permissions, uid/gid and source absolute path are NOT compared\n"
         "  * manifest paths are UTF-8 with '/' separators\n"
         "  * RANGE manifests compare with received FILE manifests; BLOCK manifests compare block-by-block\n"
         "  * v2 record payload is compressed internally; v1 manifests remain readable\n"
         "  * exit code: 0 identical/success, 1 different, 2 error\n\n", fp);
}

static void usage(void) { usage_to(stdout); }

static int parse_u64_dec(const char *s, uint64_t *out) {
    uint64_t v=0;
    const unsigned char *p=(const unsigned char *)s;
    if(!s || !*s) return -1;
    for(;*p;p++) {
        unsigned d;
        if(*p<'0' || *p>'9') return -1;
        d=(unsigned)(*p-'0');
        if(v>(UINT64_MAX-d)/10u) return -1;
        v=v*10u+d;
    }
    *out=v;
    return 0;
}

#ifdef _WIN32
static int parse_u64_dec_w(const wchar_t *s, uint64_t *out) {
    uint64_t v=0; const wchar_t *p=s;
    if(!s || !*s) return -1;
    for(;*p;p++) {
        unsigned d;
        if(*p<L'0' || *p>L'9') return -1;
        d=(unsigned)(*p-L'0');
        if(v>(UINT64_MAX-d)/10u) return -1;
        v=v*10u+d;
    }
    *out=v; return 0;
}
#endif

#ifdef _WIN32

static wchar_t *default_out_for_one(const wchar_t *path) {
    wchar_t *bn=native_basename_dup(path); size_t n=wcslen(bn); wchar_t *o=(wchar_t *)xmalloc((n+6)*sizeof(wchar_t));
    memcpy(o,bn,n*sizeof(wchar_t)); memcpy(o+n,L".hash",6*sizeof(wchar_t)); free(bn); return o;
}


static wchar_t *default_out_for_range_w(const wchar_t *path, uint64_t offset, uint64_t length) {
    wchar_t *bn=native_basename_dup(path); size_t n=wcslen(bn); wchar_t suffix[96]; wchar_t *o;
    _snwprintf(suffix,sizeof(suffix)/sizeof(suffix[0]),L".%llu+%llu.hash",(unsigned long long)offset,(unsigned long long)length);
    suffix[(sizeof(suffix)/sizeof(suffix[0]))-1]=0;
    o=(wchar_t *)xmalloc((n+wcslen(suffix)+1)*sizeof(wchar_t));
    wcscpy(o,bn);wcscat(o,suffix);free(bn);return o;
}

static int generate_range_w(const wchar_t *out, const wchar_t *path, uint64_t offset, uint64_t length) {
    record_vec rv; uint8_t h[32]; wchar_t *wbn; char *root,*uo; int r; DWORD attr;
    memset(&rv,0,sizeof(rv));
    attr=GetFileAttributesW(path);
    if(attr==INVALID_FILE_ATTRIBUTES || (attr&FILE_ATTRIBUTE_DIRECTORY) || (attr&FILE_ATTRIBUTE_REPARSE_POINT)) {
        fwprintf(stderr,L"hashcheck: range input must be a regular file: %ls\n",path); return 2;
    }
    r=hash_file_range_native(path,offset,length,h);
    if(r==-2){fwprintf(stderr,L"hashcheck: requested range is outside file: %ls\n",path);return 2;}
    if(r!=0){fwprintf(stderr,L"hashcheck: cannot read range: %ls\n",path);return 2;}
    wbn=native_basename_dup(path);root=wide_to_utf8(wbn);free(wbn);
    records_push(&rv,RT_FILE,length,h,root);
    if(write_manifest_native_ex(out,&rv,1,HC_FLAG_RANGE,offset)!=0){free(root);records_free(&rv);return 2;}
    {char digest[65];hex32(h,digest);printf("SHA-256  %s  %s (range offset=%" PRIu64 " length=%" PRIu64 ")\n",digest,root,offset,length);}
    uo=wide_to_utf8(out);printf("Wrote %s : range offset=%" PRIu64 " length=%" PRIu64 "\n",uo,offset,length);free(uo);
    free(root);records_free(&rv);return 0;
}


static wchar_t *default_out_for_blocks_w(const wchar_t *path, int have_range, uint64_t offset, uint64_t length, uint64_t block) {
    wchar_t *bn=native_basename_dup(path), suffix[160], *o; size_t n=wcslen(bn);
    if(have_range) _snwprintf(suffix,sizeof(suffix)/sizeof(suffix[0]),L".%llu+%llu.block%llu.hash",(unsigned long long)offset,(unsigned long long)length,(unsigned long long)block);
    else _snwprintf(suffix,sizeof(suffix)/sizeof(suffix[0]),L".block%llu.hash",(unsigned long long)block);
    o=(wchar_t *)xmalloc((n+wcslen(suffix)+1)*sizeof(wchar_t));wcscpy(o,bn);wcscat(o,suffix);free(bn);return o;
}
static int generate_blocks_w(const wchar_t *out, const wchar_t *path, uint64_t offset, uint64_t length, uint64_t block) {
    record_vec rv; char *uo; int r; DWORD attr; memset(&rv,0,sizeof(rv));
    attr=GetFileAttributesW(path); if(attr==INVALID_FILE_ATTRIBUTES || (attr&FILE_ATTRIBUTE_DIRECTORY) || (attr&FILE_ATTRIBUTE_REPARSE_POINT)){fwprintf(stderr,L"hashcheck: block input must be a regular file: %ls\n",path);return 2;}
    r=hash_file_blocks_native(path,offset,length,block,&rv); if(r==-2){fwprintf(stderr,L"hashcheck: requested block range is outside file: %ls\n",path);return 2;} if(r!=0){fwprintf(stderr,L"hashcheck: cannot read block range: %ls\n",path);records_free(&rv);return 2;}
    if(write_manifest_native_ex(out,&rv,0,HC_FLAG_RANGE|HC_FLAG_BLOCKS,offset)!=0){records_free(&rv);return 2;}
    {size_t i;for(i=0;i<rv.n;i++){char digest[65];hex32(rv.v[i].hash,digest);printf("SHA-256  %s  %s (block size=%" PRIu64 ")\n",digest,rv.v[i].path,rv.v[i].size);}}
    uo=wide_to_utf8(out);printf("Wrote %s : %zu blocks, offset=%" PRIu64 " length=%" PRIu64 " block=%" PRIu64 "\n",uo,rv.n,offset,length,block);free(uo);records_free(&rv);return 0;
}

static int generate_w(const wchar_t *out, int npaths, wchar_t **paths, const exclude_vec *excludes) {
    record_vec rv; int i,j,wr,root_count=0; uint8_t t,h[32]; uint64_t sz;
    char **roots=(char **)xmalloc((size_t)npaths*sizeof(char*));
    uint8_t (*root_hashes)[32]=(uint8_t (*)[32])xmalloc((size_t)npaths*32);
    unsigned char *included=(unsigned char *)xmalloc((size_t)npaths);
    memset(&rv,0,sizeof(rv)); memset(included,0,(size_t)npaths);
    for(i=0;i<npaths;i++){
        wchar_t *wbn=native_basename_dup(paths[i]); roots[i]=wide_to_utf8(wbn); free(wbn);
        for(j=0;j<i;j++) if(strcmp(roots[j],roots[i])==0) dief("duplicate logical root name %s; rename one root or create separate manifests",roots[i]);
        wr=walk_native(paths[i],roots[i],&rv,roots[i],excludes,&t,h,&sz,0);
        if(wr<0){for(j=0;j<=i;j++)free(roots[j]);free(root_hashes);free(included);free(roots);records_free(&rv);return 2;}
        if(wr==0){included[i]=1;root_count++;memcpy(root_hashes[i],h,32);}
    }
    if(write_manifest_native(out,&rv,(uint32_t)root_count)!=0){fwprintf(stderr,L"hashcheck: failed to write %ls\n",out);records_free(&rv);for(i=0;i<npaths;i++)free(roots[i]);free(root_hashes);free(included);free(roots);return 2;}
    for(i=0;i<npaths;i++)if(included[i])print_sha256(root_hashes[i],roots[i]);
    {char *uo=wide_to_utf8(out);printf("Wrote %s : %zu records (%s)\n",uo,rv.n,os_name(local_os_id()));free(uo);}
    records_free(&rv);free(root_hashes);free(included);for(i=0;i<npaths;i++)free(roots[i]);free(roots);return 0;
}


int wmain(int argc, wchar_t **argv) {
    uint64_t off=0,len=0,block=0;
    int have_off=0,have_len=0,have_block=0,compare_mode=0,npos=0,i,r;
    wchar_t *out=NULL, *mksh=NULL, *log_path=NULL;
    wchar_t **pos;
    exclude_vec excludes; memset(&excludes,0,sizeof(excludes));

    if(argc==1){usage_to(stderr);return 0;}
    pos=(wchar_t **)xmalloc((size_t)argc*sizeof(*pos));

    for(i=1;i<argc;i++){
        if(wcscmp(argv[i],L"-h")==0||wcscmp(argv[i],L"--help")==0){free(pos);usage();return 0;}
        if(wcscmp(argv[i],L"-c")==0||wcscmp(argv[i],L"--compare")==0){compare_mode=1;continue;}
        if(wcscmp(argv[i],L"-o")==0){
            if(out||i+1>=argc){free(pos);usage();return 2;}
            out=argv[++i]; continue;
        }
        if(wcscmp(argv[i],L"--mksh")==0){
            if(mksh||i+1>=argc){free(pos);usage();return 2;}
            mksh=argv[++i]; continue;
        }
        if(wcscmp(argv[i],L"--log")==0){
            if(log_path||i+1>=argc){free(pos);usage();return 2;}
            log_path=argv[++i]; continue;
        }
        if(wcscmp(argv[i],L"--offset")==0){
            if(have_off||i+1>=argc||parse_u64_dec_w(argv[i+1],&off)!=0){free(pos);usage();return 2;}
            have_off=1; i++; continue;
        }
        if(wcscmp(argv[i],L"--length")==0){
            if(have_len||i+1>=argc||parse_u64_dec_w(argv[i+1],&len)!=0){free(pos);usage();return 2;}
            have_len=1; i++; continue;
        }
        if(wcscmp(argv[i],L"--exclude")==0){
            char *rule; if(i+1>=argc){free(pos);usage();return 2;}
            rule=wide_to_utf8(argv[++i]); exclude_add(&excludes,rule); free(rule); continue;
        }
        if(wcscmp(argv[i],L"--block")==0){
            if(have_block||i+1>=argc||parse_u64_dec_w(argv[i+1],&block)!=0||block==0){free(pos);usage();return 2;}
            have_block=1; i++; continue;
        }
        if(wcscmp(argv[i],L"--")==0){
            for(i++;i<argc;i++) pos[npos++]=argv[i];
            break;
        }
        if(argv[i][0]==L'-'){free(pos);usage();return 2;}
        pos[npos++]=argv[i];
    }

    if(mksh){
        wchar_t *auto_out=NULL;
        if(compare_mode||have_off||have_len||have_block||excludes.n||npos!=0||!log_path){
            if(!log_path) fwprintf(stderr,L"hashcheck: --mksh requires --log RECORD.log\n");
            free(pos);usage_to(stderr);return 2;
        }
        if(out){r=hc_generate_mksh_w(out,mksh,log_path);free(pos);return r;}
        auto_out=hc_default_mksh_out_w(mksh);r=hc_generate_mksh_w(auto_out,mksh,log_path);free(auto_out);free(pos);return r;
    }
    if(log_path){fwprintf(stderr,L"hashcheck: --log is only valid with --mksh\n");free(pos);return 2;}

    if(compare_mode){
        manifest a,b;
        if(out||have_off||have_len||have_block||excludes.n||npos!=2){free(pos);usage();return 2;}
        if(read_manifest_native(pos[0],&a)!=0||read_manifest_native(pos[1],&b)!=0){free(pos);dief("cannot read manifest");}
        r=compare_manifest(&a,&b);manifest_free(&a);manifest_free(&b);free(pos);return r;
    }
    if(have_off!=have_len){fprintf(stderr,"hashcheck: --offset and --length must be specified together\n");free(pos);return 2;}
    if(have_block){
        wchar_t *auto_out; uint64_t use_off=0,use_len=0;
        if(excludes.n||npos!=1){free(pos);usage();return 2;}
        if(have_off){use_off=off;use_len=len;} else {
            struct _stat64 st; if(_wstat64(pos[0],&st)!=0 || !(st.st_mode&_S_IFREG)){fwprintf(stderr,L"hashcheck: block input must be a regular file: %ls\n",pos[0]);free(pos);return 2;} use_len=(uint64_t)st.st_size;
        }
        if(out){r=generate_blocks_w(out,pos[0],use_off,use_len,block);free(pos);return r;}
        auto_out=default_out_for_blocks_w(pos[0],have_off,use_off,use_len,block);r=generate_blocks_w(auto_out,pos[0],use_off,use_len,block);free(auto_out);free(pos);return r;
    }
    if(have_off){
        wchar_t *auto_out;
        if(excludes.n||npos!=1){free(pos);usage();return 2;}
        if(out){r=generate_range_w(out,pos[0],off,len);free(pos);return r;}
        auto_out=default_out_for_range_w(pos[0],off,len);r=generate_range_w(auto_out,pos[0],off,len);free(auto_out);free(pos);return r;
    }
    if(!out && npos==1 && path_is_manifest_native(pos[0])){ if(excludes.n){free(pos);usage();return 2;}
        manifest m;
        if(read_manifest_native(pos[0],&m)!=0){free(pos);dief("invalid manifest");}
        print_manifest(&m);r=m.checksum_ok?0:2;manifest_free(&m);free(pos);return r;
    }
    if(!out && npos==2 && path_is_manifest_native(pos[0]) && path_is_manifest_native(pos[1])){ if(excludes.n){free(pos);usage();return 2;}
        manifest a,b;
        if(read_manifest_native(pos[0],&a)!=0||read_manifest_native(pos[1],&b)!=0){free(pos);dief("invalid manifest");}
        r=compare_manifest(&a,&b);manifest_free(&a);manifest_free(&b);free(pos);return r;
    }
    if(npos<1){free(pos);usage();return 2;}
    if(out){r=generate_w(out,npos,pos,&excludes);free(pos);return r;}
    if(npos==1){wchar_t *auto_out=default_out_for_one(pos[0]);r=generate_w(auto_out,1,pos,&excludes);free(auto_out);free(pos);return r;}
    r=generate_w(L"hashcheck.hash",npos,pos,&excludes);free(pos);return r;
}
#else

static char *default_out_for_one(const char *path) {
    char *bn=native_basename_dup(path); size_t n=strlen(bn); char *o=(char *)xmalloc(n+6); memcpy(o,bn,n);memcpy(o+n,".hash",6);free(bn);return o;
}

static char *default_out_for_range(const char *path, uint64_t offset, uint64_t length) {
    char *bn=native_basename_dup(path); size_t n=strlen(bn); char suffix[96]; char *o;
    snprintf(suffix,sizeof(suffix),".%" PRIu64 "+%" PRIu64 ".hash",offset,length);
    o=(char *)xmalloc(n+strlen(suffix)+1);strcpy(o,bn);strcat(o,suffix);free(bn);return o;
}

static int generate_range_u8(const char *out, const char *path, uint64_t offset, uint64_t length) {
    record_vec rv; uint8_t h[32]; char *root; int r; struct stat st;
    memset(&rv,0,sizeof(rv));
    if(lstat(path,&st)!=0 || !S_ISREG(st.st_mode)){fprintf(stderr,"hashcheck: range input must be a regular file: %s\n",path);return 2;}
    r=hash_file_range_native(path,offset,length,h);
    if(r==-2){fprintf(stderr,"hashcheck: requested range is outside file: %s\n",path);return 2;}
    if(r!=0){fprintf(stderr,"hashcheck: cannot read range '%s': %s\n",path,strerror(errno));return 2;}
    root=native_basename_dup(path);records_push(&rv,RT_FILE,length,h,root);
    if(write_manifest_utf8_ex(out,&rv,1,HC_FLAG_RANGE,offset)!=0){free(root);records_free(&rv);return 2;}
    {char digest[65];hex32(h,digest);printf("SHA-256  %s  %s (range offset=%" PRIu64 " length=%" PRIu64 ")\n",digest,root,offset,length);}
    printf("Wrote %s : range offset=%" PRIu64 " length=%" PRIu64 "\n",out,offset,length);
    free(root);records_free(&rv);return 0;
}


static char *default_out_for_blocks(const char *path, int have_range, uint64_t offset, uint64_t length, uint64_t block) {
    char *bn=native_basename_dup(path), suffix[160], *o; size_t n=strlen(bn);
    if(have_range) snprintf(suffix,sizeof(suffix),".%" PRIu64 "+%" PRIu64 ".block%" PRIu64 ".hash",offset,length,block);
    else snprintf(suffix,sizeof(suffix),".block%" PRIu64 ".hash",block);
    o=(char *)xmalloc(n+strlen(suffix)+1);strcpy(o,bn);strcat(o,suffix);free(bn);return o;
}
static int generate_blocks_u8(const char *out, const char *path, uint64_t offset, uint64_t length, uint64_t block) {
    record_vec rv; int r; struct stat st; memset(&rv,0,sizeof(rv));
    if(lstat(path,&st)!=0 || !S_ISREG(st.st_mode)){fprintf(stderr,"hashcheck: block input must be a regular file: %s\n",path);return 2;}
    r=hash_file_blocks_native(path,offset,length,block,&rv); if(r==-2){fprintf(stderr,"hashcheck: requested block range is outside file: %s\n",path);return 2;} if(r!=0){fprintf(stderr,"hashcheck: cannot read block range '%s': %s\n",path,strerror(errno));records_free(&rv);return 2;}
    if(write_manifest_utf8_ex(out,&rv,0,HC_FLAG_RANGE|HC_FLAG_BLOCKS,offset)!=0){records_free(&rv);return 2;}
    {size_t i;for(i=0;i<rv.n;i++){char digest[65];hex32(rv.v[i].hash,digest);printf("SHA-256  %s  %s (block size=%" PRIu64 ")\n",digest,rv.v[i].path,rv.v[i].size);}}
    printf("Wrote %s : %zu blocks, offset=%" PRIu64 " length=%" PRIu64 " block=%" PRIu64 "\n",out,rv.n,offset,length,block);records_free(&rv);return 0;
}

static int generate_u8(const char *out, int npaths, char **paths, const exclude_vec *excludes) {
    record_vec rv; int i,j,wr,root_count=0; uint8_t t,h[32]; uint64_t sz;
    char **roots=(char **)xmalloc((size_t)npaths*sizeof(char*));
    uint8_t (*root_hashes)[32]=(uint8_t (*)[32])xmalloc((size_t)npaths*32);
    unsigned char *included=(unsigned char *)xmalloc((size_t)npaths);
    memset(&rv,0,sizeof(rv)); memset(included,0,(size_t)npaths);
    for(i=0;i<npaths;i++){
        roots[i]=native_basename_dup(paths[i]);
        for(j=0;j<i;j++) if(strcmp(roots[j],roots[i])==0) dief("duplicate logical root name %s; rename one root or create separate manifests",roots[i]);
        wr=walk_native(paths[i],roots[i],&rv,roots[i],excludes,&t,h,&sz,0);
        if(wr<0){for(j=0;j<=i;j++)free(roots[j]);free(root_hashes);free(included);free(roots);records_free(&rv);return 2;}
        if(wr==0){included[i]=1;root_count++;memcpy(root_hashes[i],h,32);}
    }
    if(write_manifest_utf8(out,&rv,(uint32_t)root_count)!=0){records_free(&rv);for(i=0;i<npaths;i++)free(roots[i]);free(root_hashes);free(included);free(roots);return 2;}
    for(i=0;i<npaths;i++)if(included[i])print_sha256(root_hashes[i],roots[i]);
    printf("Wrote %s : %zu records (%s)\n",out,rv.n,os_name(local_os_id()));
    records_free(&rv);free(root_hashes);free(included);for(i=0;i<npaths;i++)free(roots[i]);free(roots);return 0;
}


int main(int argc, char **argv) {
    uint64_t off=0,len=0,block=0;
    int have_off=0,have_len=0,have_block=0,compare_mode=0,npos=0,i,r;
    char *out=NULL, *mksh=NULL, *log_path=NULL;
    char **pos;
    exclude_vec excludes; memset(&excludes,0,sizeof(excludes));

    if(argc==1){usage_to(stderr);return 0;}
    pos=(char **)xmalloc((size_t)argc*sizeof(*pos));

    for(i=1;i<argc;i++){
        if(strcmp(argv[i],"-h")==0||strcmp(argv[i],"--help")==0){free(pos);usage();return 0;}
        if(strcmp(argv[i],"-c")==0||strcmp(argv[i],"--compare")==0){compare_mode=1;continue;}
        if(strcmp(argv[i],"-o")==0){
            if(out||i+1>=argc){free(pos);usage();return 2;}
            out=argv[++i]; continue;
        }
        if(strcmp(argv[i],"--mksh")==0){
            if(mksh||i+1>=argc){free(pos);usage();return 2;}
            mksh=argv[++i]; continue;
        }
        if(strcmp(argv[i],"--log")==0){
            if(log_path||i+1>=argc){free(pos);usage();return 2;}
            log_path=argv[++i]; continue;
        }
        if(strcmp(argv[i],"--offset")==0){
            if(have_off||i+1>=argc||parse_u64_dec(argv[i+1],&off)!=0){free(pos);usage();return 2;}
            have_off=1; i++; continue;
        }
        if(strcmp(argv[i],"--length")==0){
            if(have_len||i+1>=argc||parse_u64_dec(argv[i+1],&len)!=0){free(pos);usage();return 2;}
            have_len=1; i++; continue;
        }
        if(strcmp(argv[i],"--exclude")==0){
            if(i+1>=argc){free(pos);usage();return 2;}
            exclude_add(&excludes,argv[++i]); continue;
        }
        if(strcmp(argv[i],"--block")==0){
            if(have_block||i+1>=argc||parse_u64_dec(argv[i+1],&block)!=0||block==0){free(pos);usage();return 2;}
            have_block=1; i++; continue;
        }
        if(strcmp(argv[i],"--")==0){
            for(i++;i<argc;i++) pos[npos++]=argv[i];
            break;
        }
        if(argv[i][0]=='-'){free(pos);usage();return 2;}
        pos[npos++]=argv[i];
    }

    if(mksh){
        char *auto_out=NULL;
        if(compare_mode||have_off||have_len||have_block||excludes.n||npos!=0||!log_path){
            if(!log_path) fprintf(stderr,"hashcheck: --mksh requires --log RECORD.log\n");
            free(pos);usage_to(stderr);return 2;
        }
        if(out){r=hc_generate_mksh_u8(out,mksh,log_path);free(pos);return r;}
        auto_out=hc_default_mksh_out_u8(mksh);r=hc_generate_mksh_u8(auto_out,mksh,log_path);free(auto_out);free(pos);return r;
    }
    if(log_path){fprintf(stderr,"hashcheck: --log is only valid with --mksh\n");free(pos);return 2;}

    if(compare_mode){
        manifest a,b;
        if(out||have_off||have_len||have_block||excludes.n||npos!=2){free(pos);usage();return 2;}
        if(read_manifest_native(pos[0],&a)!=0||read_manifest_native(pos[1],&b)!=0){free(pos);dief("cannot read manifest");}
        r=compare_manifest(&a,&b);manifest_free(&a);manifest_free(&b);free(pos);return r;
    }
    if(have_off!=have_len){fprintf(stderr,"hashcheck: --offset and --length must be specified together\n");free(pos);return 2;}
    if(have_block){
        char *auto_out; uint64_t use_off=0,use_len=0; struct stat st;
        if(excludes.n||npos!=1){free(pos);usage();return 2;}
        if(have_off){use_off=off;use_len=len;} else {
            if(lstat(pos[0],&st)!=0 || !S_ISREG(st.st_mode)){fprintf(stderr,"hashcheck: block input must be a regular file: %s\n",pos[0]);free(pos);return 2;} use_len=(uint64_t)st.st_size;
        }
        if(out){r=generate_blocks_u8(out,pos[0],use_off,use_len,block);free(pos);return r;}
        auto_out=default_out_for_blocks(pos[0],have_off,use_off,use_len,block);r=generate_blocks_u8(auto_out,pos[0],use_off,use_len,block);free(auto_out);free(pos);return r;
    }
    if(have_off){
        char *auto_out;
        if(excludes.n||npos!=1){free(pos);usage();return 2;}
        if(out){r=generate_range_u8(out,pos[0],off,len);free(pos);return r;}
        auto_out=default_out_for_range(pos[0],off,len);r=generate_range_u8(auto_out,pos[0],off,len);free(auto_out);free(pos);return r;
    }
    if(!out && npos==1 && path_is_manifest_native(pos[0])){ if(excludes.n){free(pos);usage();return 2;}
        manifest m;
        if(read_manifest_native(pos[0],&m)!=0){free(pos);dief("invalid manifest");}
        print_manifest(&m);r=m.checksum_ok?0:2;manifest_free(&m);free(pos);return r;
    }
    if(!out && npos==2 && path_is_manifest_native(pos[0]) && path_is_manifest_native(pos[1])){ if(excludes.n){free(pos);usage();return 2;}
        manifest a,b;
        if(read_manifest_native(pos[0],&a)!=0||read_manifest_native(pos[1],&b)!=0){free(pos);dief("invalid manifest");}
        r=compare_manifest(&a,&b);manifest_free(&a);manifest_free(&b);free(pos);return r;
    }
    if(npos<1){free(pos);usage();return 2;}
    if(out){r=generate_u8(out,npos,pos,&excludes);free(pos);return r;}
    if(npos==1){char *auto_out=default_out_for_one(pos[0]);r=generate_u8(auto_out,1,pos,&excludes);free(auto_out);free(pos);return r;}
    r=generate_u8("hashcheck.hash",npos,pos,&excludes);free(pos);return r;
}
#endif
