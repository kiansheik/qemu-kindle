// fbshim.c Fake /dev/fb0 (8bpp) that streams full frames over virtio-serial.
// Protocol per frame: 32-byte header + W*H bytes payload (8bpp).
// Header (little-endian):
//   magic[4] = "FB8\0"
//   w,u32 | h,u32 | fb_size,u32 | flags,u32 (bit0=fullframe=1)
//   seq,u64
//
// Env:
//   FB_W, FB_H                      framebuffer dims (default 1272x1696)
//   FB_DEV=/dev/fb0                 fb device path to interpose
//   FB_VPORT=/dev/virtio-ports/org.kindle.fb (fallback: /dev/vport0p0)
//
// Build:
//   gcc -shared -fPIC -O2 -Wall -Wextra -o libfbshim.so fbshim.c -ldl -pthread
//
// Use:
//   LD_PRELOAD=./libfbshim.so your_fb_app

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

// SET YOUR DEVICE'S ASPECT RATIO HERE IF DIFFERENT 
static int FB_W = 1272;
static int FB_H = 1696;
static int FB_DEBUG = 1;
#define D(fmt, ...) do { if (FB_DEBUG) fprintf(stderr, "[fbshim] " fmt "\n", ##__VA_ARGS__); } while(0)
#define E(fmt, ...) do { fprintf(stderr, "[fbshim:ERR] " fmt "\n", ##__VA_ARGS__); } while(0)

// ---------- Config ----------
static const char *DEFAULT_FB_DEV   = "/dev/fb0";
static const char *DEFAULT_VPORT    = "/dev/virtio-ports/org.kindle.fb"; // symlink made by virtio-serial
static const char *FALLBACK_VPORT   = "/dev/vport0p0";

typedef struct {
  char     magic[4];  // "FB8"
  uint32_t w, h;
  uint32_t fb_size, flags;
  uint32_t pad;       // = 0
  uint64_t seq;
} fb8_pkt_hdr_t;


// ---------- State ----------
static const char *FB_DEV_PATH = NULL;
static const char *VPORT_PATH  = NULL;

static unsigned char *fb_buf = NULL;
static size_t FB_SIZE = 0;

static uint64_t seq = 0;

#define MAX_FDS 64
typedef struct {
    int in_use;
    int os_fd;
    void *last_map;
    size_t last_map_len;
    off_t pos;
} fb_fdent_t;
static fb_fdent_t FD_TAB[MAX_FDS];

static int vport_fd = -1;
static pthread_mutex_t vport_mu = PTHREAD_MUTEX_INITIALIZER;

// libc real funcs
static int   (*real_open)(const char*, int, ...) = NULL;
static int   (*real_openat)(int, const char*, int, ...) = NULL;
static int   (*real_close)(int) = NULL;
static int   (*real_fstat)(int, struct stat*) = NULL;
static int   (*real_stat)(const char*, struct stat*) = NULL;
static int   (*real_ioctl)(int, unsigned long, ...) = NULL;
static void* (*real_mmap)(void*, size_t, int, int, int, off_t) = NULL;
static int   (*real_munmap)(void*, size_t) = NULL;
static off_t (*real_lseek)(int, off_t, int) = NULL;
static ssize_t(*real_write)(int,const void*,size_t) = NULL;
static ssize_t(*real_pwrite)(int,const void*,size_t,off_t) = NULL;
static ssize_t(*real_writev)(int,const struct iovec*,int) = NULL;

static void resolve_syms(void) {
    if (real_open) return;
    real_open   = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_close  = dlsym(RTLD_NEXT, "close");
    real_fstat  = dlsym(RTLD_NEXT, "fstat");
    real_stat   = dlsym(RTLD_NEXT, "stat");
    real_ioctl  = dlsym(RTLD_NEXT, "ioctl");
    real_mmap   = dlsym(RTLD_NEXT, "mmap");
    real_munmap = dlsym(RTLD_NEXT, "munmap");
    real_lseek  = dlsym(RTLD_NEXT, "lseek");
    real_write  = dlsym(RTLD_NEXT, "write");
    real_pwrite = dlsym(RTLD_NEXT, "pwrite");
    real_writev = dlsym(RTLD_NEXT, "writev");
}

static void init_config(void) {
    if (!FB_DEV_PATH) {
        const char *d = getenv("FB_DEV");
        FB_DEV_PATH = (d && *d) ? d : DEFAULT_FB_DEV;
    }
    if (!VPORT_PATH) {
        const char *p = getenv("FB_VPORT");
        VPORT_PATH = (p && *p) ? p : DEFAULT_VPORT;
    }
    const char *ew = getenv("FB_W");
    const char *eh = getenv("FB_H");
    const char *dbg = getenv("FB_DEBUG");
    if (ew) FB_W = atoi(ew);
    if (eh) FB_H = atoi(eh);
    if (FB_W <= 0) FB_W = 1272;
    if (FB_H <= 0) FB_H = 1696;
    FB_SIZE = (size_t)FB_W * (size_t)FB_H;
    FB_DEBUG = (dbg && *dbg && strcmp(dbg,"0")!=0) ? 1 : 0;
    D("config: FB_DEV=\"%s\" VPORT=\"%s\" W=%d H=%d SIZE=%zu DEBUG=%d",
      FB_DEV_PATH, VPORT_PATH, FB_W, FB_H, FB_SIZE, FB_DEBUG);
}

// ---------- FD table helpers ----------
static int find_slot_by_fd(int fd) {
    for (int i = 0; i < MAX_FDS; i++) if (FD_TAB[i].in_use && FD_TAB[i].os_fd == fd) return i;
    return -1;
}
static int alloc_slot(int os_fd) {
    for (int i = 0; i < MAX_FDS; i++) if (!FD_TAB[i].in_use) {
        FD_TAB[i].in_use = 1;
        FD_TAB[i].os_fd = os_fd;
        FD_TAB[i].last_map = NULL;
        FD_TAB[i].last_map_len = 0;
        FD_TAB[i].pos = 0;
        D("alloc_slot: os_fd=%d -> slot=%d", os_fd, i);
        return i;
    }
    return -1;
}
static void free_slot(int fd) {
    int i = find_slot_by_fd(fd);
    if (i >= 0) {
        D("free_slot: fd=%d slot=%d", fd, i);
        FD_TAB[i].in_use = 0;
        FD_TAB[i].os_fd = -1;
        FD_TAB[i].last_map = NULL;
        FD_TAB[i].last_map_len = 0;
        FD_TAB[i].pos = 0;
    }
}

// ---------- Virtio-serial publish ----------
static int ensure_vport_open(void) {
    if (vport_fd >= 0) return 0;
    pthread_mutex_lock(&vport_mu);
    if (vport_fd >= 0) { pthread_mutex_unlock(&vport_mu); return 0; }

    int fd = -1;
    if (VPORT_PATH && access(VPORT_PATH, W_OK) == 0)
        fd = (real_open ? real_open(VPORT_PATH, O_WRONLY) : open(VPORT_PATH, O_WRONLY));

    if (fd < 0 && access(FALLBACK_VPORT, W_OK) == 0)
        fd = (real_open ? real_open(FALLBACK_VPORT, O_WRONLY) : open(FALLBACK_VPORT, O_WRONLY));

    if (fd < 0) {
        E("cannot open virtio port: tried \"%s\" and \"%s\"", VPORT_PATH, FALLBACK_VPORT);
        pthread_mutex_unlock(&vport_mu);
        return -1;
    }
    vport_fd = fd;
    D("vport open ok: fd=%d", vport_fd);
    pthread_mutex_unlock(&vport_mu);
    return 0;
}

static ssize_t full_write(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t*)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = (real_write ? real_write(fd, p, left) : write(fd, p, left));
        if (n < 0) {
            if (errno == EINTR) continue;
            return n;
        }
        if (n == 0) break;
        p += n; left -= n;
    }
    return (ssize_t)(len - left);
}

static void fbshim_publish_frame(void) {
    if (!fb_buf || FB_SIZE == 0) { D("publish: no fb_buf"); return; }
    if (ensure_vport_open() != 0) { D("publish: no vport"); return; }

    fb8_pkt_hdr_t h;
    memcpy(h.magic, "FB8", 4);
    h.w = (uint32_t)FB_W;
    h.h = (uint32_t)FB_H;
    h.fb_size = (uint32_t)FB_SIZE;
    h.flags = 1; // full frame
    h.seq = ++seq;

    struct iovec iov[2] = {
        { &h, sizeof(h) },
        { fb_buf, FB_SIZE }
    };

    ssize_t n1 = full_write(vport_fd, iov[0].iov_base, iov[0].iov_len);
    if (n1 != (ssize_t)iov[0].iov_len) { E("publish hdr write %zd/%zu err=%d", n1, iov[0].iov_len, errno); return; }
    ssize_t n2 = full_write(vport_fd, iov[1].iov_base, iov[1].iov_len);
    if (n2 != (ssize_t)iov[1].iov_len) { E("publish pixels write %zd/%zu err=%d", n2, iov[1].iov_len, errno); return; }

    D("publish: seq=%llu bytes=%zu", (unsigned long long)h.seq, FB_SIZE);
}

// ---------- Minimal FB model ----------
static void fill_fix(struct fb_fix_screeninfo *fx) {
    memset(fx, 0, sizeof(*fx));
    strcpy(fx->id, "fbshim");
    fx->smem_start  = 0;
    fx->smem_len    = (uint32_t)FB_SIZE;
    fx->type        = FB_TYPE_PACKED_PIXELS;
    fx->visual      = FB_VISUAL_PSEUDOCOLOR;
    fx->line_length = (uint32_t)FB_W;
    fx->accel       = FB_ACCEL_NONE;
}
static void fill_var(struct fb_var_screeninfo *vr) {
    memset(vr, 0, sizeof(*vr));
    vr->xres         = FB_W;
    vr->yres         = FB_H;
    vr->xres_virtual = FB_W;
    vr->yres_virtual = FB_H;
    vr->bits_per_pixel = 8;
    vr->red.offset=0; vr->red.length=8;
    vr->green.offset=0; vr->green.length=8;
    vr->blue.offset=0; vr->blue.length=8;
    vr->transp.offset=0; vr->transp.length=0;
    vr->activate = FB_ACTIVATE_NOW;
}

// ---------- Interposed syscalls ----------
int open(const char *path, int flags, ...) {
    resolve_syms(); init_config();
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }

    if (path && strcmp(path, FB_DEV_PATH) == 0) {
        int osfd = real_open ? real_open("/dev/null", O_RDWR) : open("/dev/null", O_RDWR);
        D("open(%s) -> osfd=%d", path, osfd);
        if (osfd < 0) return osfd;
        if (alloc_slot(osfd) < 0) { if (real_close) real_close(osfd); errno = EMFILE; return -1; }
        if (!fb_buf) {
            long pg = sysconf(_SC_PAGESIZE);
            size_t align = (pg > 0) ? (size_t)pg : 4096;
            if (posix_memalign((void**)&fb_buf, align, FB_SIZE) != 0) { if (real_close) real_close(osfd); errno = ENOMEM; return -1; }
            memset(fb_buf, 0xFF, FB_SIZE);
            D("fb_buf alloc: %p size=%zu", (void*)fb_buf, FB_SIZE);
        }
        return osfd;
    }
    return (flags & O_CREAT)
           ? (real_open ? real_open(path, flags, mode) : open(path, flags, mode))
           : (real_open ? real_open(path, flags) : open(path, flags));
}
int openat(int dirfd, const char *path, int flags, ...) {
    resolve_syms(); init_config();
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (path && strcmp(path, FB_DEV_PATH) == 0) {
        int osfd = real_open ? real_open("/dev/null", O_RDWR) : open("/dev/null", O_RDWR);
        D("openat(%s) -> osfd=%d", path, osfd);
        if (osfd < 0) return osfd;
        if (alloc_slot(osfd) < 0) { if (real_close) real_close(osfd); errno = EMFILE; return -1; }
        if (!fb_buf) {
            long pg = sysconf(_SC_PAGESIZE);
            size_t align = (pg > 0) ? (size_t)pg : 4096;
            if (posix_memalign((void**)&fb_buf, align, FB_SIZE) != 0) { if (real_close) real_close(osfd); errno = ENOMEM; return -1; }
            memset(fb_buf, 0xFF, FB_SIZE);
            D("fb_buf alloc: %p size=%zu", (void*)fb_buf, FB_SIZE);
        }
        return osfd;
    }
    return (flags & O_CREAT)
           ? (real_openat ? real_openat(dirfd, path, flags, mode) : openat(dirfd, path, flags, mode))
           : (real_openat ? real_openat(dirfd, path, flags) : openat(dirfd, path, flags));
}

static void fill_stat_like_fb(struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFCHR | 0666;
    st->st_rdev = makedev(29, 0);
    st->st_blksize = 4096;
    st->st_size = FB_SIZE;
}
int fstat(int fd, struct stat *st) {
    resolve_syms();
    if (find_slot_by_fd(fd) >= 0) { D("fstat(fd=%d)", fd); fill_stat_like_fb(st); return 0; }
    return real_fstat ? real_fstat(fd, st) : fstat(fd, st);
}
int stat(const char *path, struct stat *st) {
    resolve_syms(); init_config();
    if (path && strcmp(path, FB_DEV_PATH) == 0) { D("stat(%s)", path); fill_stat_like_fb(st); return 0; }
    return real_stat ? real_stat(path, st) : stat(path, st);
}

int ioctl(int fd, unsigned long req, ...) {
    resolve_syms();
    // Always read vararg for fb fds (some headers report size/dir=0).
    unsigned long uarg = 0;
    void *argp = NULL;
    int slot = find_slot_by_fd(fd);
    va_list ap; va_start(ap, req);
    if (slot >= 0) { uarg = va_arg(ap, unsigned long); argp = (void*)(uintptr_t)uarg; }
    else {
        // For non-fb fds, only fetch if it likely exists (best effort)
        unsigned long dir=_IOC_DIR(req), size=_IOC_SIZE(req);
        if (dir!=_IOC_NONE || size!=0) { uarg=va_arg(ap,unsigned long); argp=(void*)(uintptr_t)uarg; }
    }
    va_end(ap);

    if (slot >= 0) {
        D("ioctl(fd=%d, req=0x%lx arg=0x%lx)", fd, req, uarg);
        switch (req) {
            case FBIOGET_FSCREENINFO: if (!argp){ errno=EINVAL; return -1; } fill_fix((struct fb_fix_screeninfo*)argp); return 0;
            case FBIOGET_VSCREENINFO: if (!argp){ errno=EINVAL; return -1; } fill_var((struct fb_var_screeninfo*)argp); return 0;
            case FBIOPUT_VSCREENINFO: return 0;
            case FBIOPAN_DISPLAY:     fbshim_publish_frame(); return 0;
            default:                  fbshim_publish_frame(); return 0; // treat unknown as flush
        }
    }
    if (!real_ioctl) { errno = ENOSYS; return -1; }
    if (argp) return real_ioctl(fd, req, argp);
    typedef int (*ioctl_noarg_t)(int, unsigned long);
    return ((ioctl_noarg_t)real_ioctl)(fd, req);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t off) {
    resolve_syms();
    int i = find_slot_by_fd(fd);
    if (i >= 0) {
        if (!fb_buf) {
            long pg = sysconf(_SC_PAGESIZE);
            size_t align = (pg > 0) ? (size_t)pg : 4096;
            if (posix_memalign((void**)&fb_buf, align, FB_SIZE) != 0) { errno = ENOMEM; return MAP_FAILED; }
            memset(fb_buf, 0xFF, FB_SIZE);
            D("mmap: allocated fb_buf=%p size=%zu", (void*)fb_buf, FB_SIZE);
        }
        FD_TAB[i].last_map = fb_buf;
        FD_TAB[i].last_map_len = length;
        D("mmap(fd=%d) -> %p len=%zu", fd, fb_buf, length);
        return fb_buf;
    }
    void *p = real_mmap ? real_mmap(addr, length, prot, flags, fd, off) : mmap(addr,length,prot,flags,fd,off);
    D("mmap passthrough fd=%d -> %p", fd, p);
    return p;
}
int munmap(void *addr, size_t length) {
    resolve_syms();
    for (int i = 0; i < MAX_FDS; i++) {
        if (FD_TAB[i].in_use && FD_TAB[i].last_map == addr) {
            D("munmap(fd slot=%d) addr=%p len=%zu (kept)", i, addr, length);
            FD_TAB[i].last_map = NULL;
            FD_TAB[i].last_map_len = 0;
            return 0;
        }
    }
    return real_munmap ? real_munmap(addr, length) : munmap(addr, length);
}

off_t lseek(int fd, off_t offset, int whence) {
    resolve_syms();
    int i = find_slot_by_fd(fd);
    if (i < 0) return real_lseek ? real_lseek(fd, offset, whence) : lseek(fd, offset, whence);
    off_t newpos = FD_TAB[i].pos;
    switch (whence) {
        case SEEK_SET: newpos = offset; break;
        case SEEK_CUR: newpos = FD_TAB[i].pos + offset; break;
        case SEEK_END: newpos = (off_t)FB_SIZE + offset; break;
        default: errno = EINVAL; return (off_t)-1;
    }
    if (newpos < 0) { errno = EINVAL; return (off_t)-1; }
    D("lseek(fd=%d) pos %lld -> %lld", fd, (long long)FD_TAB[i].pos, (long long)newpos);
    FD_TAB[i].pos = newpos;
    return newpos;
}

static size_t fb_copy_at(off_t off, const void *src, size_t len) {
    if (!fb_buf || FB_SIZE == 0 || off >= (off_t)FB_SIZE) return 0;
    size_t max = FB_SIZE - (size_t)off;
    if (len > max) len = max;
    memcpy(fb_buf + off, src, len);
    return len;
}
ssize_t write(int fd, const void *buf, size_t count) {
    resolve_syms();
    int i = find_slot_by_fd(fd);
    if (i < 0) return real_write ? real_write(fd, buf, count) : write(fd, buf, count);
    size_t done = fb_copy_at(FD_TAB[i].pos, buf, count);
    D("write(fd=%d) pos=%lld count=%zu -> done=%zu", fd, (long long)FD_TAB[i].pos, count, done);
    FD_TAB[i].pos += (off_t)done;
    fbshim_publish_frame();
    return (ssize_t)done;
}
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    resolve_syms();
    int i = find_slot_by_fd(fd);
    if (i < 0) return real_pwrite ? real_pwrite(fd, buf, count, offset) : pwrite(fd, buf, count, offset);
    size_t done = fb_copy_at(offset, buf, count);
    D("pwrite(fd=%d) off=%lld count=%zu -> done=%zu", fd, (long long)offset, count, done);
    fbshim_publish_frame();
    return (ssize_t)done;
}
ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    resolve_syms();
    int i = find_slot_by_fd(fd);
    if (i < 0) return real_writev ? real_writev(fd, iov, iovcnt) : writev(fd, iov, iovcnt);
    ssize_t total = 0;
    for (int k = 0; k < iovcnt; k++) {
        size_t done = fb_copy_at(FD_TAB[i].pos, iov[k].iov_base, iov[k].iov_len);
        FD_TAB[i].pos += (off_t)done;
        total += (ssize_t)done;
        if (done < iov[k].iov_len) break;
    }
    D("writev(fd=%d) iovcnt=%d -> total=%zd", fd, iovcnt, total);
    fbshim_publish_frame();
    return total;
}

int close(int fd) {
    resolve_syms();
    if (find_slot_by_fd(fd) >= 0) {
        D("close(fd=%d) -> publish+close", fd);
        fbshim_publish_frame();
        free_slot(fd);
        return real_close ? real_close(fd) : close(fd);
    }
    return real_close ? real_close(fd) : close(fd);
}

__attribute__((constructor))
static void fbshim_ctor(void) {
    resolve_syms();
    init_config();
    D("ctor safe. FB_DEV=\"%s\" VPORT=\"%s\" W=%d H=%d SIZE=%zu DEBUG=%d",
      FB_DEV_PATH, VPORT_PATH, FB_W, FB_H, FB_SIZE, FB_DEBUG);
}