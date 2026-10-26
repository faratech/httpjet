/* Local qualification only; io_uring remains mandatory for the server. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define PROBE_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define PROBE_ARCH AUDIT_ARCH_AARCH64
#else
#error "qualification helper supports amd64 and arm64"
#endif

static int denied_exec(char **command) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROBE_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_register, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof instructions / sizeof instructions[0], .filter = instructions };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) {
        fprintf(stderr, "qualification seccomp setup: %s\n", strerror(errno));
        return 125;
    }
    printf("{\"schema\":1,\"mode\":\"deny-exec\",\"uid\":%lu,\"global_policy_changed\":false}\n", (unsigned long)geteuid());
    fflush(stdout);
    execv(command[0], command);
    fprintf(stderr, "qualification exec: %s\n", strerror(errno));
    return 127;
}

int main(int argc, char **argv) {
    if (geteuid() == 0) {
        puts("{\"schema\":1,\"status\":\"failed\",\"operation\":\"identity\",\"uid\":0,\"errno\":1}");
        return 1;
    }
    if (argc >= 3 && !strcmp(argv[1], "--deny-exec")) return denied_exec(argv + 2);
    if (argc != 1) { fputs("usage: io-uring-probe [--deny-exec BINARY ARGS...]\n", stderr); return 2; }
    struct io_uring_params parameters = {0};
    int descriptor = -1, error_number = 0, registered = 0, entered = 0;
    const char *operation = "setup";
    void *submission = MAP_FAILED, *completion = MAP_FAILED, *entries = MAP_FAILED;
    size_t submission_size = 0, completion_size = 0, entries_size = 0;
    struct io_uring_probe *probe = calloc(1, sizeof(*probe) + 256 * sizeof(struct io_uring_probe_op));
    if (!probe) { error_number = ENOMEM; goto done; }
    descriptor = syscall(__NR_io_uring_setup, 2, &parameters);
    if (descriptor < 0) { error_number = errno; goto done; }
    operation = "register_probe";
    if (syscall(__NR_io_uring_register, descriptor, IORING_REGISTER_PROBE, probe, 256) < 0) { error_number = errno; goto done; }
    registered = 1;
    submission_size = parameters.sq_off.array + parameters.sq_entries * sizeof(unsigned);
    completion_size = parameters.cq_off.cqes + parameters.cq_entries * sizeof(struct io_uring_cqe);
    if (parameters.features & IORING_FEAT_SINGLE_MMAP) {
        if (completion_size > submission_size) submission_size = completion_size;
        completion_size = submission_size;
    }
    operation = "mmap";
    submission = mmap(NULL, submission_size, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, IORING_OFF_SQ_RING);
    if (submission == MAP_FAILED) { error_number = errno; goto done; }
    completion = (parameters.features & IORING_FEAT_SINGLE_MMAP) ? submission :
        mmap(NULL, completion_size, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, IORING_OFF_CQ_RING);
    if (completion == MAP_FAILED) { error_number = errno; goto done; }
    entries_size = parameters.sq_entries * sizeof(struct io_uring_sqe);
    entries = mmap(NULL, entries_size, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, IORING_OFF_SQES);
    if (entries == MAP_FAILED) { error_number = errno; goto done; }
    unsigned *tail = (unsigned *)((char *)submission + parameters.sq_off.tail);
    unsigned *mask = (unsigned *)((char *)submission + parameters.sq_off.ring_mask);
    unsigned *array = (unsigned *)((char *)submission + parameters.sq_off.array);
    unsigned position = __atomic_load_n(tail, __ATOMIC_RELAXED);
    unsigned index = position & *mask;
    struct io_uring_sqe *entry = &((struct io_uring_sqe *)entries)[index];
    memset(entry, 0, sizeof *entry);
    entry->opcode = IORING_OP_NOP;
    entry->user_data = UINT64_C(0x687474706a6574);
    array[index] = index;
    __atomic_store_n(tail, position + 1, __ATOMIC_RELEASE);
    operation = "enter_nop";
    int result;
    do { result = syscall(__NR_io_uring_enter, descriptor, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0); } while (result < 0 && errno == EINTR);
    if (result < 0) { error_number = errno; goto done; }
    unsigned *head = (unsigned *)((char *)completion + parameters.cq_off.head);
    unsigned *cq_tail = (unsigned *)((char *)completion + parameters.cq_off.tail);
    unsigned *cq_mask = (unsigned *)((char *)completion + parameters.cq_off.ring_mask);
    unsigned consumed = __atomic_load_n(head, __ATOMIC_RELAXED);
    if (consumed == __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE)) { error_number = EIO; goto done; }
    struct io_uring_cqe *event = &((struct io_uring_cqe *)((char *)completion + parameters.cq_off.cqes))[consumed & *cq_mask];
    if (event->res || event->user_data != UINT64_C(0x687474706a6574)) { error_number = event->res < 0 ? -event->res : EIO; goto done; }
    __atomic_store_n(head, consumed + 1, __ATOMIC_RELEASE);
    entered = 1;
done:
    printf("{\"schema\":1,\"status\":\"%s\",\"uid\":%lu,\"operation\":\"%s\",\"errno\":%d,\"operations\":{\"setup\":%s,\"register_probe\":%s,\"enter_nop\":%s}}\n",
           entered ? "passed" : "failed", (unsigned long)geteuid(), operation, error_number,
           descriptor >= 0 ? "true" : "false", registered ? "true" : "false", entered ? "true" : "false");
    if (entries != MAP_FAILED) munmap(entries, entries_size);
    if (completion != MAP_FAILED && completion != submission) munmap(completion, completion_size);
    if (submission != MAP_FAILED) munmap(submission, submission_size);
    if (descriptor >= 0) close(descriptor);
    free(probe);
    return entered ? 0 : 1;
}
