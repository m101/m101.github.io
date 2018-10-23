// @author  m_101
// @year    2011
// @desc    Program for launching GCHQ code
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <string.h>

// for memalign, mprotect
#include <sys/mman.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>

// ptrace
#include <sys/ptrace.h>
// for registers
#include <sys/user.h>

#define __NR_exit   1
#define MSG_LENGTH  0x32

// launch a file
int launch_file (char *filename) {
    //
    char *mem;
    void (*func)();
    // file related
    FILE *fp;
    int szFile;

    if (!filename)
        return -1;

    // open file
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "error: Failed opening (r): %s\n", filename);
        exit(1);
    }

    // get file size
    fseek(fp, 0, SEEK_END);
    szFile = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("[+] File size: %d\n", szFile);

    // alloc aligned memory for file
    mem = memalign(PAGE_SIZE, szFile * sizeof(*mem));
    if (!mem) {
        printf("[-] error: %s\n", strerror(errno));
        return 1;
    }
    memset(mem, 0, szFile * sizeof(*mem));

    // fill mem
    fread(mem, sizeof(*mem), szFile, fp);

    // set permissions
    if (mprotect(mem, szFile * sizeof(*mem), PROT_READ | PROT_WRITE | PROT_EXEC)) {
        printf("[-] error: %s\n", strerror(errno));
        return 1;
    }

    // close file
    fclose(fp);

    // execute code
    printf("[+] Executing code at address %p\n", mem);
    func = (void *) mem;
    func();

    return 0;
}

void regs_show (struct user_regs_struct *regs) {
    if (!regs)
        return;

    printf("eax: 0x%08lx\n", regs->orig_eax);
    printf("ebx: 0x%08lx\n", regs->ebx);
    printf("ecx: 0x%08lx\n", regs->ecx);
    printf("edx: 0x%08lx\n", regs->edx);
    printf("esi: 0x%08lx\n", regs->esi);
    printf("edi: 0x%08lx\n", regs->edi);
    printf("ebp: 0x%08lx\n", regs->ebp);
    printf("esp: 0x%08lx\n", regs->esp);
    printf("eip: 0x%08lx\n", regs->eip);
    printf("eflags: 0x%08lx\n", regs->eflags);
    printf("cs: 0x%08lx\n", regs->xcs);
    printf("ds: 0x%08lx\n", regs->xds);
    printf("es: 0x%08lx\n", regs->xes);
    printf("fs: 0x%08lx\n", regs->xfs);
    printf("gs: 0x%08lx\n", regs->xgs);
    printf("ss: 0x%08lx\n", regs->xss);
}

int main (int argc, char *argv[]) {
    int retcode;
    pid_t cpid;
    struct user_regs_struct regs = {0};
    int cstatus;
    // for ptrace
    int syscall;
    // dump memory of child process
    char decoded[MSG_LENGTH * 2] = {0};
    uint32_t word;
    uint32_t addr;
    int offset;


    // check number of arguments
    if (argc < 2) {
        printf("Usage: %s filename\n", argv[0]);
        return -1;
    }

    cpid = fork();
    // child
    if (cpid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGTRAP);
        launch_file(argv[1]);
    }
    // parent
    else if (cpid > 0) {
        // wait for child
        waitpid(cpid, &cstatus, 0);

        // trace the process to arrive to the exit syscall
        do {
            // get at syscall entry
            ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
            waitpid(cpid, &cstatus, 0);

            // get registers of child process
            ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
            syscall = regs.orig_eax;

            // we are at exit syscall
            // then we finish the loop and do more processing
            if (syscall != __NR_exit) {
                // wait for syscall to complete
                // and avoid exiting process
                ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
                waitpid(cpid, &cstatus, 0);
            }
        } while (syscall != __NR_exit);

        // get registers of child process
        ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
        printf("== Registers\n");
        regs_show(&regs);

        // dump decoded string
        addr = regs.esi - MSG_LENGTH;
        for (offset = 0; offset < MSG_LENGTH; offset += 4) {
            word = ptrace(PTRACE_PEEKDATA, cpid, addr + offset, NULL);
            // printf("word: 0x%08x\n", word);
            *((uint32_t *)(decoded+offset)) = word;
        }
        printf("\n[+] Decoded string: '%s'\n", decoded);

        // continue process (so it exits)
        ptrace(PTRACE_CONT, cpid, NULL, NULL);
    }
    // error
    else {
        printf("Failed fork\n");
    }

    return 0;
}

