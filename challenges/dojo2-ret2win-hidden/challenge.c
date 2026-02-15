#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

/*
  Mini-DOJO Level 2: Hidden ret2win

  Notes:
  - No PIE, no canary, execstack enabled.
  - Students must discover the target function address using tooling.
*/

static void banner(void) {
    puts("==============================================");
    puts(" Mini-DOJO: Level 2 — Hidden Path");
    puts("==============================================");
    puts("Welcome, hacker.");
    puts("Hint: the binary knows more than it tells you.");
    puts("Try: file, checksec, strings, nm, readelf, objdump, gdb");
    puts("--------------------------------------------------");
}

__attribute__((noinline))
static void vuln(void) {
    char buf[64];

    puts("Tell me a story:");
    puts("(Careful: stories that are too long can change the ending.)");

    // Deliberate vulnerability for educational purposes:
    // gets() has no bounds checking.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    gets(buf);
#pragma GCC diagnostic pop

    puts("Thanks for sharing.");
}

__attribute__((noinline))
void win(void) {
    // Do not print anything here: keep it silent.
    // Escalate privileges (binary is SUID root).
    setgid(0);
    setuid(0);

    // Spawn a root shell that preserves privileges.
    execl("/bin/sh", "sh", "-p", NULL);

    // If execl fails:
    _exit(1);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    banner();
    vuln();
    puts("Goodbye.");
    return 0;
}