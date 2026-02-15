#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void win() {
    printf("\n🎉 Congratulations! You called the win() function!\n");
    printf("Spawning a root shell...\n\n");

    // Set effective UID to root (0) since this binary is SUID root
    setuid(0);
    setgid(0);
    // Spawn a shell with root privileges
    execl("/bin/sh", "sh", "-p", NULL);
}

void vuln() {
    char buffer[64];
    
    printf("Welcome to Dojo 1: ret2win!\n");
    printf("==============================\n\n");
    printf("This is a beginner-friendly buffer overflow challenge.\n");
    printf("Your goal: overflow the buffer and redirect execution to the win() function.\n\n");
    printf("win() function is located at: %p\n\n", win);
    printf("Enter your input: ");
    fflush(stdout);
    
    // Vulnerable function - no bounds checking!
    gets(buffer);
    
    printf("\nYou entered: %s\n", buffer);
}

int main() {
    // Disable buffering for cleaner output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    vuln();
    
    printf("\nExiting normally. Better luck next time!\n");
    return 0;
}
