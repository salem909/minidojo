# Mini-DOJO — Level 2: Hidden ret2win

You are the `hacker` user (UID 1000) in a Linux container.

- `/flag` exists and is readable only by `root` (`0400`).
- `/challenge/challenge` is **SUID root**.
- Your terminal is provided via a browser shell.

## Goal

Get a **root shell** and read the flag:

- As `hacker`, `cat /flag` should fail.
- After exploitation, `id` should show `uid=0(root)`, and `cat /flag` should print the flag.

## What you are given

A single SUID binary:

```bash
ls -l /challenge/challenge