/*
 * victim.c - a TOY self-protection ("toy RASP") for teaching runtime integrity.
 *
 * This program simulates the core enforcement pattern used by real anti-tamper /
 * RASP products:
 *
 *      detect hostile environment  ->  reach a verdict  ->  CALL a kill routine
 *
 * The whole point of the lab is to show WHY that pattern is fragile when the
 * protected code does NOT verify its own integrity at runtime: on a machine where
 * an attacker can write another process's memory (e.g. root + /proc/<pid>/mem),
 * the single CALL that enforces the verdict can be neutralised in place, and the
 * program keeps running even though the detection still fires.
 *
 * Build:
 *   gcc -O0 -fno-inline -fno-omit-frame-pointer -no-pie -o victim src/victim.c      # vulnerable
 *   gcc -O0 -fno-inline -fno-omit-frame-pointer -no-pie -DWITH_SELFCRC \
 *       -o victim_hardened src/victim.c                                             # mitigated
 *
 * (-no-pie keeps the demo addresses stable and the call a plain direct CALL, which
 *  makes the teaching obvious. The technique itself does not depend on it.)
 *
 * This file is 100% original and self-contained. It targets nothing but itself.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#ifndef ARM_SECONDS
#define ARM_SECONDS 6   /* "arming window": time for the attacker tool to act */
#endif

/* Region of security_verdict() that a self-integrity check would protect.
 * Must be large enough to cover the enforcement CALL site. */
#define GUARD_LEN 96

/* --------------------------------------------------------------------------
 * The "kill switch". In a real product this is a panic()/abort()/raise() path.
 * Here it is a deliberate, honest SIGKILL of our own process.
 * -------------------------------------------------------------------------- */
__attribute__((noinline, used))
static void enforce_termination(const char *why)
{
    fprintf(stderr, "[toy-rasp] verdict=HOSTILE (%s) -> terminating process\n", why);
    fflush(stderr);
    raise(SIGKILL);
    _exit(42); /* not reached */
}

/* --------------------------------------------------------------------------
 * The "detection". A real product probes for root, emulator, debugger, hooks,
 * etc. We return a fixed verdict so the demo is 100% deterministic.
 * -------------------------------------------------------------------------- */
__attribute__((noinline, used))
static int environment_is_hostile(void)
{
    return 1; /* pretend we are on a rooted / instrumented device */
}

/* --------------------------------------------------------------------------
 * A tiny CRC32 (IEEE) used ONLY by the hardened build to check that its own
 * code bytes were not modified. This is the mitigation the lab demonstrates.
 * -------------------------------------------------------------------------- */
__attribute__((used))
static uint32_t crc32_region(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= b[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (-(int32_t)(crc & 1)));
    }
    return ~crc;
}

#ifdef WITH_SELFCRC
static uint32_t g_text_baseline; /* captured at startup, over clean bytes */
#endif

/* --------------------------------------------------------------------------
 * The verdict step. environment_is_hostile() -> enforce_termination().
 * The CALL to enforce_termination() is the instruction the attacker neutralises.
 * -------------------------------------------------------------------------- */
__attribute__((noinline, used))
static void security_verdict(void)
{
#ifdef WITH_SELFCRC
    /* Self-integrity: if our own .text bytes changed, the enforcement CALL may
     * have been patched out. Detect that and enforce anyway. */
    if (crc32_region((const void *)security_verdict, GUARD_LEN) != g_text_baseline)
        enforce_termination("code-integrity-mismatch");
#endif
    if (environment_is_hostile())
        enforce_termination("environment-check");   /* <<< THE ENFORCEMENT CALL */
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[victim] pid=%d\n", (int)getpid());
    printf("[victim] &security_verdict   = %p\n", (void *)security_verdict);
    printf("[victim] &enforce_termination= %p\n", (void *)enforce_termination);
#ifdef WITH_SELFCRC
    g_text_baseline = crc32_region((const void *)security_verdict, GUARD_LEN);
    printf("[victim] self-CRC ENABLED, baseline=0x%08x\n", g_text_baseline);
#else
    printf("[victim] self-CRC DISABLED (vulnerable build)\n");
#endif
    fprintf(stderr, "[victim] arming window: %ds -- run the patcher now\n", ARM_SECONDS);
    sleep(ARM_SECONDS);

    for (int t = 0;; t++) {
        security_verdict();                 /* dies here unless neutralised */
        printf("[victim] tick=%d survived (verdict did not terminate us)\n", t);
        sleep(2);
    }
    return 0;
}
