// SPDX-License-Identifier: GPL-2.0
/*
 * This program test's basic kernel shadow stack support. It enable's shadow
 * stack manual via the arch_prctl(), instead of relying on glibc. It's
 * Makefile doesn't compile with shadow stack support, so it doesn't rely on
 * any particular glibc. As a result it can't do any operations that require
 * special glibc shadow stack support (longjmp(), swapcontext(), etc). Just
 * stick to the basics and hope the compiler doesn't do anything strange.
 */

#define _GNU_SOURCE

#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <x86intrin.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <stdint.h>
#include <signal.h>

#define _STR(x) #x
#define STR(x) _STR(x)

#define SS_SIZE 0x200000

#define __NR_map_shadow_stack 		451

#define ARCH_CET_ENABLE			0x4001
#define ARCH_CET_DISABLE		0x4002
#define ARCH_CET_LOCK			0x4003

#define CET_SHSTK			0x1
#define CET_WRSS			0x2

#if (__GNUC__ < 8) || (__GNUC__ == 8 && __GNUC_MINOR__ < 5)
int main(int argc, char *argv[])
{
	printf("[SKIP]\tCompiler does not support CET.\n");
	return 0;
}
#else
void write_shstk(volatile unsigned long *addr, unsigned long val)
{
#ifdef __i386__
	asm volatile("wrssd %[val], (%[addr])\n" :: [addr] "r" (addr), [val] "r" (val));
#else
	asm volatile("1: wrssq %[val], (%[addr])\n" :: [addr] "r" (addr), [val] "r" (val));
#endif
}

unsigned long get_ssp(void)
{
	unsigned long ret = 0;
#ifdef __i386__
	asm volatile("xor %0, %0; rdsspd %0": "=r" (ret));
#else
	asm volatile("xor %0, %0; rdsspq %0": "=r" (ret));
#endif
	return ret;
}

/*
 * For use in inline enablement of shadow stack.
 *
 * The program can't return from the point where shadow stack get's enabled
 * because there will be no address on the shadow stack. So it can't use
 * syscall() for enablement, since it is a function.
 * 
 * Based on code from nolibc.h. Keep a copy here because this can't pull in all
 * of nolibc.h.
 */
#define ARCH_PRCTL(arg1, arg2)					\
({								\
	long _ret;						\
	register long _num  asm("eax") = __NR_arch_prctl;	\
	register long _arg1 asm("rdi") = (long)(arg1);		\
	register long _arg2 asm("rsi") = (long)(arg2);		\
								\
	asm volatile (						\
		"syscall\n"					\
		: "=a"(_ret)					\
		: "r"(_arg1), "r"(_arg2),			\
		  "0"(_num)					\
		: "rcx", "r11", "memory", "cc"			\
	);							\
	_ret;							\
})

void *create_shstk(unsigned long addr)
{
	return (void *)syscall(__NR_map_shadow_stack, addr, SS_SIZE, SHADOW_STACK_SET_TOKEN);
}

void free_shstk(void *shstk)
{
	munmap(shstk, SS_SIZE);
}

int reset_shstk(void *shstk)
{
	return madvise(shstk, SS_SIZE, MADV_DONTNEED);
}

void try_shstk(unsigned long new_ssp)
{
	unsigned long ssp0, ssp1;

	printf("[INFO]\tnew_ssp = %lx, *new_ssp = %lx\n",
		new_ssp, *((unsigned long *)new_ssp));

	ssp0 = get_ssp();
	printf("[INFO]\tchanging ssp from %lx to %lx\n", ssp0, new_ssp);

	/* Make sure is aligned to 8 bytes */
	if ((ssp0 & 0xf) != 0)
		ssp0 &= -8;

	asm volatile("rstorssp (%0)\n":: "r" (new_ssp));
	asm volatile("saveprevssp");
	ssp1 = get_ssp();
	printf("[INFO]\tssp is now %lx\n", ssp1);

	/* Switch back to original shadow stack */
	ssp0 -= 8;
	asm volatile("rstorssp (%0)\n":: "r" (ssp0));
	asm volatile("saveprevssp");
}

int test_shstk_pivot(void)
{
	void *shstk = create_shstk(0);

	if (shstk == MAP_FAILED) {
		printf("[FAIL]\tError creating shadow stack: %d\n", errno);
		return 1;
	}
	try_shstk((unsigned long)shstk + SS_SIZE - 8);
	free_shstk(shstk);

	printf("[OK]\tShadow stack pivot\n");
	return 0;
}

int test_shstk_faults(void)
{
	volatile unsigned long *shstk = create_shstk(0);

	/* Read shadow stack, test if it's zero to not get read optimized out */
	if (*shstk != 0) {
		printf("1\n");
		goto err;
	}

	/* Wrss memory that was already read. */
	write_shstk(shstk, 1);
	if (*shstk != 1) 
		goto err;

	/* Page out memory, so we can wrss it again. */
	if (reset_shstk((void *)shstk))
		goto err;

	write_shstk(shstk, 1);
	if (*shstk != 1)
		goto err;

	/* Fork and write shadow stack test? */
	printf("[OK]\tShadow stack faults\n");
	return 0;

err:
	return 1;
}

unsigned long saved_ssp;
unsigned long saved_ssp_val;
volatile bool segv_triggered;

void __attribute__ ((noinline)) violate_ss(void)
{
	saved_ssp = get_ssp();
	saved_ssp_val = *(unsigned long*) saved_ssp;

	/* Corrupt shadow stack */
	printf("[INFO]\tCorrupting shadow stack\n");
	write_shstk((void *)saved_ssp, 0);
}

void segv_handler(int signum, siginfo_t *si, void *uc)
{
	printf("[INFO]\tGenerated shadow stack violation successfully\n");

	segv_triggered = true;

	/* Fix shadow stack */
	write_shstk((void *)saved_ssp, saved_ssp_val);
}

int *ptr = NULL;

int test_shstk_violation(void)
{
	struct sigaction sa;

	sa.sa_sigaction = segv_handler;
	if (sigaction(SIGSEGV, &sa, NULL))
		return 1;
	sa.sa_flags = SA_SIGINFO;
	
	segv_triggered = false;

	/* Make sure segv_triggered is set before violate_ss() */
	asm volatile("": : :"memory");

	violate_ss();

	signal(SIGSEGV, SIG_DFL);

	printf("[OK]\tShadow stack violation test\n");

	return !segv_triggered;
}

int test_shstk_alt_stack(void)
{
	printf("[SKIP]\tShadow alt stack not implemented\n");

	return 0;
}


int main(int argc, char *argv[])
{
	int ret = 0;

	if (ARCH_PRCTL(ARCH_CET_ENABLE, CET_SHSTK)) {
		printf("[SKIP]\tCould not enable Shadow stack.\n");
		return 1;
	}

	if (ARCH_PRCTL(ARCH_CET_DISABLE, CET_SHSTK)) {
		ret = 1;
		printf("[FAIL]\tDisabling shadow stack failed\n");
	}

	if (ARCH_PRCTL(ARCH_CET_ENABLE, CET_SHSTK)) {
		printf("[SKIP]\tCould not re-enable Shadow stack.\n");
		return 1;
	}

	if (ARCH_PRCTL(ARCH_CET_ENABLE, CET_WRSS)) {
		printf("[SKIP]\tCould not enable WRSS.\n");
		ret = 1;
		goto out;
	}

	/* Should have succeeded if here, but this is a test, so double check. */
	if (!get_ssp()) {
		printf("[FAIL]\tShadow stack disabled.\n");
		return 1;
	}

	if (test_shstk_pivot()) {
		ret = 1;
		printf("[FAIL]\tShadow stack pivot.\n");
		goto out;
	}

	if (test_shstk_faults()) {
		ret = 1;
		printf("[FAIL]\tShadow stack fault test.\n");
		goto out;
	}

	if (test_shstk_violation()) {
		ret = 1;
		printf("[FAIL]\tShadow stack violation test.\n");
		goto out;
	}

	if (test_shstk_alt_stack()) {
		ret = 1;
		printf("[FAIL]\tShadow alt stack.\n");
	}
out:
	/*
	 * Disable shadow stack before the function returns, or there will be a
	 * shadow stack violation.
	 */
	if (ARCH_PRCTL(ARCH_CET_DISABLE, CET_SHSTK)) {
		ret = 1;
		printf("[FAIL]\tDisabling shadow stack failed\n");
	}

	return ret;
}
#endif
