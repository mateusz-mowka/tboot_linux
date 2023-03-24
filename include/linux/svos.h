/***************************************************************************/
/**                   I N T E L  C O N F I D E N T I A L                  **/
/***************************************************************************/
/**                                                                       **/
/**  Copyright (c) 2005 Intel Corporation                                 **/
/**                                                                       **/
/**  This program contains proprietary and confidential information.      **/
/**  All rights reserved.                                                 **/
/**                                                                       **/
/***************************************************************************/
/**                   I N T E L  C O N F I D E N T I A L                  **/
/***************************************************************************/

// Provides definitions that are unique to SVOS.

#ifndef _LINUX_SVOS_H
#define _LINUX_SVOS_H

#include <asm/ptrace.h>
#include <linux/nodemask.h>
#include <linux/numa.h>

/* Common definitions for SVOS machine check handlers */
#define SVOS_MACHINE_CHECK_RESULT_DEFAULT   0           /* SVOS machine check return code: default behavior */
#define SVOS_MACHINE_CHECK_RESULT_PANIC     1           /* SVOS machine check return code: override - panic */
#define SVOS_MACHINE_CHECK_RESULT_NOPANIC   2           /* SVOS machine check return code: override - panic */

#ifdef __KERNEL__
#include <linux/ptrace.h>
#include <linux/list.h>

#define SVOS_ANNOUNCE_MESSAGE                                                                    \
"********************************************************************************************\n" \
"*                                     SVOS-NEXT                                            *\n" \
"*                                                                                          *\n" \
"*      NOTE: SVOS contains Intel Top Secret information.  For Intel internal use only.     *\n" \
"********************************************************************************************\n"

#define SVOS_RAS_ANNOUNCE_MESSAGE                                                                \
"********************************************************************************************\n" \
"*                                                                                          *\n" \
"*  NOTE: Error correction is enabled (svos_enable_ras) - ONLY to be used for RAS testing!  *\n" \
"*                                                                                          *\n" \
"********************************************************************************************\n"

/*
 * Indices of miscellaneous automatically registered interrupt resources
 * (svMisc interrupt category).
 */
enum {
	INT_MISC_MCH,			/* Machine check */
	INT_MISC_CMCI,			/* Correctable machine check interrupt */
	INT_MISC_THERMAL,		/* thermal interrupt */
	N_AUTO_REG_MISC_INT_RESOURCES
};

extern int (*svMiscIntHandlerKernelP)(int irq, void *interrupt_res, struct pt_regs *regs);
/* Pointer to vector of interrupt resources for kernel's use in calling back to svfs.*/
extern void ***svExternalInterruptDataKernelP;
/* Boolean for SVOS user-registered machine check handlers to indicate that system should be bugchecked. */
extern int svMCHContinue;

static inline int svos_interrupt_callback(int index, struct pt_regs *regs)
{
        int     returnCode = 0;
        if ((svMiscIntHandlerKernelP != NULL) && (svExternalInterruptDataKernelP != NULL)) {
                if (*svExternalInterruptDataKernelP[index] != NULL) {
                        returnCode =
                                (*svMiscIntHandlerKernelP) (
                                        0,
                                        svExternalInterruptDataKernelP[index],
                                        regs
                                );
                }
        }
        return(returnCode);
}

static inline int svos_process_mce(struct pt_regs *regs)
{
        int svMachineCheckHandlers;
        int returnCode;

        /* Initialize.  Prepare to determine if a trap handler is registered. */
        svMachineCheckHandlers = 0;
        returnCode = SVOS_MACHINE_CHECK_RESULT_DEFAULT;

        /* Call the application-provided machine check handlers if they are registered. */
        if (svMiscIntHandlerKernelP != NULL) {
                svMachineCheckHandlers = svos_interrupt_callback(INT_MISC_MCH, regs);
        }

        /* If at least one SVOS-application provided handler was registered, treat the
           handlers' indication of recoverability (via svMCHContinue) as definitive. */
        if (svMachineCheckHandlers) {
                /* At least one trap handler was registered.  System will be treated as
                   recoverable, unless one of the handlers indicated that the system must
                   have panic invoked. */
                if (svMCHContinue) {
                        /* Handlers indicate system should continue. */
                        returnCode = SVOS_MACHINE_CHECK_RESULT_NOPANIC;
                } else {
                        /* At least one handler requested that the system be panic'd.*/
                        returnCode = SVOS_MACHINE_CHECK_RESULT_PANIC;
                }
        }
        return(returnCode);
}

struct svos_node_memory {
	int initialized;
	u64 os_base;
        unsigned long before_after_size;
        unsigned long after_above_size;
        unsigned long total_size;
        unsigned long tunables[6];  /* only using 3 now */
	struct list_head active_chunks;
};

extern struct e820_table e820_svos;
extern unsigned long svos_adjgap(unsigned long);
extern void svos_parse_mem(char *);
extern void svos_mem_init(void);
extern void svos_setup_svos_e820(void);
extern int svos_trap_hook(int, struct pt_regs *);
extern int svos_enable_ras_errorcorrect;

#endif // __KERNEL__
#endif // _LINUX_SVOS_H
