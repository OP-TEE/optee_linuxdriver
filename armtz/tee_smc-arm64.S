/*
 * Copyright (c) 2014, Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <linux/linkage.h>

	.text

#define SMC_PARAM_W0_OFFS	0
#define SMC_PARAM_W2_OFFS	8
#define SMC_PARAM_W4_OFFS	16
#define SMC_PARAM_W6_OFFS	24

	/* void tee_smc_call(struct smc_param *param); */
	.globl	tee_smc_call
ENTRY(tee_smc_call)
	stp	x28, x30, [sp, #-16]!
	mov	x28, x0
	ldp	w0, w1, [x28, #SMC_PARAM_W0_OFFS]
	ldp	w2, w3, [x28, #SMC_PARAM_W2_OFFS]
	ldp	w4, w5, [x28, #SMC_PARAM_W4_OFFS]
	ldp	w6, w7, [x28, #SMC_PARAM_W6_OFFS]
	smc	#0
	stp	w0, w1, [x28, #SMC_PARAM_W0_OFFS]
	stp	w2, w3, [x28, #SMC_PARAM_W2_OFFS]
	ldp	x28, x30, [sp], #16
	ret
ENDPROC(tee_smc_call)
