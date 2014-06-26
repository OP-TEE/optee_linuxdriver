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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
#include <linux/linkage.h>

	.text

#define SMC_PARAM_X0_OFFS	0
#define SMC_PARAM_X2_OFFS	16
#define SMC_PARAM_X4_OFFS	32
#define SMC_PARAM_X6_OFFS	48

	/* void tee_smc_call64(struct smc_param64 *param); */
	.globl	tee_smc_call64
ENTRY(tee_smc_call64)
	stp	x28, x30, [sp, #-16]!
	mov	x28, x0
	ldp	x0, x1, [x28, #SMC_PARAM_X0_OFFS]
	ldp	x2, x3, [x28, #SMC_PARAM_X2_OFFS]
	ldp	x4, x5, [x28, #SMC_PARAM_X4_OFFS]
	ldp	x6, x7, [x28, #SMC_PARAM_X6_OFFS]
	smc	#0
	stp	x0, x1, [x28, #SMC_PARAM_X0_OFFS]
	stp	x2, x3, [x28, #SMC_PARAM_X2_OFFS]
	ldp	x28, x30, [sp], #16
	ret
ENDPROC(tee_smc_call64)
