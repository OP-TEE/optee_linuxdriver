/*
* Copyright (C) STMicroelectronics 2014. All rights reserved.
*
* This code is STMicroelectronics proprietary and confidential.
* Any use of the code for whatever purpose is subject to
* specific written permission of STMicroelectronics SA.
*/

#include <linux/linkage.h>

.text
.balign 4
.code 32

	/* void tee_smc_call(struct smc_param *param); */
	.globl	tee_smc_call
ENTRY(tee_smc_call)
	push	{r4-r8, lr}
	mov	r8, r0
	ldm	r8, {r0-r7}
.arch_extension sec
	smc	#0
	stm	r8, {r0-r7}
	pop	{r4-r8, pc}
ENDPROC(tee_smc_call)
