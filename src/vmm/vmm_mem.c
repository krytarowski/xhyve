/*-
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (c) 2015 xhyve developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <stdint.h>
#include <stdlib.h>
#if defined(__APPLE__)
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#elif defined(__NetBSD__)
#include <nvmm.h>
#endif
#include <xhyve/support/misc.h>
#include <xhyve/vmm/vmm_mem.h>

int
vmm_mem_init(void)
{
	return (0);
}

void *
vmm_mem_alloc(uint64_t gpa, size_t size, uint64_t prot)
{
	void *object;
#if defined(__APPLE__)
    hv_memory_flags_t hvProt;
#elif defined(__NetBSD__)
	nvmm_prot_t vhProt;
#endif

	object = valloc(size);

	if (!object) {
		xhyve_abort("vmm_mem_alloc failed\n");
	}

#if defined(__APPLE__)
    hvProt = (prot & XHYVE_PROT_READ) ? HV_MEMORY_READ : 0;
    hvProt |= (prot & XHYVE_PROT_WRITE) ? HV_MEMORY_WRITE : 0;
    hvProt |= (prot & XHYVE_PROT_EXECUTE) ? HV_MEMORY_EXEC : 0;
#elif defined(__NetBSD__)
	hvProt = (prot & XHYVE_PROT_READ) ? NVMM_PROT_READ : 0;
	hvProt = (prot & XHYVE_PROT_WRITE) ? NVMM_PROT_WRITE : 0;
	hvProt = (prot & XHYVE_PROT_EXECUTE) ? NVMM_PROT_EXEC : 0;
#endif

	if (hv_vm_map(object, gpa, size, hvProt))
	{
		xhyve_abort("hv_vm_map failed\n");
	}

	return object;
}

void
vmm_mem_free(uint64_t gpa, size_t size, void *object)
{
	hv_vm_unmap(gpa, size);
	free(object);
}
