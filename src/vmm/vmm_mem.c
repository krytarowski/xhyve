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

#include <sys/types.h>
#include <sys/mman.h>
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

#if !defined(__NetBSD__)
int
vmm_mem_init(void *arg)
{
	return (0);
}

void *
vmm_mem_alloc(void *arg, uint64_t gpa, size_t size, uint64_t prot)
{
	void *object;
#if defined(__APPLE__)
    hv_memory_flags_t hvProt;
#elif defined(__NetBSD__)
	int hvProt;
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
	hvProt = (prot & XHYVE_PROT_READ) ? PROT_READ : 0;
	hvProt = (prot & XHYVE_PROT_WRITE) ? PROT_WRITE : 0;
	hvProt = (prot & XHYVE_PROT_EXECUTE) ? PROT_EXEC : 0;
#endif

#if defined(__APPLE__)
	if (hv_vm_map(object, gpa, size, hvProt))
#elif defined(__NetBSD__)
	if (nvmm_gpa_map(NULL /* XXX */, (uintptr_t)object, gpa, size, hvProt))
#endif
	{
		xhyve_abort("hv_vm_map failed\n");
	}

	return object;
}

void
vmm_mem_free(void *arg, uint64_t gpa, size_t size, void *object)
{
#if defined(__APPLE__)
	hv_vm_unmap(gpa, size);
#elif defined(__NetBSD__)
	if (nvmm_gpa_unmap(NULL /* XXX */, object, gpa, size))
#endif

	free(object);
}
#endif
