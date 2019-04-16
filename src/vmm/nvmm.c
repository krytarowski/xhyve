#if defined(__NetBSD__)

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <xhyve/support/misc.h>
#include <xhyve/support/specialreg.h>
#include <xhyve/vmm/vmm.h>
#include <xhyve/vmm/vmm_lapic.h>
#include <xhyve/vmm/io/vatpic.h>
#include <xhyve/vmm/io/vlapic.h>
#include <xhyve/vmm/io/vlapic_priv.h>

#include <nvmm.h>

static int debug = 2;
        
#define DPRINTF(fmt, ...) do { if (debug) printf("%s:%d:%s(): " fmt "\r", __FILE__, __LINE__, __func__, ## __VA_ARGS__); } while (0)

static void
vmm_vcpu_dump(struct nvmm_machine *mach, nvmm_cpuid_t cpuid)
{
	if (debug > 1)
		return;

        struct nvmm_x64_state state;
        uint16_t *attr;   
        size_t i;
        int ret;

        const char *segnames[] = {
                "ES", "CS", "SS", "DS", "FS", "GS", "GDT", "IDT", "LDT", "TR"
        };

        ret = nvmm_vcpu_getstate(mach, cpuid, &state, NVMM_X64_STATE_ALL);
        if (ret == -1)    
		abort();

        printf("+ VCPU id=%d\n\r", (int)cpuid);
        printf("| -> RIP=%"PRIx64"\n\r", state.gprs[NVMM_X64_GPR_RIP]);
        printf("| -> RSP=%"PRIx64"\n\r", state.gprs[NVMM_X64_GPR_RSP]);
        printf("| -> RAX=%"PRIx64"\n\r", state.gprs[NVMM_X64_GPR_RAX]);
        printf("| -> RBX=%"PRIx64"\n\r", state.gprs[NVMM_X64_GPR_RBX]);

        printf("| -> RCX=%"PRIx64"\n\r", state.gprs[NVMM_X64_GPR_RCX]);                                                                                        
        printf("| -> RFLAGS=%p\n\r", (void *)state.gprs[NVMM_X64_GPR_RFLAGS]);
        for (i = 0; i < NVMM_X64_NSEG; i++) {
                attr = (uint16_t *)&state.segs[i].attrib;
                printf("| -> %s: sel=0x%x base=%"PRIx64", limit=%x, attrib=%x\n\r",
                    segnames[i],
                    state.segs[i].selector,
                    state.segs[i].base,
                    state.segs[i].limit,
                    *attr);                                                                                                                                  
        }
        printf("| -> MSR_EFER=%"PRIx64"\n\r", state.msrs[NVMM_X64_MSR_EFER]);
        printf("| -> CR0=%"PRIx64"\n\r", state.crs[NVMM_X64_CR_CR0]);
        printf("| -> CR3=%"PRIx64"\n\r", state.crs[NVMM_X64_CR_CR3]);
        printf("| -> CR4=%"PRIx64"\n\r", state.crs[NVMM_X64_CR_CR4]);
        printf("| -> CR8=%"PRIx64"\n\r", state.crs[NVMM_X64_CR_CR8]);

        return;
}

struct apic_page {
        uint32_t reg[XHYVE_PAGE_SIZE / 4];
};
static_assert(sizeof(struct apic_page) == XHYVE_PAGE_SIZE);

struct vlapic_vtx {
        struct vlapic vlapic;
        struct pir_desc *pir_desc;
        struct vmx *vmx;
};

struct vcpu {
	bool vcpu_dirty;
};

struct vmx {
	struct apic_page apic_page[VM_MAXCPU]; /* one apic page per vcpu */
	struct nvmm_machine mach;
	struct vm *vm;
};

static const uint64_t nvmm_x86_regs_segs[] = {
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RAX */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RBX */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RCX */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RDX */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RSI */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RDI */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RBP */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_R8  */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_R9  */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_R10 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_R11 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_R12 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_R13 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_R14 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_R15 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_CR0 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_CR3 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_CR4 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_DR7 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RSP */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RIP */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_RFLAGS */
        NVMM_X64_SEG_ES,  /* VM_REG_GUEST_ES */
        NVMM_X64_SEG_CS,  /* VM_REG_GUEST_CS */
        NVMM_X64_SEG_SS,  /* VM_REG_GUEST_SS */
	NVMM_X64_SEG_DS,  /* VM_REG_GUEST_DS */
        NVMM_X64_SEG_FS,  /* VM_REG_GUEST_FS */
        NVMM_X64_SEG_GS,  /* VM_REG_GUEST_GS */
        NVMM_X64_SEG_LDT, /* VM_REG_GUEST_LDTR */
        NVMM_X64_SEG_TR,  /* VM_REG_GUEST_TR */
        NVMM_X64_SEG_IDT, /* VM_REG_GUEST_IDTR */
        NVMM_X64_SEG_GDT, /* VM_REG_GUEST_GDTR */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_EFER */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_CR2 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_PDPTE0 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_PDPTE1 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_PDPTE2 */
        NVMM_X64_NSEG,    /* VM_REG_GUEST_PDPTE3 */
        NVMM_X64_NSEG     /* VM_REG_GUEST_INTR_SHADOW */
			  /* VM_REG_LAST */

};

static const uint64_t nvmm_x86_regs_gprs[] = {
        NVMM_X64_GPR_RAX, /* VM_REG_GUEST_RAX */
        NVMM_X64_GPR_RBX, /* VM_REG_GUEST_RBX */
        NVMM_X64_GPR_RCX, /* VM_REG_GUEST_RCX */
        NVMM_X64_GPR_RDX, /* VM_REG_GUEST_RDX */
        NVMM_X64_GPR_RSI, /* VM_REG_GUEST_RSI */
        NVMM_X64_GPR_RDI, /* VM_REG_GUEST_RDI */
        NVMM_X64_GPR_RBP, /* VM_REG_GUEST_RBP */
        NVMM_X64_GPR_R8,  /* VM_REG_GUEST_R8  */
        NVMM_X64_GPR_R9,  /* VM_REG_GUEST_R9  */
        NVMM_X64_GPR_R10, /* VM_REG_GUEST_R10 */
        NVMM_X64_GPR_R11, /* VM_REG_GUEST_R11 */
        NVMM_X64_GPR_R12, /* VM_REG_GUEST_R12 */
        NVMM_X64_GPR_R13, /* VM_REG_GUEST_R13 */
        NVMM_X64_GPR_R14, /* VM_REG_GUEST_R14 */
        NVMM_X64_GPR_R15, /* VM_REG_GUEST_R15 */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_CR0 */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_CR3 */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_CR4 */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_DR7 */
        NVMM_X64_GPR_RSP, /* VM_REG_GUEST_RSP */
        NVMM_X64_GPR_RIP, /* VM_REG_GUEST_RIP */
        NVMM_X64_GPR_RFLAGS,/* VM_REG_GUEST_RFLAGS */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_ES */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_CS */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_SS */
	NVMM_X64_NGPR,    /* VM_REG_GUEST_DS */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_FS */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_GS */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_LDTR */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_TR */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_IDTR */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_GDTR */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_EFER */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_CR2 */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_PDPTE0 */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_PDPTE1 */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_PDPTE2 */
        NVMM_X64_NGPR,    /* VM_REG_GUEST_PDPTE3 */
        NVMM_X64_NGPR     /* VM_REG_GUEST_INTR_SHADOW */
			  /* VM_REG_LAST */

};

static const uint64_t nvmm_x86_regs_crs[] = {
        NVMM_X64_NCR,     /* VM_REG_GUEST_RAX */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RBX */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RCX */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RDX */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RSI */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RDI */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RBP */
        NVMM_X64_NCR,     /* VM_REG_GUEST_R8  */
        NVMM_X64_NCR,     /* VM_REG_GUEST_R9  */
        NVMM_X64_NCR,     /* VM_REG_GUEST_R10 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_R11 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_R12 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_R13 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_R14 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_R15 */
        NVMM_X64_CR_CR0,  /* VM_REG_GUEST_CR0 */
        NVMM_X64_CR_CR3,  /* VM_REG_GUEST_CR3 */
        NVMM_X64_CR_CR4,  /* VM_REG_GUEST_CR4 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_DR7 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RSP */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RIP */
        NVMM_X64_NCR,     /* VM_REG_GUEST_RFLAGS */
        NVMM_X64_NCR,     /* VM_REG_GUEST_ES */
        NVMM_X64_NCR,     /* VM_REG_GUEST_CS */
        NVMM_X64_NCR,     /* VM_REG_GUEST_SS */
	NVMM_X64_NCR,     /* VM_REG_GUEST_DS */
        NVMM_X64_NCR,     /* VM_REG_GUEST_FS */
        NVMM_X64_NCR,     /* VM_REG_GUEST_GS */
        NVMM_X64_NCR,     /* VM_REG_GUEST_LDTR */
        NVMM_X64_NCR,     /* VM_REG_GUEST_TR */
        NVMM_X64_NCR,     /* VM_REG_GUEST_IDTR */
        NVMM_X64_NCR,     /* VM_REG_GUEST_GDTR */
        NVMM_X64_NCR,     /* VM_REG_GUEST_EFER */
        NVMM_X64_CR_CR2,  /* VM_REG_GUEST_CR2 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_PDPTE0 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_PDPTE1 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_PDPTE2 */
        NVMM_X64_NCR,     /* VM_REG_GUEST_PDPTE3 */
        NVMM_X64_NCR      /* VM_REG_GUEST_INTR_SHADOW */
			  /* VM_REG_LAST */

};

static const uint64_t nvmm_x86_regs_drs[] = {
        NVMM_X64_NDR,     /* VM_REG_GUEST_RAX */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RBX */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RCX */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RDX */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RSI */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RDI */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RBP */
        NVMM_X64_NDR,     /* VM_REG_GUEST_R8  */
        NVMM_X64_NDR,     /* VM_REG_GUEST_R9  */
        NVMM_X64_NDR,     /* VM_REG_GUEST_R10 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_R11 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_R12 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_R13 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_R14 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_R15 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_CR0 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_CR3 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_CR4 */
        NVMM_X64_DR_DR7,  /* VM_REG_GUEST_DR7 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RSP */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RIP */
        NVMM_X64_NDR,     /* VM_REG_GUEST_RFLAGS */
        NVMM_X64_NDR,     /* VM_REG_GUEST_ES */
        NVMM_X64_NDR,     /* VM_REG_GUEST_CS */
        NVMM_X64_NDR,     /* VM_REG_GUEST_SS */
	NVMM_X64_NDR,     /* VM_REG_GUEST_DS */
        NVMM_X64_NDR,     /* VM_REG_GUEST_FS */
        NVMM_X64_NDR,     /* VM_REG_GUEST_GS */
        NVMM_X64_NDR,     /* VM_REG_GUEST_LDTR */
        NVMM_X64_NDR,     /* VM_REG_GUEST_TR */
        NVMM_X64_NDR,     /* VM_REG_GUEST_IDTR */
        NVMM_X64_NDR,     /* VM_REG_GUEST_GDTR */
        NVMM_X64_NDR,     /* VM_REG_GUEST_EFER */
        NVMM_X64_NDR,     /* VM_REG_GUEST_CR2 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_PDPTE0 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_PDPTE1 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_PDPTE2 */
        NVMM_X64_NDR,     /* VM_REG_GUEST_PDPTE3 */
        NVMM_X64_NDR      /* VM_REG_GUEST_INTR_SHADOW */
			  /* VM_REG_LAST */

};

static const uint64_t nvmm_x86_regs_msrs[] = {
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RAX */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RBX */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RCX */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RDX */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RSI */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RDI */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RBP */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_R8  */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_R9  */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_R10 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_R11 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_R12 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_R13 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_R14 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_R15 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_CR0 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_CR3 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_CR4 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_DR7 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RSP */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RIP */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_RFLAGS */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_ES */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_CS */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_SS */
	NVMM_X64_NMSR,    /* VM_REG_GUEST_DS */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_FS */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_GS */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_LDTR */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_TR */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_IDTR */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_GDTR */
        NVMM_X64_MSR_EFER,/* VM_REG_GUEST_EFER */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_CR2 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_PDPTE0 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_PDPTE1 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_PDPTE2 */
        NVMM_X64_NMSR,    /* VM_REG_GUEST_PDPTE3 */
        NVMM_X64_NMSR     /* VM_REG_GUEST_INTR_SHADOW */
			  /* VM_REG_LAST */

};

static int
vmx_init(void)
{
	struct nvmm_capability cap;
	int ret;

	ret = nvmm_capability(&cap);
	if (ret == -1) {
		xhyve_abort("NVMM: No accelerator found, error=%d\n", errno);
	}
	if (cap.version != 1) {
		xhyve_abort("NVMM: Unsupported version %lu", cap.version);
	}
	if (cap.state_size != sizeof(struct nvmm_x64_state)) {
		xhyve_abort("NVMM: Wrong state size %zu", cap.state_size);
	}

	DPRINTF("NetBSD Virtual Machine Monitor accelerator is available\n");

	return 0;
}

static int
vmx_cleanup(void)
{
	DPRINTF("vmx_cleanup()\n");

        return (0);
}

static void
nvmm_io_callback(struct nvmm_io *io)
{
	DPRINTF("nvmm_io_callback()\n");
}

static void
nvmm_mem_callback(struct nvmm_mem *mem)
{
	DPRINTF("nvmm_mem_callback() mem.gpa=%" PRIx64 ", mem.write=%s, size=%zu, data=%p\n", mem->gpa, mem->write ? "true" : "false", mem->size, mem->data);

	abort();

	if (mem->write) {
		memcpy(hva, mem->data, mem->size);
	} else {
		memcpy(mem->data, hva, mem->size);
	}
}

static const struct nvmm_callbacks nvmm_callbacks = {
	.io = nvmm_io_callback,
	.mem = nvmm_mem_callback
};

static void *
vmx_vm_init(struct vm *vm)
{
	struct nvmm_x86_conf_cpuid cpuid;
	struct vmx *vmx;
	int ret;

	DPRINTF("vmx_vm_init()\n");

	vmx = malloc(sizeof(struct vmx));
	if (vmx == NULL) {
		xhyve_abort("NVMM: Cannot allocate memory for the vmx struct, error=%d", errno);
	}
	memset(vmx, 0, sizeof(struct vmx));
	vmx->vm = vm;

	ret = nvmm_machine_create(&vmx->mach);
	if (ret == -1) {
		xhyve_abort("NVMM: Machine creation failed, error=%d", errno);
	}

	// Configure acceleration
	memset(&cpuid, 0, sizeof(cpuid));
	cpuid.leaf = 0x00000001;
	cpuid.del.edx = CPUID_MCE | CPUID_MCA | CPUID_MTRR;
	ret = nvmm_machine_configure(&vmx->mach, NVMM_X86_CONF_CPUID, &cpuid);
	if (ret == -1) {
		xhyve_abort("NVMM: Machine configuration failed, error=%d", errno);
	}

	nvmm_callbacks_register(&nvmm_callbacks);

	DPRINTF("NetBSD Virtual Machine Monitor accelerator is operational\n");

	return (vmx);
}

static int
vmx_vcpu_init(void *arg, int vcpuid)
{
	struct vmx *vmx;
	int ret;

	DPRINTF("vmx_vcpu_init(vcpuid=%d)\n", vcpuid);

	vmx = (struct vmx *)arg;

	ret = nvmm_vcpu_create(&vmx->mach, vcpuid);
	if (ret == -1) {
		xhyve_abort("NVMM: Failed to create a virtual processor, error=%d\n", errno);
	}

	return 0;
}

static int
nvmm_handle_memory(struct nvmm_machine *mach, int vcpu, struct nvmm_exit *exit)
{
	int ret;

	DPRINTF("nvmm_handle_memory(vcpuid=%d)\n", vcpu);

	ret = nvmm_assist_mem(mach, vcpu, exit);
	if (ret == -1) {
		xhyve_abort("NVMM: Mem Assist Failed [gpa=%p]", (void *)exit->u.mem.gpa);
	}

	return ret;
}

static int
nvmm_handle_io(struct nvmm_machine *mach, struct nvmm_vcpu *vcpu,
	struct nvmm_exit *exit)
{
	int ret;

	DPRINTF("nvmm_handle_io(vcpuid=%d)\n", vcpu);

	ret = nvmm_assist_io(mach, vcpu, exit);
	if (ret == -1) {
		xhyve_abort("NVMM: I/O Assist Failed [port=%d]",
			(int)exit->u.io.port);
	}

	return ret;
}

static int
nvmm_handle_msr(struct nvmm_machine *mach, int vcpu,
	struct nvmm_exit *exit)
{
	DPRINTF("nvmm_handle_msr(vcpuid=%d)\n", vcpu);

	return 0;
}

static int
vmx_run(void *arg, int vcpu, register_t rip, void *rendezvous_cookie,
		void *suspend_cookie)
{
	struct vmx *vmx;
	struct nvmm_x64_state state;
	struct nvmm_exit exit;
	int ret;

	DPRINTF("vmx_run(vcpuid=%d, rip=%" PRIxREGISTER ")\n", vcpu, rip);

	vmx = (struct vmx *)arg;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);
	state.gprs[NVMM_X64_GPR_RIP] = rip;
	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	vmm_vcpu_dump((void *)&vmx->mach, vcpu);

	while (1) {
		nvmm_vcpu_run(&vmx->mach, vcpu, &exit);

		switch (exit.reason) {
		case NVMM_EXIT_NONE:
			break;
		case NVMM_EXIT_MEMORY:
			ret = nvmm_handle_memory(&vmx->mach, vcpu, &exit);
			break;
		case NVMM_EXIT_IO:
			abort();
			ret = nvmm_handle_io(&vmx->mach, vcpu, &exit);
			break;
		case NVMM_EXIT_MSR:
			abort();
			ret = nvmm_handle_msr(&vmx->mach, vcpu, &exit);
			break;
		case NVMM_EXIT_INT_READY:
		case NVMM_EXIT_NMI_READY:
			abort();
			break;
		case NVMM_EXIT_MONITOR:
		case NVMM_EXIT_MWAIT:
		case NVMM_EXIT_MWAIT_COND:
			// XXX
			abort();
			break;
		case NVMM_EXIT_HALTED:
			// XXX
			abort();
			break;
		case NVMM_EXIT_SHUTDOWN:
			// XXX
			abort();
			ret = 1;
			break;
		default:
			abort();
			xhyve_abort("NVMM: Unexpected VM exit code %lx", exit.reason);
			// XXX
			break;
		}
	}

	return 0;
}

static void
vmx_vm_cleanup(void *arg)
{
	DPRINTF("vmx_vm_cleanup()\n");
}

static void
vmx_vcpu_cleanup(void *arg, int vcpuid)
{
	DPRINTF("vmx_vcpu_cleanup(vcpu=%d)\n", vcpuid);
}

static int
vmx_getreg_seg_desc(struct vmx *vmx, int vcpu, int reg, struct seg_desc *desc)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_getreg_seg(vcpu=%d, reg=%d)\n", vcpu, reg);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_SEGS);

	memcpy(&state.segs[nvmm_x86_regs_segs[reg]].attrib, &desc->access, sizeof(desc->access));
	state.segs[nvmm_x86_regs_segs[reg]].limit = desc->limit;
	state.segs[nvmm_x86_regs_segs[reg]].base = desc->base;

	return 0;
}

static int
vmx_getreg_seg(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_getreg_gpr(vcpu=%d, reg=%d)\n", vcpu, reg);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	*retval = (uint64_t)state.segs[nvmm_x86_regs_segs[reg]].selector;

	return 0;
}

static int
vmx_getreg_gpr(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_getreg_gpr(vcpu=%d, reg=%d)\n", vcpu, reg);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	*retval = state.gprs[nvmm_x86_regs_gprs[reg]];

	return 0;
}

static int
vmx_getreg_cr(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_getreg_cr(vcpu=%d, reg=%d)\n", vcpu, reg);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_CRS);

	*retval = state.crs[nvmm_x86_regs_crs[reg]];

	return 0;
}

static int
vmx_getreg_dr(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_getreg_dr(vcpu=%d, reg=%d)\n", vcpu, reg);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_DRS);

	*retval = state.drs[nvmm_x86_regs_drs[reg]];

	return 0;
}

static int
vmx_getreg_msr(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_getreg_msr(vcpu=%d, reg=%d)\n", vcpu, reg);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_MSRS);

	*retval = state.msrs[nvmm_x86_regs_msrs[reg]];

	return 0;
}

static int
vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval)
{
	struct vmx *vmx;

	DPRINTF("vmx_getreg(vcpu=%d, reg=%d)\n", vcpu, reg);

	vmx = (struct vmx *)arg;

	switch (reg) {
	case VM_REG_GUEST_RAX:
	case VM_REG_GUEST_RBX:
	case VM_REG_GUEST_RCX:
	case VM_REG_GUEST_RDX:
	case VM_REG_GUEST_RSI:
	case VM_REG_GUEST_RDI:
	case VM_REG_GUEST_RBP:
	case VM_REG_GUEST_R8:
	case VM_REG_GUEST_R9:
	case VM_REG_GUEST_R10:
	case VM_REG_GUEST_R11:
	case VM_REG_GUEST_R12:
	case VM_REG_GUEST_R13:
	case VM_REG_GUEST_R14:
	case VM_REG_GUEST_R15:
	case VM_REG_GUEST_RIP:
	case VM_REG_GUEST_RFLAGS:
	case VM_REG_GUEST_RSP:
		return vmx_getreg_gpr(vmx, vcpu, reg, retval);

	case VM_REG_GUEST_CR0:
	case VM_REG_GUEST_CR3:
	case VM_REG_GUEST_CR4:
	case VM_REG_GUEST_CR2:
		return vmx_getreg_cr(vmx, vcpu, reg, retval);

	case VM_REG_GUEST_DR7:
		return vmx_getreg_dr(vmx, vcpu, reg, retval);

	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_GDTR:
		return vmx_getreg_seg(vmx, vcpu, reg, retval);

	case VM_REG_GUEST_EFER:
		return vmx_getreg_msr(vmx, vcpu, reg, retval);

	case VM_REG_GUEST_PDPTE0:
	case VM_REG_GUEST_PDPTE1:
	case VM_REG_GUEST_PDPTE2:
	case VM_REG_GUEST_PDPTE3:
		abort();

	case VM_REG_GUEST_INTR_SHADOW:
		abort();

	case VM_REG_LAST:
	default:
		abort();
		break;
	};


	return 0;
}


static int
vmx_setreg_seg_desc(struct vmx *vmx, int vcpu, int reg, struct seg_desc *desc)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_setreg_seg(vcpu=%d, reg=%d)\n", vcpu, reg);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_SEGS);

	memcpy(&desc->access, &state.segs[nvmm_x86_regs_segs[reg]].attrib, sizeof(desc->access));
	desc->limit = state.segs[nvmm_x86_regs_segs[reg]].limit;
	desc->base = state.segs[nvmm_x86_regs_segs[reg]].base;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_SEGS);

	return 0;
}

static int
vmx_setreg_seg(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_setreg_seg(vcpu=%d, reg=%d, val=%" PRIx64 ")\n", vcpu, reg, val);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_SEGS);

	state.segs[nvmm_x86_regs_segs[reg]].selector = (uint16_t)val;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_SEGS);

	return 0;
}

static int
vmx_setreg_gpr(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_setreg_gpr(vcpu=%d, reg=%d, val=%" PRIx64 ")\n", vcpu, reg, val);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	vmm_vcpu_dump((void *)&vmx->mach, vcpu);
	state.gprs[nvmm_x86_regs_gprs[reg]] = val;
	vmm_vcpu_dump((void *)&vmx->mach, vcpu);

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	return 0;
}

static int
vmx_setreg_cr(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_setreg_cr(vcpu=%d, reg=%d, val=%" PRIx64 ")\n", vcpu, reg, val);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_CRS);

	state.crs[nvmm_x86_regs_crs[reg]] = val;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_CRS);

	return 0;
}

static int
vmx_setreg_dr(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_setreg_dr(vcpu=%d, reg=%d, val=%" PRIx64 ")\n", vcpu, reg, val);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_DRS);

	state.drs[nvmm_x86_regs_drs[reg]] = val;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_DRS);

	return 0;
}

static int
vmx_setreg_msr(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	DPRINTF("vmx_setreg_msr(vcpu=%d, reg=%d, val=%" PRIx64 ")\n", vcpu, reg, val);

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_MSRS);

	state.msrs[nvmm_x86_regs_msrs[reg]] = val;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_MSRS);

	return 0;
}

static int
vmx_setreg(void *arg, int vcpu, int reg, uint64_t val)
{
	struct vmx *vmx;

	DPRINTF("vmx_setreg(vcpu=%d, reg=%d, val=%" PRIx64 ")\n", vcpu, reg, val);

	vmx = (struct vmx *)arg;

	switch (reg) {
	case VM_REG_GUEST_RAX:
	case VM_REG_GUEST_RBX:
	case VM_REG_GUEST_RCX:
	case VM_REG_GUEST_RDX:
	case VM_REG_GUEST_RSI:
	case VM_REG_GUEST_RDI:
	case VM_REG_GUEST_RBP:
	case VM_REG_GUEST_R8:
	case VM_REG_GUEST_R9:
	case VM_REG_GUEST_R10:
	case VM_REG_GUEST_R11:
	case VM_REG_GUEST_R12:
	case VM_REG_GUEST_R13:
	case VM_REG_GUEST_R14:
	case VM_REG_GUEST_R15:
	case VM_REG_GUEST_RIP:
	case VM_REG_GUEST_RFLAGS:
	case VM_REG_GUEST_RSP:
		return vmx_setreg_gpr(vmx, vcpu, reg, val);

	case VM_REG_GUEST_CR0:
	case VM_REG_GUEST_CR3:
	case VM_REG_GUEST_CR4:
	case VM_REG_GUEST_CR2:
		return vmx_setreg_cr(vmx, vcpu, reg, val);

	case VM_REG_GUEST_DR7:
		return vmx_setreg_dr(vmx, vcpu, reg, val);

	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_GDTR:
		return vmx_setreg_seg(vmx, vcpu, reg, val);

	case VM_REG_GUEST_EFER:
		return vmx_setreg_msr(vmx, vcpu, reg, val);

	case VM_REG_GUEST_PDPTE0:
	case VM_REG_GUEST_PDPTE1:
	case VM_REG_GUEST_PDPTE2:
	case VM_REG_GUEST_PDPTE3:
		abort();

	case VM_REG_GUEST_INTR_SHADOW:
		abort();

	case VM_REG_LAST:
	default:
		abort();
		break;
	};

	return 0;
}

static int
vmx_getdesc(void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	struct vmx *vmx;

	DPRINTF("vmx_getdesc(vcpu=%d, reg=%d)\n", vcpu, reg);

	vmx = (struct vmx *)arg;

	switch (reg) {
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_GDTR:
		return vmx_getreg_seg_desc(vmx, vcpu, reg, desc);

	default:
		abort();
		break;
	};


	return 0;
}

static int
vmx_setdesc(void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	struct vmx *vmx;

	DPRINTF("vmx_setdesc(vcpu=%d, reg=%d)\n", vcpu, reg);

	vmx = (struct vmx *)arg;

	switch (reg) {
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_GDTR:
		return vmx_setreg_seg_desc(vmx, vcpu, reg, desc);
	default:
		abort();
		break;
	};

	return 0;
}

static int
vmx_getcap(void *arg, int vcpu, int type, int *retval)
{
	DPRINTF("vmx_getcap(vcpu=%d, type=%d)\n", vcpu, type);

	return 0;
}

static int
vmx_setcap(void *arg, int vcpu, int type, int val)
{
	DPRINTF("vmx_setcap(vcpu=%d, type=%d)\n", vcpu, type);

	return 0;
}

static struct vlapic *
vmx_vlapic_init(void *arg, int vcpuid)
{
        struct vmx *vmx;
        struct vlapic *vlapic;
        struct vlapic_vtx *vlapic_vtx;

	DPRINTF("vmx_vlapic_init(vcpuid=%d)\n", vcpuid);

        vmx = arg;

        vlapic = malloc(sizeof(struct vlapic_vtx));
        assert(vlapic);
        bzero(vlapic, sizeof(struct vlapic));
        vlapic->vm = vmx->vm;
        vlapic->vcpuid = vcpuid;
        vlapic->apic_page = (struct LAPIC *)&vmx->apic_page[vcpuid];

        vlapic_vtx = (struct vlapic_vtx *)vlapic;
        vlapic_vtx->vmx = vmx;

        vlapic_init(vlapic);

        return (vlapic);
}

static void
vmx_vlapic_cleanup(UNUSED void *arg, struct vlapic *vlapic)
{
	DPRINTF("vmx_vlapic_cleanup()\n");

        vlapic_cleanup(vlapic);
        free(vlapic);
}

static void
vmx_vcpu_interrupt(int vcpu)
{
	DPRINTF("vmx_vcpu_interrupt(vcpu=%d)\n", vcpu);
}

struct vmm_ops vmm_ops_nvmm = {
	vmx_init,
	vmx_cleanup,
	vmx_vm_init,
	vmx_vcpu_init,
	vmx_run,
	vmx_vm_cleanup,
	vmx_vcpu_cleanup,
	vmx_getreg,
	vmx_setreg,
	vmx_getdesc,
	vmx_setdesc,
	vmx_getcap,
	vmx_setcap,
	vmx_vlapic_init,
	vmx_vlapic_cleanup,
	vmx_vcpu_interrupt
};

int
vmm_mem_init(void)
{

	return (0);
}

void *
vmm_mem_alloc(void *arg, uint64_t gpa, size_t size, uint64_t prot)
{
	void *object;
	int hvProt;
	struct vmx *vmx;

	DPRINTF("vmm_mem_alloc(gpa=%" PRIx64 ", size=%zu, prot=%" PRIx64 ")\n", gpa, size, prot);

	vmx = (struct vmx *)arg;
	object = valloc(size);

	if (!object) {
		xhyve_abort("vmm_mem_alloc failed\n");
	}

	hvProt = (prot & XHYVE_PROT_READ) ? PROT_READ : 0;
	hvProt = (prot & XHYVE_PROT_WRITE) ? PROT_WRITE : 0;
	hvProt = (prot & XHYVE_PROT_EXECUTE) ? PROT_EXEC : 0;

	DPRINTF("nvmm_hva_map(%p, %" PRIxPTR ", %zu)\n", &vmx->mach, object, size);
	if (nvmm_hva_map(&vmx->mach, (uintptr_t)object, size)) {
		xhyve_abort("nvmm_hva_map failed\n");
	}

	DPRINTF("nvmm_gpa_map(%p, %" PRIxPTR ", %" PRIxPTR ", %zu, %d)\n", &vmx->mach, object, gpa, size, hvProt);
	if (nvmm_gpa_map(&vmx->mach, (uintptr_t)object, gpa, size, hvProt) == -1) {
		xhyve_abort("nvmm_gpa_map failed\n");
	}

	return object;
}

void
vmm_mem_free(void *arg, uint64_t gpa, size_t size, void *object)
{
	struct vmx *vmx;

	DPRINTF("vmm_mem_free(gpa=%" PRIx64 ", size=%zu)\n", gpa, size);

	vmx = (struct vmx *)arg;

	if (nvmm_gpa_unmap(&vmx->mach, object, gpa, size) == -1) {
		xhyve_abort("nvmm_gpa_unmap failed\n");
	}

	if (nvmm_hva_unmap(&vmx->mach, object, size) == -1) {
		xhyve_abort("nvmm_hva_unmap failed\n");
	}

	free(object);
}
#endif
