#if defined(__NetBSD__)

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <xhyve/support/misc.h>
#include <xhyve/support/specialreg.h>
#include <xhyve/vmm/vmm.h>

#include <nvmm.h>

struct vcpu {
	bool vcpu_dirty;
};

struct vmx {
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

	printf("NetBSD Virtual Machine Monitor accelerator is available\n");

	return 0;
}

static int
vmx_cleanup(void)
{
        return (0);
}

static void
nvmm_io_callback(struct nvmm_io *io)
{
	// XXX
}

static void
nvmm_mem_callback(struct nvmm_mem *mem)
{
	// XXX
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

	printf("NetBSD Virtual Machine Monitor accelerator is operational\n");

	return (vmx);
}

static int
vmx_vcpu_init(void *arg, int vcpuid)
{
	struct vmx *vmx;
	int ret;

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
	// XXX

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

	vmx = (struct vmx *)arg;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);
	state.gprs[NVMM_X64_GPR_RIP] = 0;
	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	while (1) {
		nvmm_vcpu_run(&vmx->mach, vcpu, &exit);

		switch (exit.reason) {
		case NVMM_EXIT_NONE:
			break;
		case NVMM_EXIT_MEMORY:
			ret = nvmm_handle_memory(&vmx->mach, vcpu, &exit);
			break;
		case NVMM_EXIT_IO:
			ret = nvmm_handle_io(&vmx->mach, vcpu, &exit);
			break;
		case NVMM_EXIT_MSR:
			ret = nvmm_handle_msr(&vmx->mach, vcpu, &exit);
			break;
		case NVMM_EXIT_INT_READY:
		case NVMM_EXIT_NMI_READY:
			break;
		case NVMM_EXIT_MONITOR:
		case NVMM_EXIT_MWAIT:
		case NVMM_EXIT_MWAIT_COND:
			// XXX
			break;
		case NVMM_EXIT_HALTED:
			// XXX
			break;
		case NVMM_EXIT_SHUTDOWN:
			// XXX
			ret = 1;
			break;
		default:
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
}

static void
vmx_vcpu_cleanup(void *arg, int vcpuid)
{
}

static int
vmx_getreg_seg(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_SEGS);

	*retval = state.segs[nvmm_x86_regs_segs[reg]].selector; // XXX

	return 0;
}

static int
vmx_getreg_gpr(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	*retval = state.gprs[nvmm_x86_regs_gprs[reg]];

	return 0;
}

static int
vmx_getreg_cr(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_CRS);

	*retval = state.crs[nvmm_x86_regs_crs[reg]];

	return 0;
}

static int
vmx_getreg_dr(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_DRS);

	*retval = state.drs[nvmm_x86_regs_drs[reg]];

	return 0;
}

static int
vmx_getreg_msr(struct vmx *vmx, int vcpu, int reg, uint64_t *retval)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_MSRS);

	*retval = state.msrs[nvmm_x86_regs_msrs[reg]];

	return 0;
}

static int
vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval)
{
	struct vmx *vmx;

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
		// XXX

	case VM_REG_GUEST_INTR_SHADOW:
		// XXX

	case VM_REG_LAST:
	default:
		// XXX
		break;
	};


	return 0;
}


static int
vmx_setreg_seg(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_SEGS);

	state.segs[nvmm_x86_regs_segs[reg]].selector = val; // XXX

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_SEGS);

	return 0;
}

static int
vmx_setreg_gpr(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	state.gprs[nvmm_x86_regs_gprs[reg]] = val;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	return 0;
}

static int
vmx_setreg_cr(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_CRS);

	state.crs[nvmm_x86_regs_crs[reg]] = val;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_CRS);

	return 0;
}

static int
vmx_setreg_dr(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_DRS);

	state.drs[nvmm_x86_regs_drs[reg]] = val;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_DRS);

	return 0;
}

static int
vmx_setreg_msr(struct vmx *vmx, int vcpu, int reg, uint64_t val)
{
	struct nvmm_x64_state state;

	nvmm_vcpu_getstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_MSRS);

	state.msrs[nvmm_x86_regs_msrs[reg]] = val;

	nvmm_vcpu_setstate(&vmx->mach, vcpu, &state, NVMM_X64_STATE_MSRS);

	return 0;
}

static int
vmx_setreg(void *arg, int vcpu, int reg, uint64_t val)
{
	struct vmx *vmx;

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
		// XXX

	case VM_REG_GUEST_INTR_SHADOW:
		// XXX

	case VM_REG_LAST:
	default:
		// XXX
		break;
	};

	return 0;
}

static int
vmx_getdesc(UNUSED void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	return 0;
}

static int
vmx_setdesc(UNUSED void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	return 0;
}

static int
vmx_getcap(void *arg, int vcpu, int type, int *retval)
{
	return 0;
}

static int
vmx_setcap(void *arg, int vcpu, int type, int val)
{
	return 0;
}

static struct vlapic *
vmx_vlapic_init(void *arg, int vcpuid)
{
	return NULL;
}

static void
vmx_vlapic_cleanup(UNUSED void *arg, struct vlapic *vlapic)
{
}

static void
vmx_vcpu_interrupt(int vcpu)
{

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
#endif
