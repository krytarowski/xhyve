#if defined(__NetBSD__)

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

#include "hax-interface.h"

int	get_module_info(const char *, modstat_t *);

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
	int hax_fd;
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
	int rv;

	rv = get_module_info("haxm", NULL);
	if (rv != 0) {
		fprintf(stderr, "HAXM: Kernel module not found, error=%d\n", errno);
	}

	printf("HAXM Virtual Machine Monitor accelerator is available\n");

	return rv;
}

static int
vmx_cleanup(void)
{
        return (0);
}

static void *
vmx_vm_init(struct vm *vm)
{
	struct nvmm_x86_conf_cpuid cpuid;
	struct vmx *vmx;
	int ret;

	vmx = malloc(sizeof(struct vmx));
	if (vmx == NULL) {
		xhyve_abort("HAX: Cannot allocate memory for the vmx struct, error=%d", errno);
	}
	memset(vmx, 0, sizeof(struct vmx));
	vmx->vm = vm;

	printf("HAXM Virtual Machine Monitor accelerator is operational\n");

	return (vmx);
}

static int
vmx_vcpu_init(void *arg, int vcpuid)
{
	struct vmx *vmx;
	int ret;

	vmx = (struct vmx *)arg;

	return 0;
}

static int
vmx_run(void *arg, int vcpu, register_t rip, void *rendezvous_cookie,
		void *suspend_cookie)
{
	struct vmx *vmx;

	vmx = (struct vmx *)arg;

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
vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval)
{
	struct vmx *vmx;

	vmx = (struct vmx *)arg;

	return 0;
}



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
		// XXX

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
vmx_getdesc(void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	struct vmx *vmx;

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
		return vmx_getreg_seg(vmx, vcpu, reg, desc);

	default:
		// XXX
		break;
	};


	return 0;
}

static int
vmx_setdesc(void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	struct vmx *vmx;

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
		return vmx_setreg_seg(vmx, vcpu, reg, desc);
	default:
		// XXX
		break;
	};

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
        struct vmx *vmx;
        struct vlapic *vlapic;
        struct vlapic_vtx *vlapic_vtx;

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
        vlapic_cleanup(vlapic);
        free(vlapic);
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
