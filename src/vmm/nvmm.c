#if defined(__NetBSD__)

#include <stddef.h>

#include <xhyve/support/misc.h>
#include <xhyve/vmm/vmm.h>

#include <nvmm.h>

static struct {
	struct nvmm_machine mach;
} nvmm_global;

static struct nvmm_machine *
get_nvmm_mach(void)
{
	return &nvmm_global.mach;
}

static int
vmx_init(void)
{
	struct nvmm_capability cap;
	struct nvmm_x86_conf_cpuid cpuid;
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

	ret = nvmm_machine_create(&nvmm_global.mach);
	if (ret == -1) {
		xhyve_abort("NVMM: Machine creation failed, error=%d", errno);
	}

	// Configure acceleration
	memset(&cpuid, 0, sizeof(cpuid));
	cpuid.leaf = 0x00000001;
	cpuid.del.edx = CPUID_MCE | CPUID_MCA | CPUID_MTRR;
	ret = nvmm_machine_configure(mach, NVMM_X86_CONF_CPUID, &cpuid);
	if (ret == -1) {
		xhyve_abort("NVMM: Machine configuration failed, error=%d", errno);
	}

	// XXX: callbacks for io/mem ?

	printf("NetBSD Virtual Machine Monitor accelerator is operational\n");

	return 0;
}

static int
vmx_cleanup(void)
{
        return (0);
}

static void *
vmx_vm_init(struct vm *vm)
{
        struct vmx *vmx;

        vmx = malloc(sizeof(struct vmx));
        assert(vmx);
        memset(vmx, 0, sizeof(struct vmx));
        vmx->vm = vm;

        return (vmx);
}

static int
vmx_vcpu_init(void *arg, int vcpuid)
{
	struct nvmm_machine mach = get_nvmm_mach();
	int ret;

	ret = nvmm_vcpu_create(&mach, vcpuid);
	if (ret == -1) {
		xhyve_abort("NVMM: Failed to create a virtual processor, error=%d\n", errno);
	}

	return 0;
}

static int
vmx_run(void *arg, int vcpu, register_t rip, void *rendezvous_cookie,
        void *suspend_cookie)
{

	struct nvmm_machine mach;
	struct nvmm_x64_state state;
	struct nvmm_exit exit;

	nvmm_vcpu_getstate(&mach, vcpu, &state, NVMM_X64_STATE_GPRS);
	state.gprs[NVMM_X64_GPR_RIP] = 0;
	nvmm_vcpu_setstate(&mach, vcpu, &state, NVMM_X64_STATE_GPRS);

	while (1) {
		nvmm_vcpu_run(&mach, vcpu, &exit);

		switch (exit.reason) {
		case NVMM_EXIT_NONE:
			break;
		case NVMM_EXIT_HALTED:
			return 0;
		default:
			return -1;
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
vmx_getreg(UNUSED void *arg, int vcpu, int reg, uint64_t *retval)
{
	return 0;
}

static int
vmx_setreg(void *arg, int vcpu, int reg, uint64_t val)
{
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
