#if defined(__NetBSD__)

#include <stddef.h>

#include <xhyve/support/misc.h>
#include <xhyve/vmm/vmm.h>

static int
vmx_init(void)
{
}

static int
vmx_cleanup(void)
{
        return (0);
}

static void *
vmx_vm_init(struct vm *vm)
{
	return NULL;
}

static int
vmx_vcpu_init(void *arg, int vcpuid)
{
	return 0;
}

static int
vmx_run(void *arg, int vcpu, register_t rip, void *rendezvous_cookie,
        void *suspend_cookie)
{
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
