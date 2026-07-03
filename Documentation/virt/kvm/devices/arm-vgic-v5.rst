.. SPDX-License-Identifier: GPL-2.0

====================================================
ARM Virtual Generic Interrupt Controller v5 (VGICv5)
====================================================


Device types supported:
  - KVM_DEV_TYPE_ARM_VGIC_V5     ARM Generic Interrupt Controller v5.0

Only one VGIC instance may be instantiated through this API.  The created VGIC
will act as the VM interrupt controller, requiring emulated user-space devices
to inject interrupts to the VGIC instead of directly to CPUs.

Creating a guest GICv5 device requires a GICv5 host.  The VGICv5 device supports
PPI, SPI, and LPI interrupts.  The PPI and SPI interrupts can either be injected
from emulated in-kernel devices (such as the Arch Timer, or PMU), or via the
KVM_IRQ_LINE ioctl.  LPIs are not externally injected, but are handled in
hardware via the LPI IST.  Their pending state is driven directly by the guest.

Groups:
  KVM_DEV_ARM_VGIC_GRP_ADDR
   Attributes:

    KVM_VGIC_V5_ADDR_TYPE_IRS (rw, 64-bit)
      Base address in the guest physical address space of the GICv5 IRS
      (Interrupt Routing Service) register mappings. Only valid for
      KVM_DEV_TYPE_ARM_VGIC_V5.  This address needs to be 64K aligned and the
      region covers 128 KByte - the IRS has a CONFIG_FRAME and a SETLPI_FRAME,
      each of which is 64 KBytes in size.

      Setting the address of the IRS in GPA space is mandatory before VGIC
      resources are mapped, as the IRS is responsible for handling SPIs and
      LPIs. Failure to set the IRS address before the first vCPU run results in
      an error.

  KVM_DEV_ARM_VGIC_GRP_NR_IRQS
   Attributes:

    A value describing the number of SPIs for this GIC instance. This is
    GICv5-specific: unlike GICv2/v3, the value does not include SGIs or PPIs.
    The value ranges from 32 to the maximum value reported by
    GICV5_IRS_IDR5.SPI_RANGE, in increments of 32. If userspace does not set
    this attribute, KVM uses 32 SPIs by default.

    kvm_device_attr.addr points to a __u32 value.

  KVM_DEV_ARM_VGIC_GRP_CTRL
   Attributes:

    KVM_DEV_ARM_VGIC_CTRL_INIT
      request the initialization of the VGIC, no additional parameter in
      kvm_device_attr.addr. Must be called after all VCPUs have been created.

   KVM_DEV_ARM_VGIC_USERSPACE_PPIS
      request the mask of userspace-drivable PPIs. Only a subset of the PPIs can
      be directly driven from userspace with GICv5, and the returned mask
      informs userspace of which it is allowed to drive via KVM_IRQ_LINE.

      Userspace must allocate and point to __u64[2] of data in
      kvm_device_attr.addr. When this call returns, the provided memory will be
      populated with the userspace PPI mask. The lower __u64 contains the mask
      for the lower 64 PPIS, with the remaining 64 being in the second __u64.

      This is a read-only attribute, and cannot be set. Attempts to set it are
      rejected.

  Errors:

    =======  ========================================================
    -ENXIO   VGIC not properly configured as required prior to calling
             this attribute
    -ENODEV  no online VCPU
    -ENOMEM  memory shortage when allocating vgic internal data
    -EFAULT  Invalid guest ram access
    -EBUSY   One or more VCPUS are running
    =======  ========================================================

  KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS
   Attributes:

    The attr field of kvm_device_attr encodes two values::

      bits:     | 63      ....       32 | 31  ....  16 | 15  ....  0 |
      values:   |         mpidr         |      RES     |    instr    |

    The mpidr field encodes the CPU ID based on the affinity information in the
    architecture defined MPIDR, and the field is encoded as follows::

      | 63 .... 56 | 55 .... 48 | 47 .... 40 | 39 .... 32 |
      |    Aff3    |    Aff2    |    Aff1    |    Aff0    |

    The instr field encodes the system register to access based on the fields
    defined in the A64 instruction set encoding for system register access
    (RES means the bits are reserved for future use and should be zero)::

      | 15 ... 14 | 13 ... 11 | 10 ... 7 | 6 ... 3 | 2 ... 0 |
      |   Op 0    |    Op1    |    CRn   |   CRm   |   Op2   |

    All system regs accessed through this API are (rw, 64-bit) and
    kvm_device_attr.addr points to a __u64 value.

    KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS accesses the CPU interface registers for the
    CPU specified by the mpidr field.

    The available registers are:

    =======================  ===================================================
    ICC_ICSR_EL1
    ICC_PPI_ENABLER0_EL1
    ICC_PPI_ENABLER1_EL1
    ICC_PPI_SACTIVER0_EL1    ICC_PPI_CACTIVER0_EL1 is not supported. Writes to
                             ICC_PPI_SACTIVER0_EL1 are treated as RAW writes of
                             the underlying state.
    ICC_PPI_SACTIVER1_EL1    ICC_PPI_CACTIVER1_EL1 is not supported. Writes to
                             ICC_PPI_SACTIVER1_EL1 are treated as RAW writes of
                             the underlying state.
    ICC_PPI_SPENDR0_EL1      ICC_PPI_CPENDR0_EL1 is not supported. Writes to
                             ICC_PPI_SPENDR0_EL1 are treated as RAW writes of
                             the underlying state.
    ICC_PPI_SPENDR1_EL1      ICC_PPI_CPENDR1_EL1 is not supported. Writes to
                             ICC_PPI_SPENDR1_EL1 are treated as RAW writes of
                             the underlying state.
    ICC_PPI_PRIORITYR0_EL1
    ICC_PPI_PRIORITYR1_EL1
    ICC_PPI_PRIORITYR2_EL1
    ICC_PPI_PRIORITYR3_EL1
    ICC_PPI_PRIORITYR4_EL1
    ICC_PPI_PRIORITYR5_EL1
    ICC_PPI_PRIORITYR6_EL1
    ICC_PPI_PRIORITYR7_EL1
    ICC_PPI_PRIORITYR8_EL1
    ICC_PPI_PRIORITYR9_EL1
    ICC_PPI_PRIORITYR10_EL1
    ICC_PPI_PRIORITYR11_EL1
    ICC_PPI_PRIORITYR12_EL1
    ICC_PPI_PRIORITYR13_EL1
    ICC_PPI_PRIORITYR14_EL1
    ICC_PPI_PRIORITYR15_EL1
    ICC_APR_EL1
    ICC_CR0_EL1
    ICC_PCR_EL1
    =======================  ===================================================

  KVM_DEV_ARM_VGIC_GRP_IRS_REGS
    Attributes:
      The attr field of kvm_device_attr encodes the offset of the IRS register,
      relative to the IRS CONFIG_FRAME base address. This is the address that
      was provided via KVM_VGIC_V5_ADDR_TYPE_IRS when creating VGICv5 in the
      first place.

      kvm_device_attr.addr points to a __u64 value whatever the width
      of the addressed register (32/64 bits). 64 bit registers can only
      be accessed with full length.

      Writes to read-only registers are ignored by the kernel except for:

      - IRS_IDR0 - IRS_IDR2 and IRS_IDR5 - IRS_IDR7: These are sanity checked to
        ensure that they match a sane config.
      - IRS_IDR3 and IRS_IDR4: These are RAZ/WI as nested virtualization is not
        supported.

      For registers without dedicated userspace accessors, getting or setting a
      register uses the same emulated MMIO handlers as guest reads/writes.
      Dedicated userspace accessors may instead save or restore migration state
      without triggering guest-visible side effects. For example, restoring
      IRS_IST_BASER only restores the emulated register state; any host LPI IST
      allocation based on the restored IRS_IST_CFGR and IRS_IST_BASER state
      happens when KVM_DEV_ARM_VGIC_GRP_IST is restored.

  Errors:

    =======  =================================================================
    -ENXIO   Offset does not correspond to any supported register
    -EFAULT  Invalid user pointer for attr->addr
    -EINVAL  Offset is not 32-bit aligned for 32-bit MMIO registers, or not
             64-bit aligned for 64-bit registers
    -EBUSY   VGIC is not initialized, or one or more VCPUs are running
    =======  =================================================================

  KVM_DEV_ARM_VGIC_GRP_IST
    Attributes:
      This interface is used to either save the state of the IRS's Interrupt
      State Tables (ISTs), or to restore them. A get operation saves IST state,
      and a set operation restores IST state. kvm_device_attr.attr is reserved
      and must be zero.

      The VGIC must be initialized before using this interface. Restore must be
      performed before the VM has run. For restore, userspace must have already
      restored the IRS state and guest memory needed to describe and back any
      guest LPI IST.

      Saving first asks the IRS to save and quiesce the VM so that interrupt
      state has been written back to the ISTs. KVM checks that the VM remains
      quiesced while copying out the SPI and LPI IST state.

      The LPI IST is written to or read from guest-allocated memory. KVM assumes
      that the guest has provisioned a linear virtual IST through IRS_IST_CFGR
      and IRS_IST_BASER, and uses that guest memory as the LPI IST migration
      storage. If the guest has not enabled an LPI IST, there is no LPI IST
      state to save or restore.

      The SPI IST has no guest-owned backing memory, so userspace must provide a
      buffer through kvm_device_attr.addr for both get and set operations. The
      buffer contains one little-endian 32-bit IST entry per exposed SPI, in SPI
      number order. Its size is:

        nr_spis * sizeof(__u32)

      where nr_spis is the value returned by KVM_DEV_ARM_VGIC_GRP_NR_IRQS for
      the VGICv5 device. For VGICv5 this value is the number of SPIs, not the
      total number of interrupts. Since VGICv5 currently exposes at least 32
      SPIs, kvm_device_attr.addr must be non-zero.

    Errors:

      ===========  ============================================================
      -EBUSY       One or more VCPUs are running, the VGIC is not initialized,
                   restore was requested after the VM has run, an LPI IST
                   already exists, or the save operation completed but the VM
                   did not remain quiesced
      -EINVAL      A userspace SPI IST buffer was not supplied when one is
                   required, or an internal VM table operation rejected the VM
                   state
      -ENOENT      A userspace SPI IST buffer was supplied, but there is no SPI
                   IST to serialise/unserialise
      -EFAULT      Invalid user pointer for attr->addr, or the guest memory
                   backing the LPI IST could not be accessed
      -ENXIO       Required per-VM VGICv5/IST backing state is missing or
                   inconsistent
      -ENOMEM      Restoring IST state failed while allocating the host LPI IST
                   or tracking pending interrupts
      -ETIMEDOUT   An IRS save/VM operation timed out
      ===========  ============================================================

IRS Save Sequence:
------------------

The following operations are required when saving the virtual GICv5 IRS:

a) Save the ISTs by issuing KVM_GET_DEVICE_ATTR on KVM_DEV_ARM_VGIC_GRP_IST.
b) Save the IRS MMIO register state by issuing KVM_GET_DEVICE_ATTR on
   KVM_DEV_ARM_VGIC_GRP_IRS_REGS.

These two steps may be performed in either order. However, the guest memory
must be serialised after the ISTs have been saved, as saving the LPI IST writes
the IST state back into guest memory.

IRS Restore Sequence:
---------------------

The following ordering must be followed when restoring the virtual GICv5 and
IRS:

a) Create vCPUs.
b) Provide the IRS base address by issuing KVM_SET_DEVICE_ATTR on
   KVM_DEV_ARM_VGIC_GRP_ADDR
c) Restore the number of SPIs by issuing KVM_SET_DEVICE_ATTR on
   KVM_DEV_ARM_VGIC_GRP_NR_IRQS.
d) Initialise the GIC - this sets up the default state and creates the SPI
   IST - by issuing KVM_SET_DEVICE_ATTR on KVM_DEV_ARM_VGIC_GRP_CTRL with
   KVM_DEV_ARM_VGIC_CTRL_INIT
e) Restore guest memory.
f) Restore the IRS MMIO register state by issuing KVM_SET_DEVICE_ATTR on
   KVM_DEV_ARM_VGIC_GRP_IRS_REGS. KVM uses the restored IRS_IST_CFGR and
   IRS_IST_BASER state to allocate the LPI IST during the following step.
g) Restore the ISTs by issuing KVM_SET_DEVICE_ATTR on
   KVM_DEV_ARM_VGIC_GRP_IST.

The number of SPIs must be restored before VGIC initialization because
initialization allocates the SPI state and fixes the SPI range exposed by the
IRS ID registers.

The various ``*_STATUSR`` registers are observational state in the current KVM
implementation. Userspace may save them for validation or debugging purposes,
but they are not required as restore input and do not need to be replayed during
restore.

Then vCPUs can be started.
