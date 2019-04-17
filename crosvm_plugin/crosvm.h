/*
 * Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __CROSVM_H__
#define __CROSVM_H__

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include <linux/kvm.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * This module is used to implement a plugin for crosvm.
 *
 * A plugin for crosvm interfaces with the virtual machine using the `struct
 * crosvm` object and its child objects. A typical plugin is expected to call
 * `crosvm_connect`, perform some amount of setup with the functions defined
 * here, get a handle to every vcpu using `struct crosvm_vcpu` and then call
 * `crosvm_start`. Each vcpu will then be waited on with `crosvm_vcpu_wait`,
 * each event will be responded to by the plugin, and then the vcpu is resumed
 * with `crosvm_vcpu_resume`. The vcpu state can only be examined and modified
 * between the `crosvm_vcpu_wait` and `crosvm_vcpu_resume` calls. The crosvm
 * connection can be used to modify global virtual machine state at any time,
 * with some structural restrictions after `crosvm_start` is called.
 *
 * In general, functions that return an `int` return 0 on success or a non-
 * negative file descriptor if one is expected. A negative return value is an
 * errno and indicates error. Functions that take a pointer-to-pointer to an
 * opaque structure either return a structure or delete and nullify that
 * structure pointer.
 */

/*
 * We use Semantic Versioning (http://semver.org/) here, which means that as
 * long as MAJOR is 0, breaking changes can occur, but once MAJOR is non-zero, a
 * breaking change requires a MAJOR version bump. The MINOR number increases as
 * backward compatible functionality is added. The PATCH number increases bug
 * fixes are done. The version numbers indicate here are for the plugin API and
 * do not indicate anything about what version of crosvm is running.
 */
#define CROSVM_API_MAJOR 0
#define CROSVM_API_MINOR 17
#define CROSVM_API_PATCH 0

enum crosvm_address_space {
  /* I/O port */
  CROSVM_ADDRESS_SPACE_IOPORT = 0,
  /* physical memory space */
  CROSVM_ADDRESS_SPACE_MMIO,
};

/* Handle to the parent crosvm process. */
struct crosvm;

/* Handle to a register ioeventfd. */
struct crosvm_io;

/* Handle to a registered range of shared memory. */
struct crosvm_memory;

/* Handle to a registered irqfd. */
struct crosvm_irq;

/* Handle to one of the VM's VCPUs. */
struct crosvm_vcpu;

/*
 * Connects to the parent crosvm process and returns a new `struct crosvm`
 * interface object.
 *
 * This is the entry point for interfacing with crosvm as a plugin. This should
 * be called before any other function. The returned object is not-thread safe.
 */
int crosvm_connect(struct crosvm**);

/*
 * Creates another connection for interfacing with crosvm concurrently.
 *
 * The new connection behaves exactly like the original `struct crosvm` but can
 * be used concurrently on a different thread than the original. Actual
 * execution order of the requests to crosvm is unspecified but every request is
 * completed when the `crosvm_*` call returns.
 *
 * It is invalid to call this after `crosvm_start` is called on any `struct
 * crosvm`.
 */
int crosvm_new_connection(struct crosvm*, struct crosvm**);

/*
 * Destroys this connection and tells the parent crosvm process to stop
 * listening for messages from it.
 */
int crosvm_destroy_connection(struct crosvm**);

/*
 * Gets an eventfd that is triggered when this plugin should exit.
 *
 * The returned eventfd is owned by the caller but the underlying event is
 * shared and will therefore only trigger once.
 */
int crosvm_get_shutdown_eventfd(struct crosvm*);

/*
 * Gets a bool indicating if a KVM_CAP_* enum is supported on this VM
 */
int crosvm_check_extension(struct crosvm*, uint32_t __extension,
                           bool *has_extension);

/*
 * Queries x86 cpuid features which are supported by the hardware and
 * kvm.
 */
int crosvm_get_supported_cpuid(struct crosvm*, uint32_t __entry_count,
                               struct kvm_cpuid_entry2 *__cpuid_entries,
                               uint32_t *__out_count);

/*
 * Queries x86 cpuid features which are emulated by kvm.
 */
int crosvm_get_emulated_cpuid(struct crosvm*, uint32_t __entry_count,
                              struct kvm_cpuid_entry2 *__cpuid_entries,
                              uint32_t *__out_count);

/*
 * Queries kvm for list of supported MSRs.
 */
int crosvm_get_msr_index_list(struct crosvm*, uint32_t __entry_count,
                              uint32_t *__msr_indices,
                              uint32_t *__out_count);

/*
 * The network configuration for a crosvm instance.
 */
struct crosvm_net_config {
  /*
   * The tap device fd. This fd is owned by the caller, and should be closed
   * by the caller when it is no longer in use.
   */
  int tap_fd;
  /* The IPv4 address of the tap interface, in network (big-endian) format. */
  uint32_t host_ip;
  /* The netmask of the tap interface subnet, in network (big-endian) format. */
  uint32_t netmask;
  /* The mac address of the host side of the tap interface. */
  uint8_t host_mac_address[6];
  uint8_t _padding[2];
};

#ifdef static_assert
static_assert(sizeof(struct crosvm_net_config) == 20,
              "extra padding in struct crosvm_net_config");
#endif

/*
 * Gets the network configuration.
 */
int crosvm_net_get_config(struct crosvm*, struct crosvm_net_config*);

/*
 * Registers a range in the given address space that, when accessed, will block
 * and wait for a crosvm_vcpu_resume call.
 *
 * To unreserve a range previously reserved by this function, pass the |__space|
 * and |__start| of the old reservation with a 0 |__length|.
 */
int crosvm_reserve_range(struct crosvm*, uint32_t __space, uint64_t __start,
                         uint64_t __length);

/*
 * Sets the state of the given irq pin.
 */
int crosvm_set_irq(struct crosvm*, uint32_t __irq_id, bool __active);

enum crosvm_irq_route_kind {
  /* IRQ pin to GSI route */
  CROSVM_IRQ_ROUTE_IRQCHIP = 0,
  /* MSI address and data to GSI route */
  CROSVM_IRQ_ROUTE_MSI,
};

/* One entry in the array of irq routing table */
struct crosvm_irq_route {
  /* The IRQ number to trigger. */
  uint32_t irq_id;
  /* A `crosvm_irq_route_kind` indicating which union member to use */
  uint32_t kind;
  union {
    struct {
      /*
       * One of KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, or
       * KVM_IRQCHIP_IOAPIC indicating which irqchip the indicated pin is on.
       */
      uint32_t irqchip;
      /* The pin on the irqchip used to trigger the IRQ. */
      uint32_t pin;
    } irqchip;

    struct {
      /* Address that triggers the irq. */
      uint64_t address;
      /* Data written to `address` that triggers the irq */
      uint32_t data;

      uint8_t _reserved[4];
    } msi;

    uint8_t _reserved[16];
  };
};

#ifdef static_assert
static_assert(sizeof(struct crosvm_irq_route) == 24,
              "extra padding in struct crosvm_irq_route");
#endif

/*
 * Sets all the gsi routing entries to those indicated by `routes`.
 *
 * To remove all routing entries, pass NULL for `routes` and 0 to route_count.
 */
int crosvm_set_irq_routing(struct crosvm*, uint32_t __route_count,
                           const struct crosvm_irq_route* __routes);

/* Gets the state of interrupt controller in a VM. */
int crosvm_get_pic_state(struct crosvm *, bool __primary,
                         struct kvm_pic_state *__pic_state);

/* Sets the state of interrupt controller in a VM. */
int crosvm_set_pic_state(struct crosvm *, bool __primary,
                         const struct kvm_pic_state *__pic_state);

/* Gets the state of IOAPIC in a VM. */
int crosvm_get_ioapic_state(struct crosvm *,
                            struct kvm_ioapic_state *__ioapic_state);

/* Sets the state of IOAPIC in a VM. */
int crosvm_set_ioapic_state(struct crosvm *,
                            const struct kvm_ioapic_state *__ioapic_state);

/* Gets the state of interrupt controller in a VM. */
int crosvm_get_pit_state(struct crosvm *, struct kvm_pit_state2 *__pit_state);

/* Sets the state of interrupt controller in a VM. */
int crosvm_set_pit_state(struct crosvm *,
                         const struct kvm_pit_state2 *__pit_state);

/* Gets the current timestamp of kvmclock as seen by the VM. */
int crosvm_get_clock(struct crosvm *, struct kvm_clock_data *__clock_data);

/* Sets the current timestamp of kvmclock for the VM. */
int crosvm_set_clock(struct crosvm *,
                     const struct kvm_clock_data *__clock_data);

/* Sets the identity map address as in the KVM_SET_IDENTITY_MAP_ADDR ioctl. */
int crosvm_set_identity_map_addr(struct crosvm*, uint32_t __addr);

/*
 * Triggers a CROSVM_VCPU_EVENT_KIND_PAUSED event on each vcpu identified
 * |__cpu_mask|.
 *
 * The `user` pointer will be given as the `user` pointer in the `struct
 * crosvm_vcpu_event` returned by crosvm_vcpu_wait.
 */
int crosvm_pause_vcpus(struct crosvm*, uint64_t __cpu_mask, void* __user);

/*
 * Call once initialization is done. This indicates that crosvm should proceed
 * with running the VM.
 *
 * After this call, this function is no longer valid to call.
 */
int crosvm_start(struct crosvm*);

/*
 * Allocates an eventfd that is triggered asynchronously on write in |__space|
 * at the given |__addr|.
 *
 * If |__datamatch| is non-NULL, it must be contain |__length| bytes that will
 * be compared to the bytes being written by the vcpu which will only trigger
 * the eventfd if equal. If datamatch is NULL all writes to the address will
 * trigger the eventfd.
 *
 * On successful allocation, returns a crosvm_io.  Obtain the actual fd
 * by passing this result to crosvm_io_event_fd().
 */
int crosvm_create_io_event(struct crosvm*, uint32_t __space, uint64_t __addr,
                           uint32_t __len, const uint8_t* __datamatch,
                           struct crosvm_io**);

/*
 * Destroys the given io event and unregisters it from the VM.
 */
int crosvm_destroy_io_event(struct crosvm*, struct crosvm_io**);

/*
 * Gets the eventfd triggered by the given io event.
 *
 * The returned fd is owned by the given `struct crosvm_io` and has a lifetime
 * equal to that handle.
 */
int crosvm_io_event_fd(struct crosvm_io*);

/*
 * Creates a shared memory segment backed by a memfd.
 *
 * Inserts non-overlapping memory pages in the guest physical address range
 * specified by |__start| address and |__length| bytes. The memory pages are
 * backed by the memfd |__fd| and are taken starting at |__offset| bytes from
 * the beginning of the memfd.
 *
 * The `memfd_create` syscall |__fd| must be used to create |__fd| and a shrink
 * seal must have been added to |__fd|. The memfd must be at least
 * `__length+__offset` bytes long.
 *
 * If |read_only| is true, attempts by the guest to write to this memory region
 * will trigger an IO access exit.
 *
 * To use the `crosvm_memory_get_dirty_log` method with the returned object,
 * |__dirty_log| must be true.
 */
int crosvm_create_memory(struct crosvm*, int __fd, uint64_t __offset,
                         uint64_t __length, uint64_t __start,
                         bool __read_only, bool __dirty_log,
                         struct crosvm_memory**);

/*
 * Destroys the given shared memory and unregisters it from guest physical
 * address space.
 */
int crosvm_destroy_memory(struct crosvm*, struct crosvm_memory**);

/*
 * For a given memory region returns a bitmap containing any pages
 * dirtied since the last call to this function.
 *
 * The `log` array must have as many bits as the memory segment has pages.
 */
int crosvm_memory_get_dirty_log(struct crosvm*, struct crosvm_memory*,
                                uint8_t* __log);

/*
 * Creates an irq eventfd that can be used to trigger an irq asynchronously.
 *
 * The irq that will be triggered is identified as pin |__irq_id|.
 */
int crosvm_create_irq_event(struct crosvm*, uint32_t __irq_id,
                            struct crosvm_irq**);

/*
 * Unregisters and destroys an irq eventfd.
 */
int crosvm_destroy_irq_event(struct crosvm*, struct crosvm_irq**);

/*
 * Gets the eventfd used to trigger the irq
 *
 * The returned fd is owned by the given `struct crosvm_irq` and has a lifetime
 * equal to that handle.
 */
int crosvm_irq_event_get_fd(const struct crosvm_irq*);

/*
 * Gets the resample eventfd associated with the crosvm_irq object.
 */
int crosvm_irq_event_get_resample_fd(const struct crosvm_irq*);

enum crosvm_vcpu_event_kind {
  /*
   * The first event returned by crosvm_vcpu_wait, indicating the VCPU has been
   * created but not yet started for the first time.
   */
  CROSVM_VCPU_EVENT_KIND_INIT = 0,

  /*
   * Access to an address in a space previously reserved by
   * crosvm_reserve_range.
   */
  CROSVM_VCPU_EVENT_KIND_IO_ACCESS,

  /*
   * A pause on this vcpu (and possibly others) was requested by this plugin in
   * a `crosvm_pause_vcpus` call.
   */
  CROSVM_VCPU_EVENT_KIND_PAUSED,
};

struct crosvm_vcpu_event {
  /* Indicates the kind of event and which union member is valid. */
  uint32_t kind;

  uint8_t _padding[4];

  union {
    /* CROSVM_VCPU_EVENT_KIND_IO_ACCESS */
    struct {
      /*
       * One of `enum crosvm_address_space` indicating which address space the
       * access occurred in.
       */
      uint32_t address_space;

      uint8_t _padding[4];

      /* The address that the access occurred at. */
      uint64_t address;

      /*
       * In the case that `is_write` is true, the first `length` bytes are the
       * data being written by the vcpu.
       */
      uint8_t *data;

      /*
       * Number of bytes in the access. In the case that the access is larger
       * than 8 bytes, such as by AVX-512 instructions, multiple vcpu access
       * events are generated serially to cover each 8 byte fragment of the
       * access.
       *
       * Larger I/O accesses are possible.  "rep in" can generate I/Os larger
       * than 8 bytes, though such accesses can also be split into multiple
       * events.  Currently kvm doesn't seem to batch "rep out" I/Os.
       */
      uint32_t length;

      /*
       * True if the vcpu was attempting to write, false in case of an attempt
       * to read.
       */
      uint8_t is_write;

      uint8_t _reserved[3];
    } io_access;

    /* CROSVM_VCPU_EVENT_KIND_PAUSED */
    void *user;

    uint8_t _reserved[64];
  };
};

#ifdef static_assert
static_assert(sizeof(struct crosvm_vcpu_event) == 72,
              "extra padding in struct crosvm_vcpu_event");
#endif

/*
 * Gets the vcpu object for the given |__cpu_id|.
 *
 *
 * The `struct crosvm_vcpu` is owned by `struct crosvm`. Each call with the same
 * `crosvm` and |__cpu_id| will yield the same pointer. The `crosvm_vcpu` does
 * not need to be destroyed or created explicitly.
 *
 * The range of valid |__cpu_id|s is 0 to the number of vcpus - 1. To get every
 * `crosvm_vcpu`, simply call this function iteratively with increasing
 * |__cpu_id| until `-ENOENT` is returned.
 *
 */
int crosvm_get_vcpu(struct crosvm*, uint32_t __cpu_id, struct crosvm_vcpu**);

/*
 * Blocks until a vcpu event happens that requires a response.
 *
 * When crosvm_vcpu_wait returns successfully, the event structure is filled
 * with the description of the event that occurred. The vcpu will suspend
 * execution until a matching call to `crosvm_vcpu_resume` is made. Until such a
 * call is made, the vcpu's run structure can be read and written using any
 * `crosvm_vcpu_get` or `crosvm_vcpu_set` function.
 */
int crosvm_vcpu_wait(struct crosvm_vcpu*, struct crosvm_vcpu_event*);

/*
 * Resumes execution of a vcpu after a call to `crosvm_vcpu_wait` returns.
 *
 * In the case that the event was a read operation, `data` indicates what the
 * result of that read operation should be. If the read operation was larger
 * than 8 bytes, such as by AVX-512 instructions, this will not actually resume
 * the vcpu, but instead generate another vcpu access event of the next fragment
 * of the read, which can be handled by the next `crosvm_vcpu_wait` call.
 *
 * Once the vcpu event has been responded to sufficiently enough to resume
 * execution, `crosvm_vcpu_resume` should be called. After `crosvm_vcpu_resume`
 * is called, none of the vcpu state operations are valid until the next time
 * `crosvm_vcpu_wait` returns.
 */
int crosvm_vcpu_resume(struct crosvm_vcpu*);

/* Gets the state of the vcpu's registers. */
int crosvm_vcpu_get_regs(struct crosvm_vcpu*, struct kvm_regs*);
/* Sets the state of the vcpu's registers. */
int crosvm_vcpu_set_regs(struct crosvm_vcpu*, const struct kvm_regs*);

/* Gets the state of the vcpu's special registers. */
int crosvm_vcpu_get_sregs(struct crosvm_vcpu*, struct kvm_sregs*);
/* Sets the state of the vcpu's special registers. */
int crosvm_vcpu_set_sregs(struct crosvm_vcpu*, const struct kvm_sregs*);

/* Gets the state of the vcpu's floating point unint. */
int crosvm_vcpu_get_fpu(struct crosvm_vcpu*, struct kvm_fpu*);
/* Sets the state of the vcpu's floating point unint. */
int crosvm_vcpu_set_fpu(struct crosvm_vcpu*, const struct kvm_fpu*);

/* Gets the state of the vcpu's debug registers. */
int crosvm_vcpu_get_debugregs(struct crosvm_vcpu*, struct kvm_debugregs*);
/* Sets the state of the vcpu's debug registers */
int crosvm_vcpu_set_debugregs(struct crosvm_vcpu*, const struct kvm_debugregs*);

/* Gets the state of the vcpu's xcr registers. */
int crosvm_vcpu_get_xcrs(struct crosvm_vcpu*, struct kvm_xcrs*);
/* Sets the state of the vcpu's xcr registers. */
int crosvm_vcpu_set_xcrs(struct crosvm_vcpu*, const struct kvm_xcrs*);

/* Gets the MSRs of the vcpu indicated by the index field of each entry. */
int crosvm_vcpu_get_msrs(struct crosvm_vcpu*, uint32_t __msr_count,
                         struct kvm_msr_entry *__msr_entries,
                         uint32_t *__out_count);
/* Sets the MSRs of the vcpu indicated by the index field of each entry. */
int crosvm_vcpu_set_msrs(struct crosvm_vcpu*, uint32_t __msr_count,
                         const struct kvm_msr_entry *__msr_entries);

/* Sets the responses to the cpuid instructions executed on this vcpu, */
int crosvm_vcpu_set_cpuid(struct crosvm_vcpu*, uint32_t __cpuid_count,
                          const struct kvm_cpuid_entry2 *__cpuid_entries);

/* Gets state of LAPIC of the VCPU. */
int crosvm_vcpu_get_lapic_state(struct crosvm_vcpu *,
                                struct kvm_lapic_state *__lapic_state);
/* Sets state of LAPIC of the VCPU. */
int crosvm_vcpu_set_lapic_state(struct crosvm_vcpu *,
                                const struct kvm_lapic_state *__lapic_state);

/* Gets the "multiprocessor state" of given VCPU. */
int crosvm_vcpu_get_mp_state(struct crosvm_vcpu *,
                             struct kvm_mp_state *__mp_state);
/* Sets the "multiprocessor state" of given VCPU. */
int crosvm_vcpu_set_mp_state(struct crosvm_vcpu *,
                             const struct kvm_mp_state *__mp_state);

/* Gets currently pending exceptions, interrupts, NMIs, etc for VCPU. */
int crosvm_vcpu_get_vcpu_events(struct crosvm_vcpu *,
                                struct kvm_vcpu_events *);

/* Sets currently pending exceptions, interrupts, NMIs, etc for VCPU. */
int crosvm_vcpu_set_vcpu_events(struct crosvm_vcpu *,
                                const struct kvm_vcpu_events *);

#ifdef  __cplusplus
}
#endif

#endif
