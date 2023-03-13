# Hypervisor Support

Multiple hypervisor backends are supported. See
[Advanced Usage](running_crosvm/advanced_usage.md#hypervisor) for overriding the default backend.

Hypervisors added to crosvm must meet the following requirements:

- Hypervisor code must be buildable in crosvm upstream.
  - Within reason, crosvm maintainers will ensure the hypervisor's code continues to build.
- Hypervisors are not required to be tested upstream.
  - We can't require testing upstream because some hypervisors require specialized hardware.
  - When not tested upstream, the hypervisor's maintainers are expected to test it downstream. If a
    change to crosvm breaks something downstream, then the hypervisor's maintainers are expected to
    supply the fix and can't expect a revert of the culprit change to be accepted upstream.

## KVM

- Platforms: Linux
- Tested upstream: yes

KVM is crosvm's preferred hypervisor for Linux.

## WHPX

- Platforms: Windows
- Tested upstream: no

## HAXM

- Platforms: Windows
- Tested upstream: no

## Android Specific

The hypervisors in this section are used as backends of the
[Android Virtualization Framework](https://source.android.com/docs/core/virtualization).

### Geniezone

- Platforms: Linux, aarch64 only
- Tested upstream: no
- Contacts: fmayle@google.com, smoreland@google.com

### Gunyah

- Platforms: Linux, aarch64 only
- Tested upstream: no
- Contacts: fmayle@google.com, smoreland@google.com
