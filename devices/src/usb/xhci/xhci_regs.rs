// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::register_space::{Register, RegisterSpace};

/// Max interrupter number.
pub const MAX_INTERRUPTER: u8 = 1;
/// For port configuration, see register HCSPARAMS1, spcap1.3 and spcap2.3.
pub const MAX_SLOTS: u8 = 16;

/// Usb 2 ports start from port number 0.
pub const USB2_PORTS_START: u8 = 0;
/// Last usb 2 ports is 7.
pub const USB2_PORTS_END: u8 = 8;
/// Usb 3 ports start from port number 8.
pub const USB3_PORTS_START: u8 = 8;
/// Last usb 3 port is 15.
pub const USB3_PORTS_END: u8 = 16;

/// Max port number. Review the following before changing this:
///     HCSPARAMS1, portsc, spcap1.3 and spcap2.3.
pub const MAX_PORTS: u8 = USB3_PORTS_END;

/// Cap register length.
pub const XHCI_CAPLENGTH: u8 = 0x20;
/// Offset for doorbell register.
pub const XHCI_DBOFF: u32 = 0x00002000;
/// Offset for RTs.
pub const XHCI_RTSOFF: u32 = 0x00003000;

/// Bitmask for the usbcmd register, see spec 5.4.1.
pub const USB_CMD_RUNSTOP: u32 = 1u32 << 0;
/// Bitmask for the usbcmd register, see spec 5.4.1.
pub const USB_CMD_RESET: u32 = 1u32 << 1;
/// Bitmask for the usbcmd register, see spec 5.4.1.
pub const USB_CMD_INTERRUPTER_ENABLE: u32 = 1u32 << 2;

/// Bitmask for the usbsts register, see spec 5.4.2.
pub const USB_STS_HALTED: u32 = 1u32 << 0;
/// Bitmask for the usbsts register, see spec 5.4.2.
pub const USB_STS_EVENT_INTERRUPT: u32 = 1u32 << 3;
/// Bitmask for the usbsts register, see spec 5.4.2.
pub const USB_STS_PORT_CHANGE_DETECT: u32 = 1u32 << 4;
/// Bitmask for the usbsts register, see spec 5.4.2.
pub const USB_STS_CONTROLLER_NOT_READY: u32 = 1u32 << 11;
/// Bitmask for the usbsts register, see spec 5.4.2.
pub const USB_STS_SET_TO_CLEAR_MASK: u32 = 0x0000041C;

/// Bitmask for the crcr register, see spec 5.4.5.
pub const CRCR_RING_CYCLE_STATE: u64 = 1u64 << 0;
/// Bitmask for the crcr register, see spec 5.4.5.
pub const CRCR_COMMAND_STOP: u64 = 1u64 << 1;
/// Bitmask for the crcr register, see spec 5.4.5.
pub const CRCR_COMMAND_ABORT: u64 = 1u64 << 2;
/// Bitmask for the crcr register, see spec 5.4.5.
pub const CRCR_COMMAND_RING_RUNNING: u64 = 1u64 << 3;
/// Bitmask for the crcr register, see spec 5.4.5.
pub const CRCR_COMMAND_RING_POINTER: u64 = 0xFFFFFFFFFFFFFFC0;

/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_CURRENT_CONNECT_STATUS: u32 = 1u32 << 0;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_PORT_ENABLED: u32 = 1u32 << 1;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_PORT_RESET: u32 = 1u32 << 4;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_PORT_LINK_STATE_MASK: u32 = 0x000001E0;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_PORT_POWER: u32 = 1u32 << 9;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_CONNECT_STATUS_CHANGE: u32 = 1u32 << 17;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_PORT_ENABLED_DISABLED_CHANGE: u32 = 1u32 << 18;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_PORT_RESET_CHANGE: u32 = 1u32 << 21;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_WARM_PORT_RESET: u32 = 1u32 << 31;
/// Bitmask for portsc register, see spec 5.4.8.
pub const PORTSC_SET_TO_CLEAR_MASK: u32 = 0x00FE0002;

/// Bitmask for iman registers, see spec 5.5.2.1.
pub const IMAN_INTERRUPT_PENDING: u32 = 1u32 << 0;
/// Bitmask for iman registers, see spec 5.5.2.1.
pub const IMAN_INTERRUPT_ENABLE: u32 = 1u32 << 1;
/// Bitmask for iman registers, see spec 5.5.2.1.
pub const IMAN_SET_TO_CLEAR_MASK: u32 = 0x00000001;

/// Bitmask for imod registers, see spec 5.5.2.2.
pub const IMOD_INTERRUPT_MODERATION_INTERVAL: u32 = 0xFFFF;
/// Bitmask for imod registers, see spec 5.5.2.2.
pub const IMOD_INTERRUPT_MODERATION_COUNTER_OFFSET: u8 = 16;

/// Bitmask for erstsz registers, see 5.5.2.3.
pub const ERSTSZ_SEGMENT_TABLE_SIZE: u32 = 0xFFFF;

/// Bitmask for erstba registers, see 5.5.2.3.
pub const ERSTBA_SEGMENT_TABLE_BASE_ADDRESS: u64 = 0xFFFFFFFFFFFFFFC0;

/// Bitmask for erdp registers, see 5.5.2.3.
pub const ERDP_EVENT_HANDLER_BUSY: u64 = 1u64 << 3;
/// Bitmask for erdp registers, see 5.5.2.3.
pub const ERDP_EVENT_RING_DEQUEUE_POINTER: u64 = 0xFFFFFFFFFFFFFFF0;
/// Bitmask for erdp registers, see 5.5.2.3.
pub const ERDP_SET_TO_CLEAR_MASK: u64 = 0x0000000000000008;

/// Bitmask for doorbell registers.
pub const DOORBELL_TARGET: u32 = 0xFF;
/// Offset of stream id.
pub const DOORBELL_STREAM_ID_OFFSET: u32 = 16;

/// Bitmask for structural parameter registers.
pub const HCSPARAMS1_MAX_INTERRUPTERS_MASK: u32 = 0x7FF00;
/// Offset of max interrupters.
pub const HCSPARAMS1_MAX_INTERRUPTERS_OFFSET: u32 = 8;
/// Mask to get max slots.
pub const HCSPARAMS1_MAX_SLOTS_MASK: u32 = 0xFF;

/// Bitmask for extended capabilities registers.
pub const SPCAP_PORT_COUNT_MASK: u32 = 0xFF00;
/// Offset of port count.
pub const SPCAP_PORT_COUNT_OFFSET: u32 = 8;

/// Helper function for validating slot_id.
pub fn valid_slot_id(slot_id: u8) -> bool {
    // slot id count from 1.
    slot_id > 0 && slot_id <= MAX_SLOTS
}

/// XhciRegs hold all xhci registers.
pub struct XhciRegs {
    pub usbcmd: Register<u32>,
    pub usbsts: Register<u32>,
    pub dnctrl: Register<u32>,
    pub crcr: Register<u64>,
    pub dcbaap: Register<u64>,
    pub config: Register<u64>,
    pub portsc: Vec<Register<u32>>,
    pub doorbells: Vec<Register<u32>>,
    pub iman: Register<u32>,
    pub imod: Register<u32>,
    pub erstsz: Register<u32>,
    pub erstba: Register<u64>,
    pub erdp: Register<u64>,
}

/// This function returns mmio space definition for xhci. See Xhci spec chapter 5
/// for details.
pub fn init_xhci_mmio_space_and_regs() -> (RegisterSpace, XhciRegs) {
    let mut mmio = RegisterSpace::new();

    /* Host Controller Capability Registers */
    mmio.add_register(
        // CAPLENGTH
        static_register!(
        ty: u8,
        offset: 0x00,
        value: XHCI_CAPLENGTH, // Operation register start at offset 0x20
        ),
    );
    mmio.add_register(
        // HCIVERSION
        static_register!(
        ty: u16,
        offset: 0x02,
        value: 0x0110,// Revision 1.1
        ),
    );
    mmio.add_register(
        // HCSPARAMS1
        static_register!(
        ty: u32,
        offset: 0x04,
        value: 0x10000110, // max_slots = 16, max_interrupters = 1, max_ports = 16
        ),
    );

    mmio.add_register(
        // HCSPARAMS2
        static_register!(
        ty: u32,
        offset: 0x08,
        // Maximum number of event ring segment table entries = 32k
        // No scratchpad buffers.
        value: 0xf0,
        ),
    );

    mmio.add_register(
        // HCSPARAM3
        static_register!(
        ty: u32,
        offset: 0x0c,

        // Exit latencies for U1 (standby with fast exit) and U2 (standby with
        // slower exit) power states. We use the max values:
        // - U1 to U0: < 10 us
        // - U2 to U1: < 2047 us
        value: 0x07FF000A,
        ),
    );

    mmio.add_register(
        // HCCPARAMS1
        static_register!(
        ty: u32,
        offset: 0x10,
        // Supports 64 bit addressing
        // Max primary stream array size = 0 (streams not supported).
        // Extended capabilities pointer = 0xC000 offset from base.
        value: 0x30000501,
        ),
    );
    mmio.add_register(
        // DBOFF
        static_register!(
        ty: u32,
        offset: 0x14,
        value: XHCI_DBOFF, // Doorbell array offset 0x2000 from base.
        ),
    );

    mmio.add_register(
        // RTSOFF
        static_register!(
        ty: u32,
        offset: 0x18,
        value: XHCI_RTSOFF, // Runtime registers offset 0x3000 from base.
        ),
    );

    mmio.add_register(
        // HCCPARAMS2
        static_register!(
        ty: u32,
        offset: 0x1c,
        value: 0,
        ),
    );
    /* End of Host Controller Capability Registers */

    /* Host Controller Operational Registers */
    let usbcmd = register!(
        name: "usbcmd",
        ty: u32,
        offset: 0x20,
        reset_value: 0,
        guest_writeable_mask: 0x00002F0F,
        guest_write_1_to_clear_mask: 0,
    );
    mmio.add_register(usbcmd.clone());

    let usbsts = register!(
        name: "usbsts",
        ty: u32,
        offset: 0x24,
        reset_value: 0x00000001,
        guest_writeable_mask: 0x0000041C,
        guest_write_1_to_clear_mask: 0x0000041C,
    );
    mmio.add_register(usbsts.clone());

    mmio.add_register(
        //  Pagesize
        static_register!(
        ty: u32,
        offset: 0x28,
        value: 0x00000001,
        ),
    );

    let dnctrl = register!(
        name: "dnctrl",
        ty: u32,
        offset: 0x34,
        reset_value: 0,
        guest_writeable_mask: 0x0000FFFF,
        guest_write_1_to_clear_mask: 0,
    );
    mmio.add_register(dnctrl.clone());

    let crcr = register!(
        name: "crcr",
        ty: u64,
        offset: 0x38,
        reset_value: 9,
        guest_writeable_mask: 0xFFFFFFFFFFFFFFC7,
        guest_write_1_to_clear_mask: 0,
    );
    mmio.add_register(crcr.clone());

    let dcbaap = register!(
        name: "dcbaap",
        ty: u64,
        offset: 0x50,
        reset_value: 0x0,
        guest_writeable_mask: 0xFFFFFFFFFFFFFFC0,
        guest_write_1_to_clear_mask: 0,
    );
    mmio.add_register(dcbaap.clone());

    let config = register!(
        name: "config",
        ty: u64,
        offset: 0x58,
        reset_value: 0,
        guest_writeable_mask: 0x0000003F,
        guest_write_1_to_clear_mask: 0,
    );
    mmio.add_register(config.clone());

    let portsc = register_array!(
        name: "portsc",
        ty: u32,
        cnt: MAX_PORTS,
        base_offset: 0x420,
        stride: 16,
        reset_value: 0x000002A0,
        guest_writeable_mask: 0x8EFFC3F2,
        guest_write_1_to_clear_mask: 0x00FE0002,);
    mmio.add_register_array(&portsc);

    // Portpmsc.
    mmio.add_register_array(&register_array!(
            name: "portpmsc",
            ty: u32,
            cnt: MAX_PORTS,
            base_offset: 0x424,
            stride: 16,
            reset_value: 0,
            guest_writeable_mask: 0x0001FFFF,
            guest_write_1_to_clear_mask: 0,));

    // Portli
    mmio.add_register_array(&register_array!(
            name: "portli",
            ty: u32,
            cnt: MAX_PORTS,
            base_offset: 0x428,
            stride: 16,
            reset_value: 0,
            guest_writeable_mask: 0,
            guest_write_1_to_clear_mask: 0,));

    // Porthlpmc
    mmio.add_register_array(&register_array!(
            name: "porthlpmc",
            ty: u32,
            cnt: MAX_PORTS,
            base_offset: 0x42c,
            stride: 16,
            reset_value: 0,
            guest_writeable_mask: 0x00003FFF,
            guest_write_1_to_clear_mask: 0,));

    let doorbells = register_array!(
        name: "doorbell",
        ty: u32,
        cnt: MAX_SLOTS + 1, //  Must be equal to max_slots + 1
        base_offset: 0x2000,
        stride: 4,
        reset_value: 0,
        guest_writeable_mask: 0xFFFF00FF,
        guest_write_1_to_clear_mask: 0,);
    mmio.add_register_array(&doorbells);

    /*Runtime Registers */

    mmio.add_register(
        // mfindex
        static_register!(
        ty: u32,
        offset: 0x3000,
        value: 0, // 4 ports starting at port 5
        ),
    );

    /* Reg Array for interrupters */
    // Although the following should be register arrays, we only have one interrupter.
    let iman = register!(
            name: "iman",
            ty: u32,
            offset: 0x3020,
            reset_value: 0,
            guest_writeable_mask: 0x00000003,
            guest_write_1_to_clear_mask: 0x00000001,);
    mmio.add_register(iman.clone());

    let imod = register!(
            name: "imod",
            ty: u32,
            offset: 0x3024,
            reset_value: 0x00000FA0,
            guest_writeable_mask: 0xFFFFFFFF,
            guest_write_1_to_clear_mask: 0,);
    mmio.add_register(imod.clone());

    let erstsz = register!(
        name: "erstsz",
        ty: u32,
        offset: 0x3028,
        reset_value: 0,
        guest_writeable_mask: 0x0000FFFF,
        guest_write_1_to_clear_mask: 0,);
    mmio.add_register(erstsz.clone());

    let erstba = register!(
        name: "erstba",
        ty: u64,
        offset: 0x3030,
        reset_value: 0,
        guest_writeable_mask: 0xFFFFFFFFFFFFFFC0,
        guest_write_1_to_clear_mask: 0,);
    mmio.add_register(erstba.clone());

    let erdp = register!(
        name: "erdp",
        ty: u64,
        offset: 0x3038,
        reset_value: 0,
        guest_writeable_mask: 0xFFFFFFFFFFFFFFFF,
        guest_write_1_to_clear_mask: 0x0000000000000008,);
    mmio.add_register(erdp.clone());

    /* End of Runtime Registers */

    let xhci_regs = XhciRegs {
        usbcmd,
        usbsts,
        dnctrl,
        crcr,
        dcbaap,
        config,
        portsc,
        doorbells,
        iman,
        imod,
        erstsz,
        erstba,
        erdp,
    };

    /* End of Host Controller Operational Registers */

    /* Extended Capability Registers */

    // Extended capability registers. Base offset defined by hccparams1.
    // Each set of 4 registers represents a "Supported Protocol" extended
    // capability.  The first capability indicates that ports 1-8 are USB 2.0. There is no USB 3.0
    // port for now. See xHCI spec 7.1 & 7.2 for more details.
    mmio.add_register(
        // spcap 1.1
        static_register!(
        ty: u32,
        offset: 0xc000,
        // "Supported Protocol" capability.
        // Next capability starts after 0x40 dwords.
        // USB 2.0. Revision 2.0.
        value: 0x02004002,
        ),
    );
    mmio.add_register(
        // spcap 1.2
        static_register!(
        ty: u32,
        offset: 0xc004,
        value: 0x20425355, // Name string = "USB "
        ),
    );
    mmio.add_register(
        // spcap 1.3
        static_register!(
        ty: u32,
        offset: 0xc008,
        value: 0x00000801, // 8 ports starting at port 1. See USB2_PORTS_START and USB2_PORTS_END.
        ),
    );

    mmio.add_register(
        // spcap 1.4
        static_register!(
        ty: u32,
        offset: 0xc00c,
        // The specification says that this shall be set to 0.
        // Section 7.2.2.1.4.
        value: 0,
        ),
    );

    mmio.add_register(
        // spcap 2.1
        static_register!(
        ty: u32,
        offset: 0xc100,
        // "Supported Protocol" capability.
        // Not next capability.
        // USB 3.0. Revision 2.0.
        value: 0x03000002,
        ),
    );
    mmio.add_register(
        // spcap 2.2
        static_register!(
        ty: u32,
        offset: 0xc104,
        value: 0x20425355, // Name string = "USB "
        ),
    );
    mmio.add_register(
        // spcap 2.3
        static_register!(
        ty: u32,
        offset: 0xc108,
        value: 0x00000809, // 8 ports starting at port 9. See USB3_PORTS_START and USB3_PORTS_END.
        ),
    );

    mmio.add_register(
        // spcap 2.4
        static_register!(
        ty: u32,
        offset: 0xc10c,
        // The specification says that this shall be set to 0.
        // Section 7.2.2.1.4.
        value: 0,
        ),
    );

    /* End of Host Controller Operational Registers */

    (mmio, xhci_regs)
}
