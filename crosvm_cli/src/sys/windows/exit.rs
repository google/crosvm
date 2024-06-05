// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Enum and Anyhow helpers to set the process exit code.

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use anyhow::Context;
use win_util::ProcessType;

pub type ExitCode = i32;

#[derive(Debug)]
pub struct ExitCodeWrapper(pub ExitCode);

impl Display for ExitCodeWrapper {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "exit code: {} = 0x{:08x}", self.0, self.0)
    }
}

/// Trait for attaching context with process exit codes to a std::result::Result.
pub trait ExitContext<T, E> {
    fn exit_code<X>(self, exit_code: X) -> anyhow::Result<T>
    where
        X: Into<ExitCode>;

    fn exit_context<X, C>(self, exit_code: X, context: C) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static;

    fn with_exit_context<X, C, F>(self, exit_code: X, f: F) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<T, E> ExitContext<T, E> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn exit_code<X>(self, exit_code: X) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
    }

    fn exit_context<X, C>(self, exit_code: X, context: C) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
            .context(context)
    }

    fn with_exit_context<X, C, F>(self, exit_code: X, f: F) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
            .with_context(f)
    }
}

/// Trait for attaching context with process exit codes to an anyhow::Result.
pub trait ExitContextAnyhow<T> {
    fn exit_code<X>(self, exit_code: X) -> anyhow::Result<T>
    where
        X: Into<ExitCode>;

    fn exit_context<X, C>(self, exit_code: X, context: C) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static;

    fn with_exit_context<X, C, F>(self, exit_code: X, f: F) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    fn to_exit_code(&self) -> Option<ExitCode>;
}

impl<T> ExitContextAnyhow<T> for anyhow::Result<T> {
    fn exit_code<X>(self, exit_code: X) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
    }

    fn exit_context<X, C>(self, exit_code: X, context: C) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
            .context(context)
    }

    fn with_exit_context<X, C, F>(self, exit_code: X, f: F) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
            .with_context(f)
    }

    fn to_exit_code(&self) -> Option<ExitCode> {
        self.as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<ExitCodeWrapper>())
            .map(|w| w.0)
    }
}

/// Trait for attaching context with process exit codes to an Option.
pub trait ExitContextOption<T> {
    fn exit_code<X>(self, exit_code: X) -> anyhow::Result<T>
    where
        X: Into<ExitCode>;

    fn exit_context<X, C>(self, exit_code: X, context: C) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static;

    fn with_exit_context<X, C, F>(self, exit_code: X, f: F) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<T> ExitContextOption<T> for std::option::Option<T> {
    fn exit_code<X>(self, exit_code: X) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
    }

    fn exit_context<X, C>(self, exit_code: X, context: C) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
            .context(context)
    }

    fn with_exit_context<X, C, F>(self, exit_code: X, f: F) -> anyhow::Result<T>
    where
        X: Into<ExitCode>,
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.context(ExitCodeWrapper(exit_code.into()))
            .with_context(f)
    }
}

#[macro_export]
macro_rules! bail_exit_code {
    ($exit_code:literal, $msg:literal $(,)?) => {
        return Err(anyhow!($msg)).exit_code($exit_code)
    };
    ($exit_code:literal, $err:expr $(,)?) => {
        return Err(anyhow!($err)).exit_code($exit_code)
    };
    ($exit_code:literal, $fmt:expr, $($arg:tt)*) => {
        return Err(anyhow!($fmt, $($arg)*)).exit_code($exit_code)
    };
    ($exit_code:expr, $msg:literal $(,)?) => {
        return Err(anyhow!($msg)).exit_code($exit_code)
    };
    ($exit_code:expr, $err:expr $(,)?) => {
        return Err(anyhow!($err)).exit_code($exit_code)
    };
    ($exit_code:expr, $fmt:expr, $($arg:tt)*) => {
        return Err(anyhow!($fmt, $($arg)*)).exit_code($exit_code)
    };
}

#[macro_export]
macro_rules! ensure_exit_code {
    ($cond:expr, $exit_code:literal $(,)?) => {
        if !$cond {
            bail_exit_code!($exit_code, concat!("Condition failed: `", stringify!($cond), "`"));
        }
    };
    ($cond:expr, $exit_code:literal, $msg:literal $(,)?) => {
        if !$cond {
            bail_exit_code!($exit_code, $msg);
        }
    };
    ($cond:expr, $exit_code:literal, $err:expr $(,)?) => {
        if !$cond {
            bail_exit_code!($exit_code, $err);
        }
    };
    ($cond:expr, $exit_code:literal, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            bail_exit_code!($exit_code, $fmt, $($arg)*);
        }
    };
    ($cond:expr, $exit_code:expr $(,)?) => {
        if !$cond {
            bail_exit_code!($exit_code, concat!("Condition failed: `", stringify!($cond), "`"));
        }
    };
    ($cond:expr, $exit_code:expr, $msg:literal $(,)?) => {
        if !$cond {
            bail_exit_code!($exit_code, $msg);
        }
    };
    ($cond:expr, $exit_code:expr, $err:expr $(,)?) => {
        if !$cond {
            bail_exit_code!($exit_code, $err);
        }
    };
    ($cond:expr, $exit_code:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            bail_exit_code!($exit_code, $fmt, $($arg)*);
        }
    };
}

#[allow(clippy::enum_clike_unportable_variant)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    // Windows process exit codes triggered by the kernel tend to be NTSTATUS, so we treat
    // our error codes as NTSTATUS to avoid clashing. This means we set the vendor bit. We also
    // set the severity to error. As these all set in the MSB, we can write this as a prefix of
    // 0xE0.
    //
    // Because of how these error codes are used in CommandType, we can only use the lower two
    // bytes of the u32 for our error codes; in other words, the legal range is
    // [0xE0000000, 0xE000FFFF].
    AddGpuDeviceMemory = 0xE0000001,
    AddIrqChipVcpu = 0xE0000002,
    AddPmemDeviceMemory = 0xE0000003,
    AllocateGpuDeviceAddress = 0xE0000004,
    AllocatePmemDeviceAddress = 0xE0000005,
    BlockDeviceNew = 0xE0000006,
    BuildVm = 0xE0000007,
    ChownTpmStorage = 0xE0000008,
    CloneEvent = 0xE000000A,
    CloneVcpu = 0xE000000B,
    ConfigureVcpu = 0xE000000C,
    CreateConsole = 0xE000000E,
    CreateDisk = 0xE000000F,
    CreateEvent = 0xE0000010,
    CreateGralloc = 0xE0000011,
    CreateGvm = 0xE0000012,
    CreateSocket = 0xE0000013,
    CreateTapDevice = 0xE0000014,
    CreateTimer = 0xE0000015,
    CreateTpmStorage = 0xE0000016,
    CreateVcpu = 0xE0000017,
    CreateWaitContext = 0xE0000018,
    Disk = 0xE0000019,
    DiskImageLock = 0xE000001A,
    DropCapabilities = 0xE000001B,
    EventDeviceSetup = 0xE000001C,
    EnableHighResTimer = 0xE000001D,
    HandleCreateQcowError = 0xE000001E,
    HandleVmRequestError = 0xE0000020,
    InitSysLogError = 0xE0000021,
    InputDeviceNew = 0xE0000022,
    InputEventsOpen = 0xE0000023,
    InvalidRunArgs = 0xE0000025,
    InvalidSubCommand = 0xE0000026,
    InvalidSubCommandArgs = 0xE0000027,
    InvalidWaylandPath = 0xE0000028,
    LoadKernel = 0xE0000029,
    MissingCommandArg = 0xE0000030,
    ModifyBatteryError = 0xE0000031,
    NetDeviceNew = 0xE0000032,
    OpenAcpiTable = 0xE0000033,
    OpenAndroidFstab = 0xE0000034,
    OpenBios = 0xE0000035,
    OpenInitrd = 0xE0000036,
    OpenKernel = 0xE0000037,
    OpenVinput = 0xE0000038,
    PivotRootDoesntExist = 0xE0000039,
    PmemDeviceImageTooBig = 0xE000003A,
    PmemDeviceNew = 0xE000003B,
    ReadMemAvailable = 0xE000003C,
    RegisterBalloon = 0xE000003D,
    RegisterBlock = 0xE000003E,
    RegisterGpu = 0xE000003F,
    RegisterNet = 0xE0000040,
    RegisterP9 = 0xE0000041,
    RegisterRng = 0xE0000042,
    RegisterWayland = 0xE0000043,
    ReserveGpuMemory = 0xE0000044,
    ReserveMemory = 0xE0000045,
    ReservePmemMemory = 0xE0000046,
    ResetTimer = 0xE0000047,
    RngDeviceNew = 0xE0000048,
    RunnableVcpu = 0xE0000049,
    SettingSignalMask = 0xE000004B,
    SpawnVcpu = 0xE000004D,
    SysUtil = 0xE000004E,
    Timer = 0xE000004F,
    ValidateRawDescriptor = 0xE0000050,
    VirtioPciDev = 0xE0000051,
    WaitContextAdd = 0xE0000052,
    WaitContextDelete = 0xE0000053,
    WhpxSetupError = 0xE0000054,
    VcpuFailEntry = 0xE0000055,
    VcpuRunError = 0xE0000056,
    VcpuShutdown = 0xE0000057,
    VcpuSystemEvent = 0xE0000058,
    WaitUntilRunnable = 0xE0000059,
    CreateControlServer = 0xE000005A,
    CreateTube = 0xE000005B,
    UsbError = 0xE000005E,
    GuestMemoryLayout = 0xE000005F,
    CreateVm = 0xE0000060,
    CreateGuestMemory = 0xE0000061,
    CreateIrqChip = 0xE0000062,
    SpawnIrqThread = 0xE0000063,
    ConnectTube = 0xE0000064,
    BalloonDeviceNew = 0xE0000065,
    BalloonStats = 0xE0000066,
    OpenCompositeFooterFile = 0xE0000068,
    OpenCompositeHeaderFile = 0xE0000069,
    OpenCompositeImageFile = 0xE0000070,
    CreateCompositeDisk = 0xE0000071,
    MissingControlTube = 0xE0000072,
    TubeTransporterInit = 0xE0000073,
    TubeFailure = 0xE0000074,
    ProcessSpawnFailed = 0xE0000075,
    LogFile = 0xE0000076,
    CreateZeroFiller = 0xE0000077,
    GenerateAcpi = 0xE0000078,
    WaitContextWait = 0xE0000079,
    SetSigintHandler = 0xE000007A,
    KilledBySignal = 0xE000007B,
    BrokerDeviceExitedTimeout = 0xE000007C,
    BrokerMainExitedTimeout = 0xE000007D,
    MemoryTooLarge = 0xE000007E,
    BrokerMetricsExitedTimeout = 0xE000007F,
    MetricsController = 0xE0000080,
    SwiotlbTooLarge = 0xE0000081,
    UserspaceVsockDeviceNew = 0xE0000082,
    VhostUserBlockDeviceNew = 0xE0000083,
    CrashReportingInit = 0xE0000084,
    StartBackendDevice = 0xE0000085,
    ConfigureHotPlugDevice = 0xE0000086,
    InvalidHotPlugKey = 0xE0000087,
    InvalidVfioPath = 0xE0000088,
    NoHotPlugBus = 0xE0000089,
    SandboxError = 0xE000008A,
    Pstore = 0xE000008B,
    ProcessInvariantsInit = 0xE000008C,
    VirtioVhostUserDeviceNew = 0xE000008D,
    CloneTube = 0xE000008E,
    VhostUserGpuDeviceNew = 0xE000008F,
    CreateAsyncDisk = 0xE0000090,
    CreateDiskCheckAsyncOkError = 0xE0000091,
    VhostUserNetDeviceNew = 0xE0000092,
    BrokerSigtermTimeout = 0xE0000093,
    SpawnVcpuMonitor = 0xE0000094,
    NoDefaultHypervisor = 0xE0000095,
    TscCalibrationFailed = 0xE0000096,
    UnknownError = 0xE0000097,
    CommonChildSetupError = 0xE0000098,
    CreateImeThread = 0xE0000099,
    OpenDiskImage = 0xE000009A,
    VirtioSoundDeviceNew = 0xE000009B,
    StartSpu = 0xE000009C,
    SandboxCreateProcessAccessDenied = 0xE000009D,
    SandboxCreateProcessElevationRequired = 0xE000009E,
    BalloonSizeInvalid = 0xE000009F,
    VhostUserSndDeviceNew = 0xE00000A0,
    FailedToCreateControlServer = 0xE00000A1,
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        exit as ExitCode
    }
}

// Bitfield masks for NTSTATUS & our extension of the format. See to_process_type_error for details.
mod bitmasks {
    pub const FACILITY_FIELD_LOWER_MASK: u32 = u32::from_be_bytes([0x00, 0x3F, 0x00, 0x00]);
    pub const EXTRA_DATA_FIELD_MASK: u32 = u32::from_be_bytes([0x0F, 0xC0, 0x00, 0x00]);
    #[cfg(test)]
    pub const EXTRA_DATA_FIELD_COMMAND_TYPE_MASK: u32 =
        u32::from_be_bytes([0x07, 0xC0, 0x00, 0x00]);
    pub const EXTRA_DATA_FIELD_OVERFLOW_BIT_MASK: u32 =
        u32::from_be_bytes([0x08, 0x00, 0x00, 0x00]);
    pub const VENDOR_FIELD_MASK: u32 = u32::from_be_bytes([0x20, 0x00, 0x00, 0x00]);
    pub const RESERVED_BIT_MASK: u32 = u32::from_be_bytes([0x10, 0x00, 0x00, 0x00]);
    pub const COMMAND_TYPE_MASK: u32 = u32::from_be_bytes([0x00, 0x00, 0x00, 0x1F]);
}
use bitmasks::*;

/// If you are looking for a fun interview question, you have come to the right place. To
/// understand the details of NTSTATUS, which you'll want to do before reading further, visit
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/87fba13e-bf06-450e-83b1-9241dc81e781>.
///
/// This function is unfortunately what happens when you only have six bits to store auxiliary
/// information, and have to fit in with an existing bitfield's schema.
///
/// For reference, the format of the NTSTATUS field is as follows:
///
/// | [31, 30] |      [29]         |      [28]       | [27, 16] | [15, 0] |
/// | Severity |  Customer/vendor  |  N (reserved)   | Facility |  Code   |
///
/// This function packs bits in NTSTATUS results (generally what a Windows exit code should be).
/// There are three primary cases it deals with:
///   1. Vendor specific exits. These are error codes we generate explicitly in crosvm. We will pack
///      these codes with the lower 6 "facility" bits ([21, 16]) set so they can't collide with the
///      other cases (this makes our facility value > FACILITY_MAXIMUM_VALUE). The top 6 bits of the
///      facility field ([27, 22]) will be clear at this point.
///
///   2. Non vendor NTSTATUS exits. These are error codes which come from Windows. We flip the
///      vendor bit on these because we're going to pack the facility field, and leaving it unset
///      would cause us to violate the rule that if the vendor bit is unset, we shouldn't exceed
///      FACILITY_MAXIMUM_VALUE in that field. The top six bits of the facility field ([27, 22])
///      will be clear in this scenario because Windows won't exceed FACILITY_MAXIMUM_VALUE;
///      however, if for some reason we see a non vendor code with any of those bits set, we will
///      fall through to case #3.
///
///   3. Non NTSTATUS errors. We detect these with two heuristics: a) Reserved field is set. b) The
///      facility field has exceeded the bottom six bits ([21, 16]).
///
///      For such cases, we pack as much of the error as we can into the lower 6 bits of the
///      facility field, and code field (2 bytes). In this case, the most significant bit of the
///      facility field is set.
///
/// For all of the cases above, we pack the 5 bits following the most significant bit of the
/// facility field (e.g. [26, 22]) with information about what command type generated this error.
pub fn to_process_type_error(error_code: u32, cmd_type: ProcessType) -> u32 {
    let is_vendor = error_code & VENDOR_FIELD_MASK != 0;

    // The reserved bit is always clear on a NTSTATUS code.
    let is_reserved_bit_clear = error_code & RESERVED_BIT_MASK == 0;

    // The six most significant bits of the facility field are where we'll be storing our
    // command type and whether we have a valid NTSTATUS error. If bits are already set there,
    // it means this isn't a valid NTSTATUS code.
    let is_extra_data_field_clear = error_code & EXTRA_DATA_FIELD_MASK == 0;

    let is_ntstatus = is_reserved_bit_clear && is_extra_data_field_clear;

    // We use the top bit of the facility field to store whether we ran out of space to pack
    // the error. The next five bits are where we store the command type, so we'll shift them
    // into the appropriate position here.
    let command_type = (cmd_type as u32 & COMMAND_TYPE_MASK) << 22;

    match (is_ntstatus, is_vendor) {
        // Valid vendor code
        (true, true) => {
            // Set all the lower facility bits, and attach the command type.
            error_code | FACILITY_FIELD_LOWER_MASK | command_type
        }

        // Valid non-vendor code
        (true, false) => {
            // Set the vendor bit and attach the command type.
            error_code | VENDOR_FIELD_MASK | command_type
        }

        // Not a valid NTSTATUS code.
        _ => {
            // Clear the extra data field, and set the the top bit of the facility field to
            // signal that we didn't have enough space for the full error codes.
            error_code & !EXTRA_DATA_FIELD_MASK | command_type | EXTRA_DATA_FIELD_OVERFLOW_BIT_MASK
        }
    }
}

#[cfg(test)]
mod tests {
    use winapi::shared::ntstatus::STATUS_BAD_INITIAL_PC;

    use super::*;

    #[test]
    fn test_to_process_type_error_ntstatus_vendor() {
        let e = to_process_type_error(Exit::InvalidRunArgs as u32, ProcessType::Main);
        assert_eq!(
            e & EXTRA_DATA_FIELD_COMMAND_TYPE_MASK,
            (ProcessType::Main as u32) << 22
        );
        assert_eq!(e & EXTRA_DATA_FIELD_OVERFLOW_BIT_MASK, 0);

        // This is a valid NTSTATUS error.
        assert_eq!(e & RESERVED_BIT_MASK, 0);

        // Check the actual crosvm error code contained in the NTSTATUS. We don't mutate the
        // severity field, so we don't mask it off. We mask off the facility field entirely because
        // that's where we stored the command type & NTSTATUS validity bit.
        assert_eq!(e & 0xF000FFFF_u32, Exit::InvalidRunArgs as u32);
    }

    #[test]
    fn test_to_process_type_error_ntstatus_non_vendor() {
        let e = to_process_type_error(STATUS_BAD_INITIAL_PC as u32, ProcessType::Main);
        assert_eq!(
            e & EXTRA_DATA_FIELD_COMMAND_TYPE_MASK,
            (ProcessType::Main as u32) << 22
        );
        assert_eq!(e & EXTRA_DATA_FIELD_OVERFLOW_BIT_MASK, 0);

        // This is a valid NTSTATUS error.
        assert_eq!(e & RESERVED_BIT_MASK, 0);

        // Check the actual error code contained in the NTSTATUS. We mask off all our extra data
        // fields and switch off the vendor bit to confirm the actual code was left alone.
        assert_eq!(
            e & !EXTRA_DATA_FIELD_MASK & !VENDOR_FIELD_MASK,
            STATUS_BAD_INITIAL_PC as u32
        );
    }

    #[test]
    fn test_to_process_type_error_wontfit_ntstatus() {
        let e = to_process_type_error(0xFFFFFFFF, ProcessType::Main);
        assert_eq!(
            e & EXTRA_DATA_FIELD_COMMAND_TYPE_MASK,
            (ProcessType::Main as u32) << 22
        );

        // -1 is not a valid NTSTATUS error.
        assert_ne!(e & RESERVED_BIT_MASK, 0);

        // Overflow did occur.
        assert_ne!(e & EXTRA_DATA_FIELD_OVERFLOW_BIT_MASK, 0);

        // Check that we left the rest of the bits (except for our command type field & overflow
        // bit) in the exit code untouched.
        assert_eq!(e & 0xF03FFFFF_u32, 0xF03FFFFF_u32);
    }
}
