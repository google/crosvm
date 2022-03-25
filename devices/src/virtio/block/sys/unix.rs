use base::iov_max;
use std::cmp::{max, min};

pub const VIRTIO_BLK_F_SEG_MAX: u32 = 2;

pub fn system_block_avail_features() -> u64 {
    1 << VIRTIO_BLK_F_SEG_MAX
}

pub fn get_seg_max(queue_size: u16) -> u32 {
    let seg_max = min(max(iov_max(), 1), u32::max_value() as usize) as u32;

    // Since we do not currently support indirect descriptors, the maximum
    // number of segments must be smaller than the queue size.
    // In addition, the request header and status each consume a descriptor.
    min(seg_max, u32::from(queue_size) - 2)
}
