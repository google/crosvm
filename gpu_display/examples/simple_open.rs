use gpu_display::{GpuDisplay, SurfaceType};

fn main() {
    let mut disp = GpuDisplay::open_x(None::<&str>).unwrap();
    let surface_id = disp
        .create_surface(None, 1280, 1024, SurfaceType::Scanout)
        .unwrap();

    let mem = disp.framebuffer(surface_id).unwrap();
    for y in 0..1024 {
        let mut row = [0u32; 1280];
        for (x, item) in row.iter_mut().enumerate() {
            let b = ((x as f32 / 1280.0) * 256.0) as u32;
            let g = ((y as f32 / 1024.0) * 256.0) as u32;
            *item = b | (g << 8);
        }
        mem.as_volatile_slice()
            .offset(1280 * 4 * y)
            .unwrap()
            .copy_from(&row);
    }
    disp.flip(surface_id);

    while !disp.close_requested(surface_id) {
        disp.dispatch_events().unwrap();
    }
}
