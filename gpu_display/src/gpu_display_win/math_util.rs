// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::any::type_name;
use std::fmt;

use euclid::point2;
use euclid::size2;
use euclid::Size2D;
use num_traits::NumCast;
use winapi::shared::windef::LPPOINT;
use winapi::shared::windef::POINT;
use winapi::shared::windef::RECT;

use super::HostWindowSpace;

pub type Point = euclid::Point2D<i32, HostWindowSpace>;
pub type Rect = euclid::Rect<i32, HostWindowSpace>;
pub type Size = euclid::Size2D<i32, HostWindowSpace>;

pub trait SizeExtension {
    fn create_and_enforce_aspect_ratio(
        original_size: &Self,
        expected_aspect_ratio: f32,
        should_adjust_width: bool,
    ) -> Self;
    fn get_largest_inner_rect_size(original_size: &Self, expected_aspect_ratio: f32) -> Self;
    fn scale(&self, ratio: f32) -> Self;
    fn transpose(&self) -> Self;
    fn shorter_edge(&self) -> i32;
    fn aspect_ratio(&self) -> f32;
    fn is_square(&self) -> bool;
    fn is_landscape(&self) -> bool;
}

impl SizeExtension for Size {
    fn create_and_enforce_aspect_ratio(
        original_size: &Self,
        expected_aspect_ratio: f32,
        should_adjust_width: bool,
    ) -> Self {
        let mut size = *original_size;
        if should_adjust_width {
            size.width = (size.height as f32 * expected_aspect_ratio).round() as i32;
        } else {
            size.height = (size.width as f32 / expected_aspect_ratio).round() as i32;
        }
        size
    }

    fn get_largest_inner_rect_size(original_size: &Self, expected_aspect_ratio: f32) -> Self {
        Size::create_and_enforce_aspect_ratio(
            original_size,
            expected_aspect_ratio,
            /* should_adjust_width */ original_size.aspect_ratio() > expected_aspect_ratio,
        )
    }

    #[inline]
    fn scale(&self, ratio: f32) -> Self {
        size2(
            (self.width as f32 * ratio) as i32,
            (self.height as f32 * ratio) as i32,
        )
    }

    #[inline]
    fn transpose(&self) -> Self {
        size2(self.height, self.width)
    }

    #[inline]
    fn shorter_edge(&self) -> i32 {
        std::cmp::min(self.width, self.height)
    }

    #[inline]
    fn aspect_ratio(&self) -> f32 {
        self.width as f32 / self.height as f32
    }

    #[inline]
    fn is_square(&self) -> bool {
        self.width == self.height
    }

    #[inline]
    fn is_landscape(&self) -> bool {
        self.width > self.height
    }
}

pub trait RectExtension {
    fn to_sys_rect(&self) -> RECT;
}

impl RectExtension for Rect {
    #[inline]
    fn to_sys_rect(&self) -> RECT {
        RECT {
            left: self.min_x(),
            top: self.min_y(),
            right: self.max_x(),
            bottom: self.max_y(),
        }
    }
}

pub trait SysRectExtension {
    fn to_rect(&self) -> Rect;
}

impl SysRectExtension for RECT {
    #[inline]
    fn to_rect(&self) -> Rect {
        Rect::new(
            point2(self.left, self.top),
            size2(self.right - self.left, self.bottom - self.top),
        )
    }
}

pub trait PointExtension {
    fn to_sys_point(&self) -> POINT;
}

impl PointExtension for Point {
    #[inline]
    fn to_sys_point(&self) -> POINT {
        POINT {
            x: self.x,
            y: self.y,
        }
    }
}

pub trait SysPointExtension {
    fn to_point(&self) -> Point;
    fn as_mut_ptr(&mut self) -> LPPOINT;
}

impl SysPointExtension for POINT {
    #[inline]
    fn to_point(&self) -> Point {
        point2(self.x, self.y)
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> LPPOINT {
        self as LPPOINT
    }
}

pub trait Size2DCheckedCast<U>: Sized {
    fn checked_cast<T: NumCast>(self) -> Size2D<T, U>;
}

impl<T, U> Size2DCheckedCast<U> for Size2D<T, U>
where
    T: NumCast + Copy + fmt::Debug,
{
    fn checked_cast<NewT: NumCast>(self) -> Size2D<NewT, U> {
        self.try_cast::<NewT>().unwrap_or_else(|| {
            panic!(
                "Cannot cast {:?} from {} to {}",
                self,
                type_name::<T>(),
                type_name::<NewT>(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn largest_inner_rect_size_when_outer_is_wider() {
        assert_eq!(
            Size::get_largest_inner_rect_size(
                /* original_size */ &size2(1600, 900),
                /* expected_aspect_ratio */ 0.5
            ),
            size2(450, 900)
        );
    }

    #[test]
    fn largest_inner_rect_size_when_outer_is_taller() {
        assert_eq!(
            Size::get_largest_inner_rect_size(
                /* original_size */ &size2(900, 1600),
                /* expected_aspect_ratio */ 3.0
            ),
            size2(900, 300)
        );
    }
}
