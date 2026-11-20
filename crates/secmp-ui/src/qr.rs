// SPDX-License-Identifier: AGPL-3.0-or-later
//! QR codes (ADR-064): the module matrix of a text from the `qrcode` crate (error correction level M, version chosen by the
//! crate) and its rendering into a Slint image, black modules on white with the quiet zone of four modules the standard asks
//! for. The text is a capability or a safety number: the matrix is made when it is shown and dropped with it.

use qrcode::{Color, EcLevel, QrCode};
use slint::{Image, Rgba8Pixel, SharedPixelBuffer};

/// The quiet zone around the code, in modules.
const QUIET: usize = 4;

/// The pixels of one module.
const SCALE: usize = 6;

/// The modules of a QR code, row by row.
#[derive(Clone, PartialEq, Eq)]
pub struct Matrix {
    width: usize,
    dark: Vec<bool>,
}

impl core::fmt::Debug for Matrix {
    /// The size only: the modules are the content.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Matrix({})", self.width)
    }
}

impl Matrix {
    /// The code of `text`; `None` if it does not fit into a QR code.
    #[must_use]
    pub fn of(text: &str) -> Option<Self> {
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
        Some(Self {
            width: code.width(),
            dark: code
                .to_colors()
                .into_iter()
                .map(|c| c == Color::Dark)
                .collect(),
        })
    }

    /// Modules per side.
    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Whether the module in column `x` of row `y` is dark; outside the code, light.
    #[must_use]
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        x < self.width
            && y.checked_mul(self.width)
                .and_then(|row| row.checked_add(x))
                .and_then(|at| self.dark.get(at))
                .copied()
                .unwrap_or(false)
    }

    /// The rows as text: `#` dark, `.` light.
    #[must_use]
    pub fn rows(&self) -> Vec<String> {
        (0..self.width)
            .map(|y| {
                (0..self.width)
                    .map(|x| if self.is_dark(x, y) { '#' } else { '.' })
                    .collect()
            })
            .collect()
    }

    /// The code as an image (black on white, quiet zone included).
    #[must_use]
    pub fn image(&self) -> Image {
        let total = QUIET.saturating_mul(2).saturating_add(self.width);
        let mut data: Vec<u8> = Vec::new();
        for y in 0..total {
            let mut row: Vec<u8> = Vec::new();
            for x in 0..total {
                let dark = x
                    .checked_sub(QUIET)
                    .zip(y.checked_sub(QUIET))
                    .is_some_and(|(mx, my)| self.is_dark(mx, my));
                let pixel: [u8; 4] = if dark {
                    [0, 0, 0, 255]
                } else {
                    [255, 255, 255, 255]
                };
                for _ in 0..SCALE {
                    row.extend_from_slice(&pixel);
                }
            }
            for _ in 0..SCALE {
                data.extend_from_slice(&row);
            }
        }
        let side = u32::try_from(total.saturating_mul(SCALE)).unwrap_or(0);
        Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
            &data, side, side,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P4: the matrix of a fixed string is the checked-in bitmap (version 1, level M, 21 × 21 modules).
    #[test]
    fn qr_matrix_roundtrips_known_string() {
        // generated once from `qrcode` 0.14.1 and frozen; the finder patterns (corners) and the timing pattern (row and
        // column 6) are those of ISO/IEC 18004 version 1
        const EXPECTED: &[&str] = &[
            "#######..####.#######",
            "#.....#.#..##.#.....#",
            "#.###.#.......#.###.#",
            "#.###.#..#..#.#.###.#",
            "#.###.#.#.#.#.#.###.#",
            "#.....#..#..#.#.....#",
            "#######.#.#.#.#######",
            ".........#.##........",
            "#.#.#.#..###....#..#.",
            ".#..#...#.....##...##",
            ".#.##.###.#.#...#####",
            "###.##....#...#.#...#",
            "#.....#.....#.##....#",
            "........####.#.###...",
            "#######..###.#####.##",
            "#.....#....###.##...#",
            "#.###.#.#..#.##.#.###",
            "#.###.#..#....#.#.##.",
            "#.###.#.#.#.#..####.#",
            "#.....#.......##...#.",
            "#######.#.#.#.#.#####",
        ];
        let rows = Matrix::of("SecMPro").map(|m| m.rows()).unwrap_or_default();
        assert_eq!(rows, EXPECTED);
    }
}
