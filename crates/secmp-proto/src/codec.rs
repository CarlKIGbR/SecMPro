// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed-layout big-endian encoding (spec §4.1): a bounded [`Reader`], a [`Writer`], the [`Encode`]/[`Decode`]
//! traits and ISO/IEC 7816-4 padding.
//!
//! Decoding is total: every read either yields exactly the requested bytes or [`Error::Rejected`]; offsets and
//! lengths are only ever split off the remaining input (`split_at_checked`) or converted with `try_from`, never
//! computed with unchecked arithmetic. [`Decode::decode`] requires the input to be consumed exactly (spec §4.1
//! consistency rule), so a structure has exactly one encoding.

use crate::error::{Error, Result};

/// The ISO/IEC 7816-4 padding marker (spec §4.1).
const PAD_MARKER: u8 = 0x80;

/// A cursor over the bytes being decoded.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The next `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(Error::Rejected)?;
        self.rest = tail;
        Ok(head)
    }

    /// The next `N` bytes as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Rejected)
    }

    /// The next `N` bytes as a boxed array (for the large opaque fields).
    pub(crate) fn boxed<const N: usize>(&mut self) -> Result<Box<[u8; N]>> {
        boxed(self.take(N)?)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A presence or boolean byte: 0x00 or 0x01, anything else rejects (spec §4.1).
    pub(crate) fn flag(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Rejected),
        }
    }

    /// The byte `expected`, or reject (`ver`, type and constant bytes).
    pub(crate) fn expect(&mut self, expected: u8) -> Result<()> {
        if self.u8()? == expected {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    }

    /// `len u8 ‖ bytes`.
    pub(crate) fn prefixed_u8(&mut self) -> Result<&'a [u8]> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    /// `len u16 ‖ bytes`.
    pub(crate) fn prefixed_u16(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    /// Everything left.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.rest)
    }

    /// Nothing may be left (spec §4.1: the enclosing structure is fully consumed).
    pub(crate) fn finish(&self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    }
}

/// `bytes` as a boxed array of exactly `N` bytes.
pub(crate) fn boxed<const N: usize>(bytes: &[u8]) -> Result<Box<[u8; N]>> {
    bytes
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| Error::Rejected)
}

/// An encoding being built.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.bytes(&v.to_be_bytes());
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.bytes(&v.to_be_bytes());
    }

    /// A presence or boolean byte.
    pub(crate) fn flag(&mut self, v: bool) {
        self.u8(u8::from(v));
    }

    /// `len u8 ‖ bytes`; rejects more than 255 bytes.
    pub(crate) fn prefixed_u8(&mut self, bytes: &[u8]) -> Result<()> {
        self.u8(u8::try_from(bytes.len()).map_err(|_| Error::Rejected)?);
        self.bytes(bytes);
        Ok(())
    }

    /// `len u16 ‖ bytes`; rejects more than 65535 bytes.
    pub(crate) fn prefixed_u16(&mut self, bytes: &[u8]) -> Result<()> {
        self.u16(u16::try_from(bytes.len()).map_err(|_| Error::Rejected)?);
        self.bytes(bytes);
        Ok(())
    }

    /// The bytes written so far.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// A structure with a canonical encoding.
pub trait Encode {
    /// Append the encoding to `w` (composition inside this crate; use [`Encode::encode`]).
    ///
    /// # Errors
    /// [`Error::Rejected`] if the value has no encoding (a length or count out of range, a body too large for
    /// its fixed size).
    fn encode_to(&self, w: &mut Writer) -> Result<()>;

    /// The encoding.
    ///
    /// # Errors
    /// As [`Encode::encode_to`].
    fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        self.encode_to(&mut w)?;
        Ok(w.into_vec())
    }
}

/// A structure decoded from exactly one encoding.
pub trait Decode: Sized {
    /// Read the structure from the front of `r` (composition inside this crate; use [`Decode::decode`]).
    ///
    /// # Errors
    /// [`Error::Rejected`] on any malformed input.
    fn decode_from(r: &mut Reader<'_>) -> Result<Self>;

    /// Decode `bytes`, which must be exactly one encoding (nothing left over).
    ///
    /// # Errors
    /// [`Error::Rejected`] on any malformed input or trailing bytes.
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let value = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(value)
    }
}

/// ISO/IEC 7816-4 padding (spec §4.1): `fields ‖ 0x80 ‖ 0x00…` to exactly `size` bytes.
///
/// # Errors
/// [`Error::Rejected`] if the fields leave no room for the marker.
pub fn pad(fields: &[u8], size: usize) -> Result<Vec<u8>> {
    // zeros of the full size, then the fields and the marker over their front (no fill loop: the Kani harnesses
    // re-encode 4336-byte frames)
    let mut out = vec![0; size];
    let (head, tail) = out
        .split_at_mut_checked(fields.len())
        .ok_or(Error::Rejected)?;
    head.copy_from_slice(fields);
    *tail.first_mut().ok_or(Error::Rejected)? = PAD_MARKER;
    Ok(out)
}

/// The fields of a padded structure: `bytes` must be exactly `size` long, and its last non-zero byte must be the
/// 0x80 marker (every byte after it zero). The inverse of [`pad`]; exactly one encoding per value.
///
/// # Errors
/// [`Error::Rejected`] on a wrong size, a missing marker or a non-zero byte after it.
pub fn unpad(bytes: &[u8], size: usize) -> Result<&[u8]> {
    if bytes.len() != size {
        return Err(Error::Rejected);
    }
    let marker = bytes.iter().rposition(|b| *b != 0).ok_or(Error::Rejected)?;
    let (fields, tail) = bytes.split_at_checked(marker).ok_or(Error::Rejected)?;
    if tail.first() == Some(&PAD_MARKER) {
        Ok(fields)
    } else {
        Err(Error::Rejected)
    }
}

/// Kani stub (`crate::kani_proofs`): an over-approximation of [`unpad`] for the frame harnesses — for an input of
/// the right size it returns *any* proper prefix, or rejects. Every result of the real `unpad` is among these, so
/// a command decoder proven on the stub's output is proven on every field string a frame can carry; `unpad` itself
/// is proven by the `padding` harness.
#[cfg(kani)]
pub(crate) mod kani_stubs {
    use crate::error::{Error, Result};

    pub(crate) fn unpad(bytes: &[u8], size: usize) -> Result<&[u8]> {
        if bytes.len() != size || kani::any() {
            return Err(Error::Rejected);
        }
        let n: usize = kani::any();
        kani::assume(n < size);
        bytes.get(..n).ok_or(Error::Rejected)
    }
}

/// `value` encoded and padded to `size`.
pub(crate) fn encode_padded(value: &impl Encode, size: usize) -> Result<Vec<u8>> {
    pad(&value.encode()?, size)
}

/// Decode a padded structure of `size` bytes whose fields are `T`.
pub(crate) fn decode_padded<T: Decode>(bytes: &[u8], size: usize) -> Result<T> {
    T::decode(unpad(bytes, size)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_is_bounded_and_exact() {
        let mut r = Reader::new(&[1, 0, 2, 0, 0, 3]);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.u16(), Ok(2));
        assert_eq!(r.u32(), Err(Error::Rejected), "three bytes left");
        let mut r = Reader::new(&[0, 0, 0, 3]);
        assert_eq!(r.u32(), Ok(3));
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(r.u8(), Err(Error::Rejected));
        let mut r = Reader::new(&[0, 0, 0, 0, 0, 0, 0, 9, 7]);
        assert_eq!(r.u64(), Ok(9));
        assert_eq!(r.finish(), Err(Error::Rejected));
        assert_eq!(r.rest(), &[7]);
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn flags_and_expected_bytes() {
        assert_eq!(Reader::new(&[0]).flag(), Ok(false));
        assert_eq!(Reader::new(&[1]).flag(), Ok(true));
        for b in [2_u8, 0x80, 0xff] {
            assert_eq!(Reader::new(&[b]).flag(), Err(Error::Rejected));
        }
        assert_eq!(Reader::new(&[1]).expect(1), Ok(()));
        assert_eq!(Reader::new(&[2]).expect(1), Err(Error::Rejected));
        assert_eq!(Reader::new(&[]).expect(1), Err(Error::Rejected));
    }

    #[test]
    fn length_prefixes() {
        let mut w = Writer::new();
        w.prefixed_u8(&[5; 255]).unwrap_or_default();
        assert!(w.prefixed_u8(&[5; 256]).is_err());
        w.prefixed_u16(&[6; 3]).unwrap_or_default();
        assert!(Writer::new().prefixed_u16(&vec![0; 65_536]).is_err());
        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.prefixed_u8().map(<[u8]>::len), Ok(255));
        assert_eq!(r.prefixed_u16(), Ok(&[6_u8, 6, 6][..]));
        assert_eq!(r.finish(), Ok(()));
        // a length beyond the input rejects
        assert_eq!(Reader::new(&[3, 1, 2]).prefixed_u8(), Err(Error::Rejected));
        assert_eq!(Reader::new(&[0, 3, 1]).prefixed_u16(), Err(Error::Rejected));
    }

    #[test]
    fn padding_round_trip_and_rejections() {
        let p = pad(&[1, 2, 3], 8).unwrap_or_default();
        assert_eq!(p, vec![1, 2, 3, 0x80, 0, 0, 0, 0]);
        assert_eq!(unpad(&p, 8), Ok(&[1_u8, 2, 3][..]));
        // fields ending in 0x80 0x00 stay unambiguous: the last non-zero byte is the marker
        let q = pad(&[0x80, 0], 4).unwrap_or_default();
        assert_eq!(unpad(&q, 4), Ok(&[0x80_u8, 0][..]));
        // the empty field list pads to a lone marker
        assert_eq!(unpad(&pad(&[], 2).unwrap_or_default(), 2), Ok(&[][..]));
        // no room for the marker
        assert_eq!(pad(&[1, 2, 3, 4], 4), Err(Error::Rejected));
        assert_eq!(pad(&[1, 2, 3], 3), Err(Error::Rejected));
        // wrong size, missing marker, wrong marker, non-zero byte after the marker, all zero
        assert_eq!(
            unpad(p.get(..7).unwrap_or_default(), 8),
            Err(Error::Rejected)
        );
        assert_eq!(unpad(&[1, 2, 3, 4], 4), Err(Error::Rejected));
        assert_eq!(unpad(&[1, 2, 0x81, 0], 4), Err(Error::Rejected));
        assert_eq!(unpad(&[1, 0x80, 0, 1], 4), Err(Error::Rejected));
        assert_eq!(unpad(&[0, 0, 0, 0], 4), Err(Error::Rejected));
        assert_eq!(unpad(&[], 0), Err(Error::Rejected));
    }

    #[test]
    fn boxed_arrays_need_the_exact_length() {
        assert!(boxed::<3>(&[1, 2, 3]).is_ok());
        assert!(boxed::<3>(&[1, 2]).is_err());
        assert!(boxed::<3>(&[1, 2, 3, 4]).is_err());
        assert!(Reader::new(&[1, 2]).boxed::<3>().is_err());
    }
}
