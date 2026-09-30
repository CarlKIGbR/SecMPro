// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed-layout big-endian encoding (spec §4.1): a bounded [`Reader`], a [`Writer`], the [`Encode`]/[`Decode`]
//! traits and ISO/IEC 7816-4 padding.
//!
//! Decoding is total: every read either yields exactly the requested bytes or [`Error::Rejected`]; offsets and
//! lengths are only ever split off the remaining input (`split_at_checked`) or converted with `try_from`, never
//! computed with unchecked arithmetic. [`Decode::decode`] requires the input to be consumed exactly (spec §4.1
//! consistency rule), so a structure has exactly one encoding.
//!
//! Encoding buffers are zeroized (M2 review C1, CLAUDE.md §1.6): an encoding may carry `send_seed`, `link_key` or
//! `inv_send_seed` (`RelayQueue`, `InvitationV1` and everything that embeds them), so the [`Writer`], every
//! [`Encode::encode`] result, [`pad`] and `encode_padded` hold their bytes in `Zeroizing<Vec<u8>>`, and the
//! [`Writer`] grows by copying into a new zeroizing buffer — a `Vec` reallocation would free the old block without
//! wiping it. One rule for every structure, secret-bearing or not.

use crate::error::{Error, Result};

/// The zeroizing buffer of the encodings: `secmp_crypto::Zeroizing` (review C1). Under Kani only, a transparent
/// stand-in with the same interface (`kani_stubs::Zeroizing`): Kani cannot execute `zeroize`, whose optimisation
/// barrier is inline assembly ("`TerminatorKind::InlineAsm` is not currently supported"), and wiping on drop is not
/// among the properties the harnesses prove (no panic, exact fit, re-encoding).
#[cfg(kani)]
pub(crate) use kani_stubs::Zeroizing;
#[cfg(not(kani))]
pub(crate) use secmp_crypto::Zeroizing;

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

/// The first allocation of a [`Writer`] that grows (it doubles from here).
const WRITER_INITIAL_CAPACITY: usize = 256;

/// An encoding being built, in a zeroizing buffer that never reallocates in place (module docs).
#[derive(Default)]
pub struct Writer {
    buf: Zeroizing<Vec<u8>>,
}

impl Writer {
    /// An empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make room for `additional` more bytes: if the buffer is too small, its bytes move into a new zeroizing
    /// buffer of at least twice their length (the length of a full buffer is its capacity; sizing from the length
    /// keeps a wrongly repeated growth linear, M2 mutation gate) and the old one is wiped as it drops.
    /// `extend_from_slice` within the capacity then never reallocates.
    ///
    /// Not under Kani: CBMC does not finish on a buffer allocated ahead of its writes (measured 2026-09-30: the `cell`
    /// harness verifies in 9 s when `extend_from_slice` grows the `Vec`, and times out after 4 min with
    /// `Vec::with_capacity` or `reserve_exact`), so the Kani builds grow as a plain `Vec` does. What the harnesses
    /// prove does not depend on the allocation; the zeroizing growth is unit-tested (`writer_grows_without_losing_bytes`).
    fn reserve(&mut self, additional: usize) {
        if cfg!(kani) {
            return;
        }
        let needed = self.buf.len().saturating_add(additional);
        if needed <= self.buf.capacity() {
            return;
        }
        let capacity = needed
            .max(self.buf.len().saturating_mul(2))
            .max(WRITER_INITIAL_CAPACITY);
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(&self.buf);
        self.buf = grown;
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
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

    /// The bytes written so far (zeroized on drop).
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
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

    /// The encoding, zeroized on drop (review C1: it may carry a `send_seed`, `link_key` or `inv_send_seed`).
    ///
    /// # Errors
    /// As [`Encode::encode_to`].
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut w = Writer::new();
        self.encode_to(&mut w)?;
        Ok(w.into_bytes())
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

/// ISO/IEC 7816-4 padding (spec §4.1): `fields ‖ 0x80 ‖ 0x00…` to exactly `size` bytes, in one zeroizing
/// allocation of exactly `size` bytes (review C1).
///
/// # Errors
/// [`Error::Rejected`] if the fields leave no room for the marker.
pub fn pad(fields: &[u8], size: usize) -> Result<Zeroizing<Vec<u8>>> {
    // zeros of the full size, then the fields and the marker over their front (no fill loop: the Kani harnesses
    // re-encode 4336-byte frames)
    let mut out = Zeroizing::new(vec![0; size]);
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

    /// `Zeroizing` without the wipe on drop, for the Kani builds only (see `codec::Zeroizing`).
    #[derive(Default, Clone, PartialEq, Eq)]
    pub struct Zeroizing<Z>(Z);

    impl<Z> Zeroizing<Z> {
        pub fn new(value: Z) -> Self {
            Self(value)
        }
    }

    impl<Z> core::ops::Deref for Zeroizing<Z> {
        type Target = Z;
        fn deref(&self) -> &Z {
            &self.0
        }
    }

    impl<Z> core::ops::DerefMut for Zeroizing<Z> {
        fn deref_mut(&mut self) -> &mut Z {
            &mut self.0
        }
    }
}

/// `value` encoded and padded to `size`; the unpadded encoding is wiped when it drops here (review C1).
pub(crate) fn encode_padded(value: &impl Encode, size: usize) -> Result<Zeroizing<Vec<u8>>> {
    pad(&value.encode()?, size)
}

/// Decode a padded structure of `size` bytes whose fields are `T`.
pub(crate) fn decode_padded<T: Decode>(bytes: &[u8], size: usize) -> Result<T> {
    T::decode(unpad(bytes, size)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    // the real type, not the crate's alias (which is a stand-in under Kani)
    use secmp_crypto::Zeroizing;

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
        let bytes = w.into_bytes();
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
        assert_eq!(*p, vec![1, 2, 3, 0x80, 0, 0, 0, 0]);
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

    /// Review C1: the writer's buffer, every encoding, `pad` and `encode_padded` are `Zeroizing<Vec<u8>>` (a
    /// change of any of these types fails to compile here).
    #[test]
    fn encoding_buffers_are_zeroizing() -> Result<()> {
        struct Bytes(Vec<u8>);
        impl Encode for Bytes {
            fn encode_to(&self, w: &mut Writer) -> Result<()> {
                w.bytes(&self.0);
                Ok(())
            }
        }
        let writer: Zeroizing<Vec<u8>> = Writer::new().into_bytes();
        let encoded: Zeroizing<Vec<u8>> = Bytes(vec![1, 2]).encode()?;
        let padded: Zeroizing<Vec<u8>> = pad(&[1, 2], 4)?;
        let encoded_padded: Zeroizing<Vec<u8>> = encode_padded(&Bytes(vec![1, 2]), 4)?;
        assert!(writer.is_empty());
        assert_eq!(*encoded, [1, 2]);
        assert_eq!(*padded, [1, 2, 0x80, 0]);
        assert_eq!(padded, encoded_padded);
        // `pad` allocates exactly the padded size (no spare capacity to hold stale bytes)
        assert_eq!(padded.capacity(), 4);
        Ok(())
    }

    /// Review C1: the growth policy of `reserve` — the first write allocates at least the initial capacity (or
    /// exactly its size, if larger), a write that fits never moves the buffer, a write that does not moves it to
    /// twice the capacity (a plain `Vec` would start at 8 bytes and reallocate in place).
    #[test]
    fn writer_growth_policy() {
        let mut w = Writer::new();
        assert_eq!(w.buf.capacity(), 0);
        w.bytes(&[1]);
        assert_eq!(w.buf.capacity(), WRITER_INITIAL_CAPACITY);
        // a write that fits leaves the buffer where it is
        let before = w.buf.as_ptr();
        w.bytes(&[2]);
        assert_eq!(w.buf.as_ptr(), before);
        assert_eq!(w.buf.capacity(), WRITER_INITIAL_CAPACITY);
        w.bytes(&vec![3; WRITER_INITIAL_CAPACITY.saturating_sub(2)]);
        assert_eq!(w.buf.len(), WRITER_INITIAL_CAPACITY);
        assert_eq!(w.buf.capacity(), WRITER_INITIAL_CAPACITY);
        w.bytes(&[4]);
        assert_eq!(w.buf.capacity(), WRITER_INITIAL_CAPACITY.saturating_mul(2));
        let mut big = Writer::new();
        big.bytes(&[5; 1000]);
        assert_eq!(big.buf.capacity(), 1000);
        big.bytes(&[]);
        assert_eq!(big.buf.capacity(), 1000);
    }

    /// Review C1: the writer grows by moving into a new, larger zeroizing buffer; the bytes stay exact across every
    /// growth step (1 … 3 × the initial capacity, in pieces of every size up to 300 bytes).
    #[test]
    fn writer_grows_without_losing_bytes() {
        for piece in [1_usize, 7, 255, 256, 257, 300] {
            let mut w = Writer::new();
            let mut expected = Vec::new();
            let mut i = 0_u8;
            while expected.len() < WRITER_INITIAL_CAPACITY.saturating_mul(3) {
                let chunk: Vec<u8> = (0..piece)
                    .map(|_| {
                        i = i.wrapping_add(1);
                        i
                    })
                    .collect();
                w.bytes(&chunk);
                expected.extend_from_slice(&chunk);
                assert!(w.buf.capacity() >= w.buf.len());
            }
            assert_eq!(*w.into_bytes(), expected, "piece {piece}");
        }
    }

    #[test]
    fn boxed_arrays_need_the_exact_length() {
        assert!(boxed::<3>(&[1, 2, 3]).is_ok());
        assert!(boxed::<3>(&[1, 2]).is_err());
        assert!(boxed::<3>(&[1, 2, 3, 4]).is_err());
        assert!(Reader::new(&[1, 2]).boxed::<3>().is_err());
    }
}
