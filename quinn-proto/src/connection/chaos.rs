//! Chromium's chaos protection of a client's Initial packets (`QuicChaosProtector`): a ClientHello
//! that can't be read off one contiguous CRYPTO frame at a predictable place.

use std::collections::VecDeque;

use bytes::{BufMut, Bytes};
use rand::{Rng, RngExt, seq::SliceRandom};

use crate::{VarInt, coding::BufMutExt, frame};

/// How many times a CRYPTO frame is cut at random, and how many PING frames are mixed in
const CUTS: std::ops::RangeInclusive<usize> = 2..=10;
const PINGS: std::ops::RangeInclusive<usize> = 2..=10;

/// Length of the leading CRYPTO frame of a ClientHello spread over several packets: the fixed
/// part of the hello and the length of its first extension, give or take.
const HEAD: std::ops::Range<usize> = 55..87;

/// How a ClientHello of `pending` bytes that does not fit in one packet of `available` bytes of
/// frames is laid out: the lengths of its head and of its tail, which the first packet carries,
/// the middle following in the next ones as evenly as they take it
pub(super) fn split_client_hello(
    pending: usize,
    available: usize,
    rng: &mut impl Rng,
) -> Option<(usize, usize)> {
    if pending == 0 {
        return None;
    }
    let header = header_len(pending as u64 - 1, pending);
    // The first packet holds two frames, the next ones one each.
    let first = available.checked_sub(2 * header)?;
    let other = available - header;
    if pending <= first {
        return None;
    }
    let occupied = other - first;
    let packets = (pending + occupied).div_ceil(other);
    let first = ((pending + occupied).div_ceil(packets)).checked_sub(occupied)?;
    let head = rng.random_range(HEAD);
    if pending <= head || first <= head {
        return None;
    }
    Some((head, first - head))
}

/// Rewrites the packet's `crypto` frames, the last frames in `buffer`, together with the padding
/// that takes the packet to `end`: the frames cut further, PING frames added, the padding in runs,
/// all shuffled into the same number of bytes
pub(super) fn scramble(
    buffer: &mut Vec<u8>,
    crypto: &VecDeque<frame::Crypto>,
    end: usize,
    rng: &mut impl Rng,
) {
    let encoded: usize = crypto
        .iter()
        .map(|frame| header_len(frame.offset, frame.data.len()) + frame.data.len())
        .sum();
    let Some(start) = buffer.len().checked_sub(encoded) else {
        return;
    };
    debug_assert!(crypto.iter().all(|frame| {
        let mut out = Vec::new();
        frame.encode(&mut out);
        buffer[start..]
            .windows(out.len())
            .any(|window| window == out)
    }));
    let mut budget = end.saturating_sub(buffer.len());
    buffer.truncate(start);

    let mut frames: Vec<(u64, Bytes)> = crypto
        .iter()
        .map(|frame| (frame.offset, frame.data.clone()))
        .collect();
    let low = frames.iter().map(|(offset, _)| *offset).min().unwrap_or(0);
    let high = frames
        .iter()
        .map(|(offset, data)| offset + data.len() as u64)
        .max()
        .unwrap_or(0);
    // A cut adds at most this much: the header of the second part
    let overhead = header_len(high, (high - low) as usize);
    for _ in 0..rng.random_range(CUTS) {
        if budget < overhead {
            break;
        }
        let index = rng.random_range(0..frames.len());
        let (offset, data) = frames[index].clone();
        if data.len() <= 1 {
            continue;
        }
        let cut = rng.random_range(1..data.len());
        let second = (offset + cut as u64, data.slice(cut..));
        let first = (offset, data.slice(..cut));
        budget = budget + header_len(offset, data.len())
            - header_len(first.0, first.1.len())
            - header_len(second.0, second.1.len());
        frames[index] = first;
        frames.push(second);
    }

    enum Item {
        Crypto(u64, Bytes),
        Ping,
        Padding(usize),
    }
    let pings = rng.random_range(PINGS).min(budget);
    budget -= pings;
    let mut items: Vec<Item> = frames
        .into_iter()
        .map(|(offset, data)| Item::Crypto(offset, data))
        .chain((0..pings).map(|_| Item::Ping))
        .collect();
    // Each place takes a random share of what is left, so runs come in a mix of lengths.
    for _ in 0..items.len() {
        if budget == 0 {
            break;
        }
        let run = rng.random_range(0..=budget);
        if run > 0 {
            items.push(Item::Padding(run));
            budget -= run;
        }
    }
    if budget > 0 {
        items.push(Item::Padding(budget));
    }
    items.shuffle(rng);

    for item in items {
        match item {
            Item::Crypto(offset, data) => frame::Crypto { offset, data }.encode(buffer),
            Item::Ping => buffer.write(frame::FrameType::PING),
            Item::Padding(run) => buffer.put_bytes(0, run),
        }
    }
    debug_assert_eq!(buffer.len(), end);
}

fn header_len(offset: u64, len: usize) -> usize {
    let size = |value: u64| VarInt::from_u64(value).map_or(8, |value| value.size());
    1 + size(offset) + size(len as u64)
}
