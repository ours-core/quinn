//! How a client lays out its first flight: packet numbers, packets per datagram, CRYPTO data.

use super::*;
use crate::{
    FixedLengthConnectionIdParser,
    crypto::ServerConfig as _,
    frame::{self, Frame},
    packet::{Header, PartialDecode, SpaceId},
};

/// A packet a client sent; the frames of Initial packets, which anyone can decrypt.
#[derive(Debug)]
struct Sent {
    space: SpaceId,
    number: Option<u64>,
    frames: Vec<Frame>,
}

/// Connects with `transport` on the client and returns the client's datagrams up to the end of
/// the handshake, each as its packets.
fn handshake(transport: TransportConfig) -> Vec<Vec<Sent>> {
    handshake_offering(transport, vec![b"h3".to_vec()])
}

/// [`handshake`], the client offering `alpn`, which the server takes.
fn handshake_offering(transport: TransportConfig, alpn: Vec<Vec<u8>>) -> Vec<Vec<Sent>> {
    let _guard = subscribe();
    let server = ServerConfig::with_crypto(Arc::new(server_crypto_with_alpn(alpn.clone())));
    let mut pair = Pair::new(Default::default(), server);
    let mut config = ClientConfig::new(Arc::new(client_crypto_with_alpn(alpn)));
    config.transport_config(Arc::new(transport));
    let client_ch = pair.begin_connect(config);
    let mut datagrams = Vec::new();
    for _ in 0..100 {
        pair.client.drive(pair.time, pair.server.addr);
        datagrams.extend(
            pair.client
                .outbound
                .iter()
                .map(|(_, contents)| contents.clone()),
        );
        if !pair.step() {
            break;
        }
    }
    assert!(
        !pair.client_conn_mut(client_ch).is_handshaking(),
        "handshake did not complete"
    );
    let original_dst_cid = *PartialDecode::new(
        BytesMut::from(&datagrams[0][..]),
        &FixedLengthConnectionIdParser::new(0),
        &[1],
        false,
    )
    .unwrap()
    .0
    .dst_cid();
    let keys = server_crypto().initial_keys(1, &original_dst_cid).unwrap();
    datagrams
        .into_iter()
        .map(|datagram| {
            let mut packets = Vec::new();
            let mut rest = Some(BytesMut::from(&datagram[..]));
            while let Some(bytes) = rest.take() {
                let (partial, next) =
                    PartialDecode::new(bytes, &FixedLengthConnectionIdParser::new(8), &[1], true)
                        .unwrap();
                rest = next;
                let Some(space) = partial.space() else {
                    continue;
                };
                if space != SpaceId::Initial {
                    packets.push(Sent {
                        space,
                        number: None,
                        frames: Vec::new(),
                    });
                    continue;
                }
                let mut packet = partial.finish(Some(&*keys.header.remote)).unwrap();
                let Header::Initial(header) = &packet.header else {
                    unreachable!()
                };
                let number = header.number.expand(0);
                keys.packet
                    .remote
                    .decrypt(number, &packet.header_data, &mut packet.payload)
                    .unwrap();
                let frames = frame::Iter::new(packet.payload.freeze())
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                packets.push(Sent {
                    space,
                    number: Some(number),
                    frames,
                });
            }
            packets
        })
        .collect()
}

#[test]
fn initial_packet_number_is_configurable() {
    let mut transport = TransportConfig::default();
    transport.initial_packet_number(1);
    let datagrams = handshake(transport);
    let numbers: Vec<u64> = datagrams
        .iter()
        .flatten()
        .filter(|sent| sent.space == SpaceId::Initial)
        .filter_map(|sent| sent.number)
        .collect();
    assert_eq!(numbers[0], 1);
    assert!(
        numbers.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "{numbers:?}"
    );

    let datagrams = handshake(TransportConfig::default());
    assert_eq!(datagrams[0][0].number, Some(0));
}

#[test]
fn packets_can_keep_a_datagram_each() {
    let datagrams = handshake(TransportConfig::default());
    assert!(
        datagrams.iter().any(|packets| packets.len() > 1),
        "quinn coalesces by default"
    );

    let mut transport = TransportConfig::default();
    transport.coalesce_packets(false);
    let datagrams = handshake(transport);
    for packets in &datagrams {
        assert_eq!(packets.len(), 1, "{datagrams:?}");
    }
    assert!(
        datagrams
            .iter()
            .any(|packets| packets[0].space == SpaceId::Handshake)
    );
}

#[test]
fn handshake_acks_can_go_alone() {
    let mut transport = TransportConfig::default();
    transport.coalesce_packets(false);
    let together = handshake(transport)
        .iter()
        .filter(|packets| packets[0].space == SpaceId::Handshake)
        .count();

    let mut transport = TransportConfig::default();
    transport.coalesce_packets(false);
    transport.handshake_acks_alone(true);
    let alone = handshake(transport)
        .iter()
        .filter(|packets| packets[0].space == SpaceId::Handshake)
        .count();
    assert_eq!(alone, together + 1);
}

/// The CRYPTO frames of a client's Initial packet, the PING frames and the runs of PADDING.
fn layout(sent: &Sent) -> (Vec<(u64, usize)>, usize, usize) {
    let mut crypto = Vec::new();
    let (mut pings, mut runs, mut padding) = (0, 0, false);
    for frame in &sent.frames {
        match frame {
            Frame::Crypto(frame) => crypto.push((frame.offset, frame.data.len())),
            Frame::Ping => pings += 1,
            Frame::Padding if !padding => runs += 1,
            _ => {}
        }
        padding = matches!(frame, Frame::Padding);
    }
    (crypto, pings, runs)
}

/// The CRYPTO data of the client's first Initial packets, as ranges sorted by offset, which must
/// leave no gap.
fn covered(datagrams: &[Vec<Sent>]) -> u64 {
    let mut ranges: Vec<(u64, usize)> = datagrams
        .iter()
        .flatten()
        .filter(|sent| sent.space == SpaceId::Initial)
        .take(2)
        .flat_map(|sent| layout(sent).0)
        .collect();
    ranges.sort();
    ranges.iter().fold(0, |end, &(offset, len)| {
        assert!(offset <= end, "gap before {offset}: {ranges:?}");
        end.max(offset + len as u64)
    })
}

#[test]
fn chaos_protection_scrambles_the_client_hello() {
    let plain = handshake(TransportConfig::default());
    let (crypto, pings, runs) = layout(&plain[0][0]);
    assert_eq!((crypto.len(), pings, runs), (1, 0, 1));

    let mut transport = TransportConfig::default();
    transport.chaos_protection(true);
    let scrambled = handshake(transport);
    let (crypto, pings, runs) = layout(&scrambled[0][0]);
    assert!(crypto.len() >= 3, "{crypto:?}");
    assert!(pings >= 2);
    assert!(runs >= 2);
    assert!(covered(&scrambled) > 200);
}

#[test]
fn chaos_protection_sends_the_ends_of_a_long_client_hello_first() {
    // Protocols enough to take the hello over one packet.
    let alpn: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'a' + i; 200]).collect();
    let mut transport = TransportConfig::default();
    transport.chaos_protection(true);
    transport.coalesce_packets(false);
    let datagrams = handshake_offering(transport, alpn);
    let total = covered(&datagrams);
    assert!(total > 1500, "{total}");
    let (first, ..) = layout(&datagrams[0][0]);
    assert!(first.iter().any(|&(offset, _)| offset == 0));
    assert!(
        first
            .iter()
            .any(|&(offset, len)| offset + len as u64 == total),
        "the tail first: {first:?}"
    );
    let head = first
        .iter()
        .filter(|&&(offset, _)| offset < 100)
        .map(|&(offset, len)| offset + len as u64)
        .max()
        .unwrap();
    assert!((55..87).contains(&head), "{first:?}");
    let (second, ..) = layout(&datagrams[1][0]);
    assert!(
        second.iter().any(|&(offset, _)| offset == head),
        "the middle next: {second:?}"
    );
}
