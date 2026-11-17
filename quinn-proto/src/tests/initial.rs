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
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut config = client_config();
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
