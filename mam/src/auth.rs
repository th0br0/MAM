use curl::*;
use alloc::*;
use sign::iss;
use merkle;
use pascal;
use trytes::*;
use errors::*;

pub fn sign<C, H>(
    message_in: &[Trit],
    next: &[Trit],
    key: &[Trit],
    hashes: &[Vec<Trit>],
    security: u8,
) -> Vec<Trit>
where
    C: Curl<Trit>,
    H: HammingNonce<Trit>,
{
    let message: Vec<Trit> = next.iter().chain(message_in.iter()).cloned().collect();
    let message_length = message.len() / TRITS_PER_TRYTE;
    let message_nonce: Vec<Trit> = H::search(&message, TRITS_PER_TRYTE as u8, security).unwrap();
    let signature = {
        let mut curl = C::default();
        let len_trits: Vec<Trit> = num::int2trits(
            message_length as isize,
            num::min_trits(message_length as isize),
        );
        curl.absorb(&len_trits);
        curl.absorb(&message);
        curl.absorb(&message_nonce);
        iss::signature::<C>(&curl.rate(), &key)
    };
    pascal::encode(message_length)
        .into_iter()
        .chain(message.into_iter())
        .chain(
            pascal::encode(message_nonce.len() / TRITS_PER_TRYTE).into_iter(),
        )
        .chain(message_nonce.into_iter())
        .chain(signature.into_iter())
        .chain(pascal::encode(hashes.len()).into_iter())
        .chain(
            hashes
                .into_iter()
                .fold(Vec::with_capacity(hashes.len() * HASH_LENGTH), |mut acc,
                 v| {
                    acc.extend(v);
                    acc
                })
                .into_iter(),
        )
        .collect()
}

pub fn authenticate<C>(
    payload: &[Trit],
    root: &[Trit],
    index: usize,
) -> Result<(Vec<Trit>, Vec<Trit>), MamError>
where
    C: Curl<Trit>,
{

    let length;
    let mut payload_iter = payload.iter();
    let (message_length, message_length_end) = pascal::decode(&payload);
    let message: Vec<Trit> = payload_iter
        .by_ref()
        .skip(message_length_end)
        .take(message_length * TRITS_PER_TRYTE)
        .cloned()
        .collect();
    let nonce: Vec<Trit> = payload_iter
        .by_ref()
        .skip({
            let t = &payload[(message_length_end + message.len())..];
            let (l, e) = pascal::decode(&t);
            length = l * TRITS_PER_TRYTE;
            e
        })
        .take(length)
        .cloned()
        .collect();
    let hash = {
        let mut curl = C::default();
        let len_trits: Vec<Trit> = num::int2trits(
            message_length as isize,
            num::min_trits(message_length as isize),
        );
        curl.absorb(&len_trits);
        curl.absorb(&message);
        curl.absorb(&nonce);
        curl.rate().to_vec()
    };
    let security = iss::checksum_security(&hash);
    if security != 0 {
        let calculated_root: Vec<Trit> = {
            let address: Vec<Trit> = {
                let signature: Vec<Trit> = payload_iter
                    .by_ref()
                    .take(security * iss::KEY_LENGTH)
                    .cloned()
                    .collect();
                iss::address::<Trit, C>(&iss::digest_bundle_signature::<C>(&hash, &signature))
            };
            let siblings: Vec<Vec<Trit>> = {
                let end_trits: Vec<Trit> = payload_iter.by_ref().cloned().collect();
                let l = pascal::decode(&end_trits);
                end_trits[l.1..]
                    .chunks(HASH_LENGTH)
                    .take(l.0)
                    .map(|c| c.to_vec())
                    .collect()
            };
            merkle::root(&address, &siblings, index)
        };
        if calculated_root == root {
            let next_root: Vec<Trit> = message[..HASH_LENGTH].to_vec();
            let message_out: Vec<Trit> = message[HASH_LENGTH..].to_vec();
            Ok((message_out, next_root))
        } else {
            Err(MamError::InvalidSignature)
        }
    } else {
        Err(MamError::InvalidHash)
    }
}
