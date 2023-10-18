use crate::{SignatureGroup, VerkeyGroup};
use amcl_wrapper::constants::FieldElement_SIZE;
use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use itertools::Itertools;
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sigkey {
    pub x: FieldElement,
    pub y: Vec<FieldElement>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verkey {
    pub X_tilde: VerkeyGroup,
    pub Y_tilde: Vec<VerkeyGroup>,
}

/// Secret key consists of two random scalars x and y
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SKrss {
    pub x: FieldElement,
    pub y: FieldElement,
}

#[derive(Clone, Debug, Error)]
pub enum SKrssError {
    #[error("Wrapped SerzDeserzError: {0}")]
    WrappedSerzDeserzError(SerzDeserzError),
}

impl From<SerzDeserzError> for SKrssError {
    fn from(value: SerzDeserzError) -> Self {
        SKrssError::WrappedSerzDeserzError(value)
    }
}

impl SKrss {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.x.to_bytes();
        b.extend(self.y.to_bytes());
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SKrss, SKrssError> {
        Ok(SKrss {
            x: FieldElement::from_bytes(&bytes[0..FieldElement_SIZE])?,
            y: FieldElement::from_bytes(&bytes[FieldElement_SIZE..bytes.len()])?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PKrss {
    pub g: SignatureGroup,
    pub g_tilde: VerkeyGroup,
    pub Y_i: Vec<Option<SignatureGroup>>,
    pub X_tilde: VerkeyGroup,
    pub Y_tilde_i: Vec<VerkeyGroup>,
}

#[derive(Clone, Debug, Error)]
pub enum PKrssError {
    #[error("Failed to parse signature parts.")]
    FailedParsingSignatureParts,
    #[error("Failed parsing Signature Group: {0}")]
    FailedParsingSignatureGroup(SerzDeserzError),
    #[error("Failed parsing Verkey Group: {0}")]
    FailedParsingVerkeyGroup(SerzDeserzError),
    #[error("Unknown SerzDeserzError: {0}")]
    UnknownSerzDeserzError(SerzDeserzError),
    #[error("Invalid length for byte encoded key, unable to seperate key components.")]
    KeyByteEncodingInvalidLength,
}

impl From<SerzDeserzError> for PKrssError {
    fn from(value: SerzDeserzError) -> Self {
        match value {
            err @ SerzDeserzError::G1BytesIncorrectSize(_, _) => {
                PKrssError::FailedParsingVerkeyGroup(err)
            }
            err @ SerzDeserzError::G2BytesIncorrectSize(_, _) => {
                PKrssError::FailedParsingSignatureGroup(err)
            }
            err @ _ => PKrssError::UnknownSerzDeserzError(err),
        }
    }
}

fn key_length_to_count_messages(key_len: usize) -> Result<usize, PKrssError> {
    if (key_len - 192 - 97 - 97 + 192) % (97 + 2 * 192) == 0 {
        Ok((key_len - 192 - 97 - 97 + 192) / (97 + 2 * 192))
    } else {
        Err(PKrssError::KeyByteEncodingInvalidLength)
    }
}

fn count_messages_to_key_lengths(count_msgs: usize) -> [usize; 5] {
    [192, 97, 192 * (count_msgs * 2 - 1), 97, 97 * count_msgs]
}

impl PKrss {
    pub fn to_bytes(&self) -> Vec<u8> {
        let PKrss {
            g,
            g_tilde,
            Y_i,
            X_tilde,
            Y_tilde_i,
        } = self;
        let mut b = g.to_bytes();
        b.extend(g_tilde.to_bytes());
        b.extend(
            Y_i.iter()
                .filter_map(|opt| {
                    if let Some(g2) = opt {
                        Some(g2.to_bytes())
                    } else {
                        None
                    }
                })
                .flatten(),
        );
        b.extend(X_tilde.to_bytes());
        b.extend(Y_tilde_i.iter().map(|g1| g1.to_bytes()).flatten());
        b
    }

    pub fn from_bytes(pk: &[u8]) -> Result<PKrss, PKrssError> {
        let infered_count_msgs = key_length_to_count_messages(pk.len())?;
        let mut pk_vec = pk.to_vec();
        pk_vec.reverse();
        let mut split_points = count_messages_to_key_lengths(infered_count_msgs).to_vec();
        split_points.reverse();

        fn splitter(pk_vec: &mut Vec<u8>, split_points: &mut Vec<usize>) -> Vec<u8> {
            let idx = split_points.pop().unwrap();
            let mut split = pk_vec.split_off(pk_vec.len() - idx);
            split.reverse();
            split
        }

        let g = SignatureGroup::from_bytes(&splitter(&mut pk_vec, &mut split_points))?;
        let g_tilde = VerkeyGroup::from_bytes(&splitter(&mut pk_vec, &mut split_points))?;
        let Y_i_flat = splitter(&mut pk_vec, &mut split_points);
        let X_tilde = VerkeyGroup::from_bytes(&splitter(&mut pk_vec, &mut split_points))?;
        let Y_tilde_i_flat = splitter(&mut pk_vec, &mut split_points);

        // unflatten Y_i and Y_tilde_i

        let Y_tilde_i = Y_tilde_i_flat
            .iter()
            .chunks(97)
            .into_iter()
            .map(|chunk| VerkeyGroup::from_bytes(&chunk.cloned().collect_vec()))
            .collect::<Result<Vec<VerkeyGroup>, SerzDeserzError>>()?;

        let mut Y_i = Y_i_flat
            .iter()
            .chunks(2 * 97 - 2)
            .into_iter()
            .map::<Result<Option<SignatureGroup>, SerzDeserzError>, _>(|chunk| {
                Some(SignatureGroup::from_bytes(&chunk.cloned().collect_vec())).transpose()
            })
            .collect::<Result<Vec<Option<SignatureGroup>>, SerzDeserzError>>()?;
        Y_i.insert(infered_count_msgs, None);

        Ok(PKrss {
            g,
            g_tilde,
            Y_i,
            X_tilde,
            Y_tilde_i,
        })
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::new();
        s += &(self.g.to_hex() + ":");
        s += &(self.g_tilde.to_hex() + ":");
        for (i, el) in self.Y_i.iter().enumerate() {
            if i != 0 {
                s += "%";
            }
            if let Some(sig_group) = el {
                s += &sig_group.to_hex();
            }
        }
        s += ":";
        s += &(self.X_tilde.to_hex() + ":");
        for (i, el) in self.Y_tilde_i.iter().enumerate() {
            if i != 0 {
                s += "%";
            }
            s += &el.to_hex();
        }
        s
    }

    pub fn from_hex(pk: &str) -> Result<PKrss, PKrssError> {
        let mut parts = pk.split(":").into_iter();
        let g = SignatureGroup::from_hex(
            parts
                .next()
                .ok_or(PKrssError::FailedParsingSignatureParts)?
                .to_string(),
        )?;
        let g_tilde = VerkeyGroup::from_hex(
            parts
                .next()
                .ok_or(PKrssError::FailedParsingSignatureParts)?
                .to_string(),
        )?;
        let Y_i = parts
            .next()
            .ok_or(PKrssError::FailedParsingSignatureParts)?
            .split("%")
            .map(|s| {
                if let "" = s {
                    Ok(None)
                } else {
                    match SignatureGroup::from_hex(s.to_string()) {
                        Ok(sig_group) => Ok(Some(sig_group)),
                        Err(err) => return Err(err),
                    }
                }
            })
            .collect::<Result<Vec<_>, SerzDeserzError>>()?;
        let X_tilde = VerkeyGroup::from_hex(
            parts
                .next()
                .ok_or(PKrssError::FailedParsingSignatureParts)?
                .to_string(),
        )?;
        let Y_tilde_i = parts
            .next()
            .ok_or(PKrssError::FailedParsingSignatureParts)?
            .split("%")
            .map(|s| VerkeyGroup::from_hex(s.to_string()))
            .collect::<Result<Vec<_>, SerzDeserzError>>()?;

        Ok(PKrss {
            g,
            g_tilde,
            Y_i,
            X_tilde,
            Y_tilde_i,
        })
    }
}
/// Parameters generated by random oracle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub g: SignatureGroup,
    pub g_tilde: VerkeyGroup,
}

impl Params {
    /// Generate g1, g2. These are shared by signer and all users. Picks a point from G1 and G2
    pub fn new(label: &[u8]) -> Self {
        let g = SignatureGroup::from_msg_hash(&[label, " : g".as_bytes()].concat());
        let g_tilde = VerkeyGroup::from_msg_hash(&[label, " : g_tilde".as_bytes()].concat());
        Self { g, g_tilde }
    }
}

/// Generate signing and verification keys for scheme from 2016 paper
pub fn keygen(count_messages: usize, params: &Params) -> (Sigkey, Verkey) {
    // TODO: Take PRNG as argument
    let x = FieldElement::random();
    let X_tilde = &params.g_tilde * &x;
    let mut y = vec![];
    let mut Y_tilde = vec![];
    for _ in 0..count_messages {
        let y_i = FieldElement::random();
        Y_tilde.push(&params.g_tilde * &y_i);
        y.push(y_i);
    }
    (Sigkey { x, y }, Verkey { X_tilde, Y_tilde })
}

/// Generate RSS public key and private key from parameters. The length of the key depends on the
/// number of elements in the longest message that is signable by the key: count_messages.
pub fn rsskeygen(count_messages: usize, params: &Params) -> (SKrss, PKrss) {
    let g = params.g.clone();
    let g_tilde = params.g_tilde.clone();

    let x = FieldElement::random();
    let y = FieldElement::random();
    let X_tilde = &g_tilde * &x;

    let mut Y_tilde_i = Vec::new();
    for i in 1..=count_messages {
        // Calculate y^i (mod arithmetic because y in Z2p)
        let y_i = FieldElement::pow(&y, &FieldElement::from(i as u64));

        // add g~ mul y^i to Y~i
        Y_tilde_i.push((&g_tilde).scalar_mul_variable_time(&y_i));
    }

    // Given that the index of redacted and unredacted messages do not intersect,
    // the pairing can be computed without knowledge of a specific element g^y^(n+1).
    // So instead of considering 2n elements, we consider 2n-1. Hence, for the public
    // key we compute only [1,n] and [n+2,2n], leaving the n+1 value.
    let mut Y_i = Vec::new();
    for i in 1..=(2 * count_messages) {
        if i == count_messages + 1 {
            Y_i.push(None);
        } else {
            let y_i = FieldElement::pow(&y, &FieldElement::from(i as u64));
            Y_i.push(Some((&g).scalar_mul_const_time(&y_i)))
        }
    }

    (
        SKrss { x, y },
        PKrss {
            g,
            g_tilde,
            Y_i,
            X_tilde,
            Y_tilde_i,
        },
    )
}

/// Generate signing and verification keys for scheme from 2018 paper. The signing and
/// verification keys will have 1 extra element for m'
pub fn keygen_2018(count_messages: usize, params: &Params) -> (Sigkey, Verkey) {
    keygen(count_messages + 1, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsssig::MathIndex;

    #[test]
    fn test_keygen() {
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen(count_msgs, &params);
        assert_eq!(sk.y.len(), count_msgs);
        assert_eq!(vk.Y_tilde.len(), count_msgs);
    }

    #[test]
    fn test_keygen_2018() {
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen_2018(count_msgs, &params);
        assert_eq!(sk.y.len(), count_msgs + 1);
        assert_eq!(vk.Y_tilde.len(), count_msgs + 1);
    }
    #[test]
    fn test_rsskeygen() {
        let count_msgs = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(count_msgs, &params);

        // test Y_i
        assert_eq!(pk.Y_i.len(), 2 * count_msgs);
        assert_eq!(pk.Y_i.at_math_idx(count_msgs + 1), &None);
        let Y_i_calc = vec![
            Some(
                params
                    .g
                    .scalar_mul_const_time(&sk.y.pow(&FieldElement::from(1))),
            ),
            Some(
                params
                    .g
                    .scalar_mul_const_time(&sk.y.pow(&FieldElement::from(2))),
            ),
            Some(
                params
                    .g
                    .scalar_mul_const_time(&sk.y.pow(&FieldElement::from(3))),
            ),
            None,
            Some(
                params
                    .g
                    .scalar_mul_const_time(&sk.y.pow(&FieldElement::from(5))),
            ),
            Some(
                params
                    .g
                    .scalar_mul_const_time(&sk.y.pow(&FieldElement::from(6))),
            ),
        ];
        assert_eq!(pk.Y_i, Y_i_calc);

        // test Y_tilde_i
        let Y_tilde_i_calc = vec![
            params
                .g_tilde
                .scalar_mul_const_time(&sk.y.pow(&FieldElement::from(1))),
            params
                .g_tilde
                .scalar_mul_const_time(&sk.y.pow(&FieldElement::from(2))),
            params
                .g_tilde
                .scalar_mul_const_time(&sk.y.pow(&FieldElement::from(3))),
        ];
        assert_eq!(pk.Y_tilde_i, Y_tilde_i_calc);
    }

    #[test]
    fn test_rsskey_ser_de() {
        let (_, pk) = rsskeygen(3, &Params::new("test".as_bytes()));
        println!("{}", serde_json::to_string_pretty(&pk).unwrap());
        let se_pk = pk.to_hex();
        println!("{}", se_pk);
        let de_pk = PKrss::from_hex(&se_pk).unwrap();
    }

    #[test]
    fn test_rsskey_sk_byte_conversion() {
        // test a range of max idxs signable (count_msgs) with a different set of params each time
        let count_msgs = [1_usize, 4, 5, 7, 8, 13, 17, 20];
        for test in count_msgs {
            let mut params = "test".as_bytes().to_vec();
            params.push(test as u8);
            let (sk, _) = rsskeygen(test, &Params::new(&params));
            let bytes = sk.to_bytes();
            assert_eq!(SKrss::from_bytes(&bytes).unwrap(), sk);
        }
    }

    #[test]
    fn test_rsskey_pk_byte_conversion() {
        // test a range of max idxs signable (count_msgs) with a different set of params each time
        let count_msgs = [1_usize, 4, 5, 7, 8, 13, 17, 20];
        for test in count_msgs {
            let mut params = "test".as_bytes().to_vec();
            params.push(test as u8);
            let (_, pk) = rsskeygen(test, &Params::new(&params));
            let bytes = pk.to_bytes();
            assert_eq!(PKrss::from_bytes(&bytes).unwrap(), pk);
        }
    }

    #[test]
    fn test_rsskey_pk_bytes() {
        let count_msgs = 8;
        let (_, pk) = rsskeygen(count_msgs, &Params::new("test".as_bytes()));
        let PKrss {
            g,
            g_tilde,
            Y_i,
            X_tilde,
            Y_tilde_i,
        } = pk;

        let mut b = g.to_bytes();
        let len_g = b.len();
        b.extend(g_tilde.to_bytes());
        let len_g_tilde = b.len() - len_g;

        b.extend(
            Y_i.iter()
                .filter_map(|opt| {
                    if let Some(g2) = opt {
                        Some(g2.to_bytes())
                    } else {
                        None
                    }
                })
                .flatten(),
        );
        let len_y_i = b.len() - len_g - len_g_tilde;
        b.extend(X_tilde.to_bytes());
        let len_x_tilde = b.len() - len_g - len_g_tilde - len_y_i;
        b.extend(Y_tilde_i.iter().map(|g1| g1.to_bytes()).flatten());
        let len_y_tilde_i = b.len() - len_g - len_g_tilde - len_y_i - len_x_tilde;

        let lengths = [len_g, len_g_tilde, len_y_i, len_x_tilde, len_y_tilde_i];
        println!("{:?}", lengths);
        // count_msgs: [g_len, g_tilde_len, Y_i_len, X_tilde_len, Y_tilde_i_len]
        // 1: [192, 97, 192, 97, 97]
        // 2: [192, 97, 576, 97, 194]
        // 3: [192, 97, 960, 97, 291]
        // 4: [192, 97, 1344, 97, 388]
        // 5: [192, 97, 1728, 97, 485]
        // 6: [192, 97, 2112, 97, 582]
        // 15: [192, 97, 5568, 97, 1455]
        // 20: [192, 97, 7488, 97, 1940]

        // test helper functions which evaluate key component split points in the byte array
        let infered_count_msgs = key_length_to_count_messages(b.len()).unwrap();
        assert_eq!(infered_count_msgs, count_msgs);
        assert_eq!(count_messages_to_key_lengths(infered_count_msgs), lengths);
    }

    #[test]
    fn test_rsskey_sk_bytes() {
        let (sk, _) = rsskeygen(3, &Params::new("test".as_bytes()));
    }
}
