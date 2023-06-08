use crate::keys::{PKrss, SKrss};
use crate::{SignatureGroup, VerkeyGroup, GT};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RSignature {
    pub sigma_1: SignatureGroup,
    pub sigma_2: SignatureGroup,
    pub sigma_3: SignatureGroup,
    pub sigma_4: VerkeyGroup,
}

// type Message = [FieldElement];
type RedactedMessage = Vec<Option<FieldElement>>;

/// Impliment a getter method for Vec that indexes into the Vec assuing a 1-indexed vector
/// (matching the notation in the RSS Scheme defined in https://eprint.iacr.org/2020/856.pdf)
pub trait MathIndex<T> {
    fn at_math_idx(&self, idx: usize) -> &T;
}
impl<T> MathIndex<T> for &[T] {
    fn at_math_idx(&self, idx: usize) -> &T {
        if 0 < idx && idx <= self.len() {
            &self[idx - 1]
        } else if idx == 0 {
            panic!("index out of bounds: first element has math index 1");
        } else {
            panic!(
                "index out of bounds: the len is {} but the math index is {}",
                self.len(),
                idx
            );
        }
    }
}

impl<T> MathIndex<T> for Vec<T> {
    fn at_math_idx(&self, idx: usize) -> &T {
        if 0 < idx && idx <= self.len() {
            &self[idx - 1]
        } else if idx == 0 {
            panic!("index out of bounds: first element has math index 1");
        } else {
            panic!(
                "index out of bounds: the len is {} but the math index is {}",
                self.len(),
                idx
            );
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum RSVerifyResult {
    Valid,
    InvalidSignature(String),
    VerificationFailure1(String),
    VerificationFailure2(String),
}

// pub fn did_to_fieldelements(message:DiD) -> FieldElement{
//     let mut context_bytes = message.context.into_bytes();
//     FieldElement;
// }

impl RSignature {
    // Given a secret key, a message of length n, and the parameters, output a signature and a 
    // redacted message
    pub fn new(messages: &[FieldElement], sk: &SKrss) -> RSignature {
        let sigma_1 = SignatureGroup::random();

        let mut sum_y_m = FieldElement::new();
        for i in 1..=messages.len() {
            let y_i = FieldElement::pow(&sk.y, &FieldElement::from(i as u64));
            let y_i_m_i = messages.at_math_idx(i) * &y_i; 
            sum_y_m += y_i_m_i;
        }
        let exponent = &sk.x + &sum_y_m;
        let sigma_2 = sigma_1.scalar_mul_const_time(&exponent);
    
        RSignature {
            sigma_1,
            sigma_2,
            sigma_3: SignatureGroup::identity(),
            sigma_4: VerkeyGroup::identity(),
        }
    }

    // Given a public key, a signature, a message of length n, and an index of things we want to
    // keep, output a derived signature and redacted message
    pub fn derive_signature(
        &self,
        pk: &PKrss,
        messages: &[FieldElement],
        idxs: &[usize],
    ) -> (RSignature, RedactedMessage) {
        let r = FieldElement::random();
        let t = FieldElement::random();
        let sigma_1_prime = self.sigma_1.scalar_mul_const_time(&r);
        let sigma_2_r = self.sigma_2.scalar_mul_const_time(&r);
        let sigma_1_prime_t = sigma_1_prime.scalar_mul_const_time(&t);
        let sigma_2_prime = sigma_2_r + sigma_1_prime_t;

        // compliment of idxs
        let mut idxs_prime: Vec<usize> = Vec::new();
        for j in 1..=messages.len() {
            if !(idxs).contains(&j) {
                idxs_prime.push(j);
            }
        }

        // sigma_tilde_prime = g_tilde^t + Sum_over_j(  Y_tilde[j] * m[j]  )
        let mut sigma_tilde_prime = VerkeyGroup::new();
        sigma_tilde_prime += pk.g_tilde.scalar_mul_const_time(&t);
        for j in &idxs_prime {
            sigma_tilde_prime += &pk
                .Y_tilde_i
                .at_math_idx(*j)
                .scalar_mul_const_time(messages.at_math_idx(*j));
        }

        let c = RSignature::hashed_exponents(
            messages.len(),
            &sigma_1_prime,
            &sigma_2_prime,
            &sigma_tilde_prime,
            idxs,
        );

        let mut sigma_3_prime = SignatureGroup::new();

        // following notation in paper
        let n = messages.len();
        for i in idxs {
            let mut Y_mj = SignatureGroup::new();
            for j in &idxs_prime {
                Y_mj += pk
                    .Y_i
                    .at_math_idx(n + 1 - i + j)
                    .to_owned()
                    .expect("only the (n+1)th element in the Vec will be None")
                    .scalar_mul_const_time(messages.at_math_idx(*j));
            }

            sigma_3_prime += (pk
                .Y_i
                .at_math_idx(n + 1 - i)
                .to_owned()
                .expect("only the (n+1)th element in the Vec will be None")
                .scalar_mul_const_time(&t)
                + Y_mj)
                .scalar_mul_const_time(
                    &c.at_math_idx(*i)
                        .to_owned()
                        .expect("Elements will be Some() for all i in idxs"),
                );
        }
        let redacted_message = RSignature::redact_message(messages, idxs);
        (
            RSignature {
                sigma_1: (sigma_1_prime),
                sigma_2: (sigma_2_prime),
                sigma_3: (sigma_3_prime),
                sigma_4: (sigma_tilde_prime),
            },
            redacted_message,
        )
    }

    pub fn verifyrsignature(
        pk: &PKrss,
        rsig: &RSignature,
        messages: &[FieldElement],
        idxs: &[usize],
    ) -> RSVerifyResult {
        if rsig.sigma_1 == SignatureGroup::identity() {
            return RSVerifyResult::InvalidSignature(
                "sigma_1 component of signature must not be Identity".to_string(),
            );
        }

        // check equation 1:  e(rhs_1_a, sigma_1) == e(g_tilde, sigma_2)
        let mut rhs_1_a = &pk.X_tilde + &rsig.sigma_4;
        for i in idxs {
            rhs_1_a += pk
                .Y_tilde_i
                .at_math_idx(*i)
                .scalar_mul_const_time(messages.at_math_idx(*i))
        }

        if GT::ate_pairing(&rhs_1_a, &rsig.sigma_1) != GT::ate_pairing(&pk.g_tilde, &rsig.sigma_2) {
            return RSVerifyResult::VerificationFailure1(
                "equality 1 failed during verification".to_string(),
            );
        }

        // check equation 2: e(g_tilde, sigma_3) == e(sigma_4, lhs_2_b)
        // Given unredacted case, rhs and lhs of equation 2 are both zero
        let n = messages.len();
        let mut lhs_2_b = SignatureGroup::new();
        let c = RSignature::hashed_exponents(n, &rsig.sigma_1, &rsig.sigma_2, &rsig.sigma_4, &idxs);
        for i in idxs {
            lhs_2_b += pk
                .Y_i
                .at_math_idx(n + 1 - i)
                .to_owned()
                .expect("only the (n+1)th element in the Vec will be None")
                .scalar_mul_const_time(
                    &c.at_math_idx(*i)
                        .to_owned()
                        .expect("Elements will be Some() for all i in idxs"),
                )
        }

        if GT::ate_pairing(&pk.g_tilde, &rsig.sigma_3) != GT::ate_pairing(&rsig.sigma_4, &lhs_2_b) {
            return RSVerifyResult::VerificationFailure2(
                "equality 2 failed during verification".to_string(),
            );
        }

        RSVerifyResult::Valid
    }

    fn hashed_exponents(
        n: usize,
        sigma_1: &SignatureGroup,
        sigma_2: &SignatureGroup,
        sigma_tilde: &VerkeyGroup,
        idxs: &[usize],
    ) -> Vec<Option<FieldElement>> {
        let sigma_1_string = sigma_1.to_string();
        let sigma_2_string = sigma_2.to_string();
        let sigma_tilde_string = sigma_tilde.to_string();
        let index_string = (&idxs)
            .into_iter()
            .map(|i| i.to_string())
            .collect::<String>();

        let mut c: Vec<Option<FieldElement>> = Vec::new();
        for i in 1..=n {
            if (&idxs).contains(&i) {
                let concantenated = String::clone(&sigma_1_string)
                    + &sigma_2_string
                    + &sigma_tilde_string
                    + &index_string
                    + &i.to_string();
                let concantenated_bytes = concantenated.as_bytes();
                c.push(Some(FieldElement::from_msg_hash(&concantenated_bytes)));
            } else {
                c.push(None);
            }
        }
        c
    }

    pub fn redact_message(msg: &[FieldElement], index: &[usize]) -> RedactedMessage {
        let mut redacted_message: RedactedMessage = Vec::new();
        for i in 1..=msg.len() {
            if index.contains(&i) {
                redacted_message.push(Some(msg.to_vec().at_math_idx(i).clone()));
            } else {
                redacted_message.push(None);
            }
        }
        redacted_message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{rsskeygen, Params};

    #[test]
    fn math_indexing() {
        let vec = vec![11, 22, 33];
        assert_eq!(vec.at_math_idx(1), &11);
        assert_eq!(vec.at_math_idx(3), &33);
    }

    #[test]
    #[should_panic = "index out of bounds: the len is 3 but the math index is 4"]
    fn math_indexing_out_of_bounds() {
        let vec = vec![11, 22, 33];
        vec.at_math_idx(4);
    }

    #[test]
    #[should_panic = "index out of bounds: first element has math index 1"]
    fn math_indexing_zero_panic() {
        let vec = vec![11, 22, 33];
        vec.at_math_idx(0);
    }

    #[test]
    fn redact_message() {
        let count_msgs = 5;
        let msgs = (0..count_msgs)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let idxs = [2, 3];
        let rmsgs = RSignature::redact_message(&msgs, &idxs);
        assert_eq!(
            rmsgs,
            vec![
                None,
                Some(msgs.at_math_idx(2).clone()),
                Some(msgs.at_math_idx(3).clone()),
                None,
                None
            ]
        )
    }

    #[test]
    fn new_RSignature() {
        let count_msgs = 3; // n
        let params = Params::new("test".as_bytes());
        let (sk, _) = rsskeygen(count_msgs, &params);
        let msgs = (0..count_msgs)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let signature = RSignature::new(&msgs, &sk);

        //extract sigma_1 (randomly generated) from RSignature to do tests
        let sigma_1 = signature.sigma_1;
        let sigma_2_calc = sigma_1.scalar_mul_const_time(
            &(&sk.x
                + &sk.y.pow(&FieldElement::from(1)) * msgs.at_math_idx(1)
                + &sk.y.pow(&FieldElement::from(2)) * msgs.at_math_idx(2)
                + &sk.y.pow(&FieldElement::from(3)) * msgs.at_math_idx(3)),
        );
        assert_eq!(signature.sigma_2, sigma_2_calc);
    }

    #[test]
    fn hashed_exponents_vec() {
        let n = 3;
        let sigma_1 = &SignatureGroup::random();
        let sigma_2 = &SignatureGroup::random();
        let sigma_tilde = &VerkeyGroup::random();
        let idxs = [2, 3];

        let c = RSignature::hashed_exponents(n, sigma_1, sigma_2, sigma_tilde, &idxs);
        let c_calc = vec![
            None,
            Some(FieldElement::from_msg_hash(
                (sigma_1.to_string()
                    + &sigma_2.to_string()
                    + &sigma_tilde.to_string()
                    + "23"
                    + "2")
                    .as_bytes(),
            )),
            Some(FieldElement::from_msg_hash(
                (sigma_1.to_string()
                    + &sigma_2.to_string()
                    + &sigma_tilde.to_string()
                    + "23"
                    + "3")
                    .as_bytes(),
            )),
        ];
        assert_eq!(c, c_calc);
    }

    #[test]
    fn sign_and_verify_full_signature() {
        let n = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(n, &params);
        let msgs = (0..n)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let sig = RSignature::new(&msgs, &sk);
        let idxs = [1, 2, 3];
        assert_eq!(
            RSignature::verifyrsignature(&pk, &sig, &msgs, &idxs),
            RSVerifyResult::Valid
        );
    }

    #[test]
    fn derive_and_verify_full_signature() {
        let n = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(n, &params);
        let msgs = (0..n)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let sig = RSignature::new(&msgs, &sk);
        
        // all elements of message
        let idxs = [1, 2, 3];

        // derive a redacted sig without reacting any elemets
        let (rsig, _) = sig.derive_signature(&pk, &msgs, &idxs);

        // verify rsig
        assert_eq!(
            RSignature::verifyrsignature(&pk, &rsig, &msgs, &idxs),
            RSVerifyResult::Valid
        );
    }

    #[test]
    fn derive_and_verify_redacted_signature() {
        let n = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(n, &params);
        let msgs = (0..n)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let sig = RSignature::new(&msgs, &sk);

        // derive redacted sig (redacting first element)
        let idxs = [2, 3];
        let (rsig, _) = sig.derive_signature(&pk, &msgs, &idxs);

        // verify
        assert_eq!(
            RSignature::verifyrsignature(&pk, &rsig, &msgs, &idxs),
            RSVerifyResult::Valid
        );
    }

    #[test]
    fn verify_imposter_signature_wrong_idxs() {
        let n = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(n, &params);
        let msgs = (0..n)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let sig = RSignature::new(&msgs, &sk);

        // derive redacted sig (redacting first element)
        let idxs = [2, 3];
        let (rsig, _) = sig.derive_signature(&pk, &msgs, &idxs);

        // verify expecting [1,2]
        let idxs_prime = [1, 2];
        assert_eq!(
            RSignature::verifyrsignature(&pk, &rsig, &msgs, &idxs_prime),
            RSVerifyResult::VerificationFailure1(
                "equality 1 failed during verification".to_string()
            )
        );
    }

    #[test]
    fn verify_imposter_signature_expecting_full_sig() {
        let n = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(n, &params);
        let msgs = (0..n)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let sig = RSignature::new(&msgs, &sk);

        // derive redacted sig (redacting first element)
        let idxs = [2, 3];
        let (rsig, _) = sig.derive_signature(&pk, &msgs, &idxs);

        // verify expecting full signature [1,2,3]
        let I_full = [1, 2, 3];
        assert_eq!(
            RSignature::verifyrsignature(&pk, &rsig, &msgs, &I_full),
            RSVerifyResult::VerificationFailure1(
                "equality 1 failed during verification".to_string()
            )
        );
    }

    #[test]
    fn verify_imposter_signature_wrong_msgs() {
        let n = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(n, &params);
        let msgs = (0..n)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let sig = RSignature::new(&msgs, &sk);

        // derive redacted sig (redacting first element)
        let idxs = [2, 3];
        let (rsig, _) = sig.derive_signature(&pk, &msgs, &idxs);

        // verfiy against different msgs for correct indicies
        let msgs_prime = (0..n)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        assert_eq!(
            RSignature::verifyrsignature(&pk, &rsig, &msgs_prime, &idxs),
            RSVerifyResult::VerificationFailure1(
                "equality 1 failed during verification".to_string()
            )
        );
    }

    #[test]
    fn verify_on_subset_of_redacted() {
        let n = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(n, &params);
        let msgs = (0..n)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let sig = RSignature::new(&msgs, &sk);

        // derive redacted sig (redacting first element)
        let idxs = [2, 3];
        let (rsig, _) = sig.derive_signature(&pk, &msgs, &idxs);

        // verify a claim that all is readacted expect 2
        // using a signature derived on 2,3
        let idxs_prime_prime = [2];
        assert_eq!(
            RSignature::verifyrsignature(&pk, &rsig, &msgs, &idxs_prime_prime),
            RSVerifyResult::VerificationFailure1(
                "equality 1 failed during verification".to_string()
            )
        );
    }
}
