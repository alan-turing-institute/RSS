// Scheme defined in 2016 paper, CT-RSA 2016 (eprint 2015/525), section 4.2.
// The idea for blind signatures can be taken from Coconut
use crate::errors::PSError;
use crate::keys::{rsskeygen, PKrss, Params, SKrss, Sigkey, Verkey};
use crate::{ate_2_pairing, SignatureGroup, SignatureGroupVec, VerkeyGroup, VerkeyGroupVec, GT};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use hex_literal::hex;
use sha2::{Digest, Sha256, Sha512};
use std::ops::Add;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RSVerifyResult {
    Valid,
    InvalidSignature(String),
    VerificationFailure(String)
}


// pub fn did_to_fieldelements(message:DiD) -> FieldElement{
//     let mut context_bytes = message.context.into_bytes();
//     FieldElement;
// }

//TODO: this is a free-body function for now, until it is clearer how it will be used
fn to_redacted_message(msg: &[FieldElement], index: &Vec<usize>) -> RedactedMessage {
    let mut redacted_message: RedactedMessage = Vec::new();
    for i in 1..=msg.len() {
        if index.contains(&i) {
            redacted_message.push(Some(msg.to_vec().at_math_idx(i).clone())); // copy unredacted parts of a message
        } else {
            redacted_message.push(None); // message is redacted
        }
    }
    redacted_message
}

impl RSignature {
    // Given a secret key, a message of length n, and the parameters, output a signature and a redacted message
    // Seems correct to me -> I've been printing each output but of course no way to hand-check...
    pub fn new(messages: &Vec<FieldElement>, sk: &SKrss) -> RSignature {
        let sigma_1 = SignatureGroup::random(); // Generate sigma1, ok

        let mut sum_y_m = FieldElement::new(); // set sum of y^i mul mi at 0
        for i in 1..=messages.len() {
            let y_i = FieldElement::pow(&sk.y, &FieldElement::from(i as u64));
            let y_i_m_i = messages.at_math_idx(i) * &y_i; // Calculate y^i * m_i, ok
            sum_y_m += y_i_m_i; // accumulate y^i * m_i for different i values, ok
        }
        let exponent = &sk.x + &sum_y_m; // x + sum of y^i * m_i, ok
        let sigma_2 = sigma_1.scalar_mul_const_time(&exponent); // Calculate sigma_2 mul (x+sum of (y^i mul m_i))
                                                                // RSS Signature is a bit different than the paper - we need the identity in sigma3 and sigma4 as part of verify for
                                                                // unmodified signature
                                                                // signature seems okay, like key generation its a simple case of addition and multiplication with the indexes checking out...
        RSignature {
            sigma_1,
            sigma_2,
            sigma_3: SignatureGroup::identity(),
            sigma_4: VerkeyGroup::identity(),
        }
    } // sigma 3 and sigma 4 are correct -> lines up with identity element as needed

    // Given a public key, a signature, a message of length n, and an index of things we want to keep,
    // output a derived signature and redacted message
    pub fn derive_signature(
        &self,
        pk: PKrss,
        messages: &Vec<FieldElement>,
        I: Vec<usize>,
    ) -> (RSignature, RedactedMessage) {
        let r = FieldElement::random(); // Generate r
        let t = FieldElement::random(); // Generate t
        let sigma_1_prime = self.sigma_1.scalar_mul_const_time(&r); // sigma'1 = sigma1 * r
        let sigma_2_r = self.sigma_2.scalar_mul_const_time(&r); // sigma2 mul r
        let sigma_1_prime_t = sigma_1_prime.scalar_mul_const_time(&t); // sigma'1 mul t
        let sigma_2_prime = sigma_2_r + sigma_1_prime_t; // sigma'2 = (sigma2 mul r) + (sigma'1 mul t)

        let mut I_prime: Vec<usize> = Vec::new();   // compliment of I
        for j in 1..=messages.len() {
            if !(&I).contains(&j) {
                I_prime.push(j);
            }
        }

        // sigma_tilde_prime = g_tilde^t + Sum_over_j(  Y_tilde[j] * m[j]  )
        let mut sigma_tilde_prime = VerkeyGroup::new(); // set accumulator to zero
        sigma_tilde_prime += pk.g_tilde.scalar_mul_const_time(&t);
        for j in &I_prime {
            sigma_tilde_prime += &pk.Y_tilde_i.at_math_idx(*j).scalar_mul_const_time(messages.at_math_idx(*j));
        }

        let c = RSignature::_hashed_exponents(messages.len(), &sigma_1_prime, &sigma_2_prime, &sigma_tilde_prime, &I);

        let mut sigma_3_prime = SignatureGroup::new(); // create an empty element for sigma_3
                                                       //println!("{:?}", c);
                                                       // NOTE: i is only for 1 to n, but we've been working with 0<=i<n. I changed Y^t_n+1-i to Y^t_n-i to account for this.
        let n = messages.len(); // following notation in paper
        for i in &I {
            let mut Y_mj = SignatureGroup::new(); // create blank to store Y^mj
            for j in &I_prime {
                Y_mj += pk.Y_i
                    .at_math_idx(n+1-i+j)
                    .to_owned()
                    .expect("only the (n+1)th element in the Vec will be None")
                    .scalar_mul_const_time(messages.at_math_idx(*j));
            }

            sigma_3_prime += (pk.Y_i
                                .at_math_idx(n+1-i)
                                .to_owned()
                                .expect("only the (n+1)th element in the Vec will be None")
                                .scalar_mul_const_time(&t)
                                + Y_mj)
                                .scalar_mul_const_time(&c
                                                        .at_math_idx(*i)
                                                        .to_owned()
                                                        .expect("Elements will be Some() for all i in I"));
        }
        let redacted_message = to_redacted_message(messages, &I);
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

    fn _hashed_exponents(
        n: usize,
        sigma_1: &SignatureGroup,
        sigma_2: &SignatureGroup,
        sigma_tilde: &VerkeyGroup,
        I: &Vec<usize>
    ) -> Vec<Option<FieldElement>> {
        let sigma_1_string = sigma_1.to_string(); // convert sigma1' to string
        let sigma_2_string = sigma_2.to_string(); // convert sigma2' to string
        let sigma_tilde_string = sigma_tilde.to_string(); // convert sigma~' to string
        let index_string = (&I).into_iter().map(|i| i.to_string()).collect::<String>(); // convert each element of index to string

        let mut c:Vec<Option<FieldElement>> = Vec::new(); // create a vector to store c_i
        for i in 1..=n {
            if (&I).contains(&i) {
                let concantenated = String::clone(&sigma_1_string)
                    + &sigma_2_string
                    + &sigma_tilde_string
                    + &index_string
                    + &i.to_string(); // create concantenation for hash input
                let concantenated_bytes = concantenated.as_bytes(); // convert hash input to bytes
                c.push(Some(FieldElement::from_msg_hash(&concantenated_bytes))) // add c_i to a vector
            } else {
                c.push(None);
            }
        }
        c
    }

    pub fn verifyrsignature(
        pk: PKrss,
        rsig: RSignature,
        messages: &Vec<FieldElement>,
        I: Vec<usize>,
    ) -> RSVerifyResult {
        if rsig.sigma_1 == SignatureGroup::identity() {
            // check if sigma3 = identity
            return RSVerifyResult::InvalidSignature("sigma_1 component of signature must not be Identity".to_string())
        }

        // check equation 1:  e(rhs_1_a, sigma_1) == e(g_tilde, sigma_2)
        let mut rhs_1_a = pk.X_tilde + &rsig.sigma_4;
        for i in &I {
            rhs_1_a += pk.Y_tilde_i
                        .at_math_idx(*i)
                        .scalar_mul_const_time(messages.at_math_idx(*i))
        }

        if GT::ate_pairing(&rhs_1_a, &rsig.sigma_1) != GT::ate_pairing(&pk.g_tilde, &rsig.sigma_2) {
            return RSVerifyResult::VerificationFailure("equality 1 failed during verification".to_string())
        }

        // check equation 2: e(g_tilde, sigma_3) == e(sigma_4, lhs_2_b)
        // Given unredacted case, rhs and lhs of equation 2 are both zero
        let n = messages.len();
        let mut lhs_2_b = SignatureGroup::new();
        let c = RSignature::_hashed_exponents(n, &rsig.sigma_1, &rsig.sigma_2, &rsig.sigma_4, &I);
        for i in &I {
            lhs_2_b += pk.Y_i
                        .at_math_idx(n+1-i)
                        .to_owned()
                        .expect("only the (n+1)th element in the Vec will be None")
                        .scalar_mul_const_time(&c
                                                .at_math_idx(*i)
                                                .to_owned()
                                                .expect("Elements will be Some() for all i in I"))
        }

        if GT::ate_pairing(&pk.g_tilde, &rsig.sigma_3) != GT::ate_pairing(&rsig.sigma_4, &lhs_2_b) {
            return RSVerifyResult::VerificationFailure("equality 1 failed during verification".to_string())
        }

        RSVerifyResult::Valid
    }

    // pub fn verifyredactedsignature(
    //     pk: PKrss,
    //     rsig: RSignature,
    //     messages: RedactedMessage,
    //     index: Vec<usize>,
    // ) -> bool {
    //     let mut new_message: Vec<FieldElement> = vec![FieldElement::new(); messages.len()];
    //     for i in 0..new_message.len() {
    //         if messages[i] == None {
    //             new_message[i] = FieldElement::new();
    //         } else {
    //             let clone_message = messages[i].clone();
    //             new_message[i] = clone_message.unwrap();
    //         }
    //     }
    //     let mut test_check: bool = false;
    //     let index_clone = index.clone();
    //     if rsig.sigma_1 == SignatureGroup::identity() {
    //         // check if sigma3 = identity
    //         println!("incorrect sigma_1"); // if yes, it's an invalid signature
    //     } else {
    //         let mut accumulator = pk.X_tilde + &rsig.sigma_4; // X~ + sigma~ correct
    //         for i in index_clone {
    //             accumulator += pk.Y_tilde_i[i].scalar_mul_const_time(&new_message[i]);
    //         }
    //         let first_equation = GT::ate_pairing(&accumulator, &rsig.sigma_1);
    //         let second_equation = GT::ate_pairing(&pk.g_tilde, &rsig.sigma_2);
    //         if first_equation == second_equation {
    //             println!("Passed first test");
    //         } else {
    //             println!("Failed first test");
    //         }

    //         let third_equation = GT::ate_pairing(&pk.g_tilde, &rsig.sigma_3); // correct
    //         let clone_index = index.clone();
    //         let mut c = FieldElementVector::new(new_message.len()); // create a vector to store c_i
    //         let sigma_1_string = rsig.sigma_1.to_string();
    //         let sigma_2_string = rsig.sigma_2.to_string();
    //         let sigma_tilde_string = rsig.sigma_4.to_string();
    //         let index_string = index.into_iter().map(|i| i.to_string()).collect::<String>(); // convert each element of index to string

    //         for i in &clone_index {
    //             let concatenated = String::clone(&sigma_1_string)
    //                 + &sigma_2_string
    //                 + &sigma_tilde_string
    //                 + &index_string
    //                 + &i.to_string();
    //             let concantenated_bytes = concatenated.as_bytes();
    //             let c_i: FieldElement = FieldElement::from_msg_hash(&concantenated_bytes); // generate c_i
    //             c[*i] = c_i;
    //         }
    //         // c vector is correct, equivalent to c for redacted signature.
    //         // println!("{:?}",c.len());
    //         let mut accumulator_2 = SignatureGroup::new(); // start from 0
    //         let index_clone = clone_index.clone();
    //         //println!("{:?}",index_clone);
    //         for i in 0..messages.len() {
    //             // go through everything in index
    //             if index_clone.contains(&i) {
    //                 let index_value = messages.len() - i - 1;
    //                 //println!("{:?}",index_value);
    //                 accumulator_2 += pk.Y_j_1_to_n[index_value].scalar_mul_const_time(&c[i]);
    //                 // n + 1 - i as original index, modified to suit value of i
    //             }
    //         }
    //         let fourth_equation = GT::ate_pairing(&rsig.sigma_4, &accumulator_2);
    //         //println!("{:?}",third_equation);
    //         println!("{:?}", fourth_equation);
    //         if third_equation == fourth_equation {
    //             test_check = true;
    //             println!("Passed second test");
    //         } else {
    //             test_check = false;
    //             println!("Failed second test");
    //         }
    //     }
    //     return test_check;
    // }
    // First verification checks out. At least we know for a redacted signature the problem isn't sigma 1 and sigma 2
    // Given how sigma4 is constructed, unlikely to be source of error.
    // So issue is in sigma3 generation or sigma 3 pairing...
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keys::keygen, rsssig};
    // For benchmarking
    use std::time::{Duration, Instant};

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
        let I = vec![2, 3];
        let rmsgs = to_redacted_message(&msgs, &I);
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
        let I = &vec![2,3];

        let c = RSignature::_hashed_exponents(n, sigma_1, sigma_2, sigma_tilde, I);
        let c_calc = vec![
            None,
            Some(FieldElement::from_msg_hash(
                (
                    sigma_1.to_string()
                    + &sigma_2.to_string()
                    + &sigma_tilde.to_string()
                    + "23"
                    + "2"
                ).as_bytes()
                
            )),
            Some(FieldElement::from_msg_hash(
                (
                    sigma_1.to_string()
                    + &sigma_2.to_string()
                    + &sigma_tilde.to_string()
                    + "23"
                    + "3"
                ).as_bytes()
                
            ))
        ];
        assert_eq!(c,c_calc);
    }

    #[test]
    fn check_exponent() {
        let count_msgs = 1;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(count_msgs, &params);
        let msgs = (0..count_msgs)
            .map(|_| FieldElement::random())
            .collect::<Vec<FieldElement>>();
        let signature = RSignature::new(&msgs, &sk);
        let index = vec![];
        let verify = RSignature::verifyrsignature(pk, signature, &msgs, index);
        //assert_eq!(SignatureGroup::identity(),signature.sigma_3);
    }

    // #[test]
    // fn generate_normal_rsig() {
    //     let count_msgs = 3; // n
    //     let params = Params::new("test".as_bytes());
    //     let (sk, pk) = rsskeygen(count_msgs, &params);
    //     let msgs = (0..count_msgs)
    //         .map(|_| FieldElement::random())
    //         .collect::<Vec<FieldElement>>();
    //     let signature = RSignature::new(&msgs, &sk);
    //     let index_kept = vec![0, 1, 2];
    //     let verify = RSignature::verifyrsignature(pk, signature, &msgs, index_kept);
    //     println!("{:?}", verify);
    // }
    // test passes! when trying it out just remember to make sure the index is right
    // this test is for unredacted message, so index is every element
    // Recall index is the stuff we want to keep
    // #[test]
    // fn test_rss_sig() {
    //     let count_msgs = 3;
    //     let params = Params::new("test".as_bytes());
    //     let (sk, pk) = rsskeygen(count_msgs, &params);
    //     let msgs = (0..count_msgs)
    //         .map(|_| FieldElement::random())
    //         .collect::<Vec<FieldElement>>();
    //     let signature = RSignature::new(&msgs, &sk);
    //     let index = vec![0];
    //     let index_clone = index.clone();
    //     let pk_new = pk.clone();
    //     let (redacted_signature, redacted_message) =
    //         RSignature::rss_derive_signature(pk, signature, &msgs, index);
    //     let verification = RSignature::verifyredactedsignature(
    //         pk_new,
    //         redacted_signature,
    //         redacted_message,
    //         index_clone,
    //     );
    //     //println!("{:?}", redacted_message);
    // }

    // #[test]
    // fn test_generatedid(){
    //     let example_id  = DiD{
    //         context: vec![String::from("https://www.w3.org/2018/credentials/v1"), String::from("https://schema.org/")],
    //         id: String::from("http://example.edu/credentials/332"),
    //         type_field: vec![String::from("VerifiableCredential"), String::from("IdentityCredential")],
    //         issuer: String::from("did:example:123456789abcdefghi"),
    //         issuance_date: String::from("2017-02-24T19:73:24Z"),
    //         credential_subject: [String::from("J. Doe");{String::from("10 Rue de Chose"); String::from("98052"); String::from("Paris");
    //         String::from("FR")},String::from("1989-03-15"),]
    //     };
    //     println!("{:?}",example_id);
    // }
    // https://hackmd.io/UJFBOl2DToSbFjFoEoMbOA?view
}
