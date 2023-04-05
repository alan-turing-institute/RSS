// Scheme defined in 2016 paper, CT-RSA 2016 (eprint 2015/525), section 4.2.
// The idea for blind signatures can be taken from Coconut

use std::clone;
use std::ops::Add;
use hex_literal::hex;
use sha2::{Sha256, Sha512, Digest};
use crate::errors::PSError;
use crate::{GT, ate_2_pairing, VerkeyGroup, VerkeyGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use crate::keys::{PKrss, SKrss, Params,Sigkey,Verkey,rsskeygen};


/// Created by the signer when no blinded messages. Also the receiver of a blind signature can get
/// this by unblinding the blind signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub sigma_1: SignatureGroup,
    pub sigma_2: SignatureGroup,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RSignature {
    pub sigma_1: SignatureGroup,
    pub sigma_2: SignatureGroup,
    pub sigma_3: SignatureGroup,
    pub sigma_4: VerkeyGroup,
}

type Message = [FieldElement];
type RedactedMessage = Vec<Option<FieldElement>>;

// Methods associated with redaction
trait Redact{
    fn to_redacted_message(&self, index: Vec<usize>) -> RedactedMessage;
}

impl Redact for Message {
    // Index I is the set of stuff we want to redact, the message should be m_i for i not in I
    fn to_redacted_message(&self, index: Vec<usize>) -> RedactedMessage{
        let mut i = 0; // loop over index i for unredacted parts
        let mut j: usize = 0; // use it to reference parts of a message 
        let mut redacted_message :RedactedMessage = vec![None; self.len()]; // create empty vector for message 
        for _ in 0..self.len(){
            if index.contains(&i){
                redacted_message[j] = None; // message is redacted
                i+=1; // increment
                j += 1; // increment
            } else {
                redacted_message[j] = Some(self[j].clone()); // copy unredacted parts of a message
                i += 1; // increment
                j += 1; // increment
                
            }
        }
        redacted_message
    } // This works as intended :) 
}

impl RSignature{
    // Given a secret key, a message of length n, and the parameters, output a signature and a redacted message
    // Seems correct to me -> I've been printing each output but of course no way to hand-check...
    pub fn rss_generate_signature(messages: &[FieldElement], sk: &SKrss, params: &Params) -> RSignature{
        let rss_sigma_1 = SignatureGroup::random(); // Generate sigma1 -> correct
        let mut x = sk.x.clone(); // x
        let mut i_exponent = FieldElement::new(); // use as index for y^i
        let mut sum_y_m = FieldElement::new(); // set sum of y^i mul mi at 0
   
        for i in 0.. messages.len(){
            let y_i = FieldElement::pow(&sk.y, &i_exponent); // calculate y^i
            let y_i_m_i = FieldElement::multiply(&messages[i], &y_i); // Calculate y^i * m_i
            sum_y_m += y_i_m_i; // accumulate y^i * m_i for different i values
            println!("{:?}",sum_y_m);
            i_exponent += &FieldElement::one(); // increment i -> usable for 1 to n
        }
        //println!("{:?}",sum_y_m);
        x += &sum_y_m; // x + sum of y^i * m_i
        println!("{:?}",x);
        let rss_sigma_2 =rss_sigma_1.scalar_mul_variable_time(&x); // Calculate sigma_2 mul (x+sum of (y^i mul m_i)) 
        //println!("{:?}",rss_sigma_2);
        // RSS Signature is a bit different than the paper - we need the identity in sigma3 and sigma4 as part of verify for
        // unmodified signatures
        RSignature { sigma_1: (rss_sigma_1), sigma_2: (rss_sigma_2), sigma_3:(SignatureGroup::identity()), sigma_4: (VerkeyGroup::identity())}
    }

    // Given a public key, a signature, a message of length n, and an index of parts of redact, 
    // output a derived signature and redacted message 
    pub fn rss_derive_signature(pk:PKrss, rsig: RSignature,messages: &[FieldElement],index: Vec<usize>) -> (RSignature, RedactedMessage){
        let r = FieldElement::random(); // Generate r
        let t = FieldElement::random(); // Generate t
        let r_clone = FieldElement::clone(&r); // Clone it for repeated uses
        let t_clone = FieldElement::clone(&t); // Clone it for repeated uses 
        let sigma_1_prime = rsig.sigma_1 * r; // sigma'1 = sigma1 * r 
        let sigma_2_r = rsig.sigma_2.scalar_mul_const_time(&r_clone); // sigma2 mul r 
        let sigma_1_prime_t = sigma_1_prime.scalar_mul_const_time(&t_clone); // sigma'1 mul t
        let sigma_2_prime = sigma_1_prime_t+ sigma_2_r; // sigma'2 = (sigma2 mul r) + (sigma'1 mul t)
        let index_clone = index.clone();
        
        let mut j= 0; // Need another counter of usize type 
        let mut accumulator = pk.X_tilde.scalar_mul_const_time(&FieldElement::new()); // set to 0 for sum of Y~j mul mj
        for j in 0..messages.len(){
            if !index.contains(&j){
                //i += 1; // we only want element not in Index
                //j += 1; // increment by 1
    
                let Y_tilde_i = &pk.Y_tilde_i[j]; // select Y~[j]
                let Y_tilde_i_mj = Y_tilde_i.scalar_mul_const_time(&messages[j]); // Y~[j] mul m[j]
                accumulator += Y_tilde_i_mj; // Sum Y~[i] mul m[j]
                
                // i+=1; // increment by 1
            }
        };
        let g_tilde_t = pk.g_tilde * t_clone; // g~ mul t
        let sigma_prime_tilde = g_tilde_t + accumulator; // sigma~' = g~ mul t + sum of (Y~[j] mul m[j])

        let sigma_1_prime_string = sigma_1_prime.to_string(); // convert sigma1' to string
        let sigma_2_prime_string = sigma_2_prime.to_string(); // convert sigma2' to string
        let sigma_prime_tilde_string = sigma_prime_tilde.to_string(); // convert sigma~' to string
        let clone_index = index.clone(); // clone index
        let index_string = index.into_iter().map(|i| i.to_string()).collect::<String>(); // convert each element of index to string
        
        let mut c = FieldElementVector::new(index_clone.len()); // create a vector to store c_i

        let mut k = 0; // create index to find i in Index
        for _ in 0..messages.len(){
            if clone_index.contains(&k){
                let k_index: String = k.to_string(); // convert k to string
                let concantenated= String::clone(&sigma_1_prime_string) + &sigma_2_prime_string + &sigma_prime_tilde_string
                + &index_string+ &k_index; // create concantenation for hash input
                let concantenated_bytes = concantenated.as_bytes(); // convert hash input to bytes
                let c_i : FieldElement= FieldElement::from_msg_hash(&concantenated_bytes); // generate c_i          
                c.push(c_i); // add c_i to a vector
                k += 1; // increment k
            } else{
                k+=1; // increment k
            }
        }
        
        let mut p= 0; // counter to go through all of index I
        let mut jj=0; // counter to go through all of j not in I
        let mut z= FieldElement::new(); // counter to refer parts of a message m_j
        let mut sigma_3_prime = SignatureGroup::new(); // create an empty element for sigma_3

        let mut i: i32= 0; // create a counter to traverse message length
        // NOTE: i is only for 1 to n, but we've been working with 0<=i<n. I changed Y^t_n+1-i to Y^t_n-i to account for this.
        for _ in 0..messages.len(){
            if clone_index.contains(&p){ // Checks if p is in index
                let mut Y_mj = SignatureGroup::new(); // create blank to store Y^mj
                if clone_index.contains(&jj){
                    jj += 1;
                } else { // identify jj not in index
                    let mut Y_mj_index = messages.len() - p as usize + jj as usize; // define index for Y^mj
                    let mut Y_mji = pk.Y_k_nplus2_to_2n[Y_mj_index].clone(); // create blank to find each constituent of Y^mj
                    Y_mj += Y_mji; // acumulate for Y_mj
                    jj += 1; // increment index
                }
                let mut Y_t = SignatureGroup::new(); // create an empty group element to store Y^t
                let mut Y_t_i = SignatureGroup::new(); // create blank to find each constituent of Y^t
                Y_t_i = pk.Y_j_1_to_n[messages.len()-p-1].clone().scalar_mul_const_time(&t) + Y_mj;
                Y_t += Y_t_i.scalar_mul_const_time(&c[p]);
                p += 1;
            } else {
                p +=1;

            }
        }
        let redacted_message = messages.to_redacted_message(clone_index);
        (RSignature{sigma_1: (sigma_1_prime), sigma_2: (sigma_2_prime), sigma_3: (sigma_3_prime), sigma_4:(sigma_prime_tilde)},  redacted_message)
    }

    pub fn verifyrsignature(pk:PKrss, rsig:RSignature, messages: &[FieldElement], index: Vec<usize>)->bool{
        let mut test_check: bool = false;
        let index_clone = index.clone();
        if rsig.sigma_1 == SignatureGroup::identity(){ // check if sigma3 = identity
            test_check = false;
            println!("incorrect sigma_1"); // if yes, it's an invalid signature
        } else {
            let mut accumulator = pk.X_tilde + rsig.sigma_4.clone(); // X~ + sigma~
            //println!("{:?}",accumulator);
            for i in index_clone{
                accumulator += pk.Y_tilde_i[i].scalar_mul_const_time(&messages[i]); 
            }
            let first_equation = GT::ate_pairing(&accumulator,&rsig.sigma_1); // seems right
            let second_equation = GT::ate_pairing(&pk.g_tilde, &rsig.sigma_2); // seems right
            if first_equation == second_equation{
            } else { // Test case of no accumulator -> not working...
                println!("{:?}", first_equation);
                println!("{:?}", second_equation);
                println!("incorrect 1st eq and 2nd eq");
            }
            let third_equation = GT::ate_pairing(&pk.g_tilde, &rsig.sigma_3);
            let mut accumulator_2 = SignatureGroup::identity().scalar_mul_const_time(&FieldElement::new());
            let clone_index = index.clone();
            let mut c = FieldElementVector::new(clone_index.len()); // create a vector to store c_i
            let sigma_1_string = rsig.sigma_1.to_string();
            let sigma_2_string = rsig.sigma_2.to_string();
            let sigma_tilde_string = rsig.sigma_4.to_string();
            let index_string = clone_index.into_iter().map(|i| i.to_string()).collect::<String>(); // convert each element of index to string
            let mut k = 0;
            for _ in 0..messages.len(){
                if index.contains(&k){
                    let concatenated = String::clone(&sigma_1_string) + &sigma_2_string + &sigma_tilde_string
                    + &index_string + &k.to_string();
                    let concantenated_bytes = concatenated.as_bytes();
                    let c_i : FieldElement= FieldElement::from_msg_hash(&concantenated_bytes); // generate c_i
                    c.push(c_i); // add c_i to a vector
                    println!("{:?}",k);
                    k += 1; // increment k
                } else{
                    k+=1; // increment k
                }
            }

            for i in index{
                let index_value = messages.len() + 1 -i;
                if index_value < messages.len(){
                    accumulator_2 += pk.Y_j_1_to_n[index_value].scalar_mul_const_time(&c[i]); // find c_i somehow...
                } //else {
                //     accumulator_2 += pk.Y_k_nplus2_to_2n[index_value].scalar_mul_const_time(&c[i]);;
                // }
            }
            let fourth_equation = GT::ate_pairing(&rsig.sigma_4, &accumulator_2);
            // I think this is wrong, pairing gives 0?
            if third_equation == fourth_equation{
                test_check = true;
                //println!("correct 3rd eq and 4th eq");
            } else {
                test_check = false;
               // println!("incorrect 3rd eq and 4th eq");
            }
        }
        return test_check;
    }
}

impl Signature {
    /// Create a new signature. The signature generation involves generating a random value for `sigma_1` so different
    /// calls to this method with same messages, signing key and params will give different value
    pub fn new(messages: &[FieldElement], sigkey: &Sigkey, params: &Params) -> Result<Self, PSError> {
        Self::check_sigkey_and_messages_compat(messages, sigkey)?;
        // A random h should be generated which is same as generating a random u and then computing h = g^u
        let u = FieldElement::random();
        let (sigma_1, sigma_2) = Self::sign_with_sigma_1_generated_from_given_exp(
            messages,
            sigkey,
            &u,
            0,
            &params.g,
        )?;
        Ok(Self { sigma_1, sigma_2 })
    }

    /// Create a new signature. The signature generation doesn't involve generating a random value but
    /// the messages are hashed to get a pseudorandom value for `sigma_1`. Hence different calls to this method
    /// with same messages and signing key will give same value
    pub fn new_deterministic(messages: &[FieldElement], sigkey: &Sigkey) -> Result<Self, PSError> {
        Self::check_sigkey_and_messages_compat(messages, sigkey)?;
        let sigma_1 = Self::generate_sigma_1_from_messages(messages);
        let sigma_2 = Self::sign_with_given_sigma_1(messages, sigkey, 0, &sigma_1)?;
        Ok(Self {sigma_1, sigma_2})
    }

    /// Generate signature when first element of signature tuple is generated using given exponent
    /// Does only 1 scalar multiplication
    pub fn sign_with_sigma_1_generated_from_given_exp(
        messages: &[FieldElement],
        sigkey: &Sigkey,
        u: &FieldElement,
        offset: usize,
        g: &SignatureGroup,
    ) -> Result<(SignatureGroup, SignatureGroup), PSError> {
        // h = g^u
        let h = g * u;
        let h_exp = Self::sign_with_given_sigma_1(messages, sigkey, offset, &h)?;
        Ok((h, h_exp))
    }

    /// Generate signature when first element of signature tuple is given
    pub fn sign_with_given_sigma_1(messages: &[FieldElement],
                                   sigkey: &Sigkey,
                                   offset: usize,
                                   h: &SignatureGroup) -> Result<SignatureGroup, PSError> {
        if sigkey.y.len() != offset + messages.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: offset + messages.len(),
                given: sigkey.y.len()
            });
        }
        // h^(x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ...) = g^{u * (x + y_j*m_j + y_{j+1}*m_{j+1} + y_{j+2}*m_{j+2} + ...)}
        let mut exp = sigkey.x.clone();
        for i in 0..messages.len() {
            exp += &sigkey.y[offset + i] * &messages[i];
        }
        let h_exp = h * &exp;
        Ok(h_exp)
    }

    /// Verify a signature. Can verify unblinded sig received from a signer and the aggregate sig as well.
    pub fn verify(
        &self,
        messages: Vec<FieldElement>,
        vk: &Verkey,
        params: &Params,
    ) -> Result<bool, PSError> {
        if vk.Y_tilde.len() != messages.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: vk.Y_tilde.len(),
                given: messages.len()
            });
        }
        if self.is_identity() {
            return Ok(false);
        }

        Ok(self.pairing_check(messages, vk, params))
    }

    /// Byte representation of the signature
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.sigma_1.to_bytes());
        bytes.append(&mut self.sigma_2.to_bytes());
        bytes
    }

    pub fn check_verkey_and_messages_compat(
        messages: &[FieldElement],
        verkey: &Verkey,
    ) -> Result<(), PSError> {
        if messages.len() != verkey.Y_tilde.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: verkey.Y_tilde.len(),
            });
        }
        Ok(())
    }

    pub fn check_sigkey_and_messages_compat(
        messages: &[FieldElement],
        sigkey: &Sigkey,
    ) -> Result<(), PSError> {
        if sigkey.y.len() != messages.len() {
            return Err(PSError::UnsupportedNoOfMessages {
                expected: messages.len(),
                given: sigkey.y.len()
            });
        }
        Ok(())
    }

    /// Checks if a signature has identity elements. A valid signature should not have identity elements.
    pub fn is_identity(&self) -> bool {
        self.sigma_1.is_identity() || self.sigma_2.is_identity()
    }

    /// Do the multi-exp and pairing check during verification.
    pub(crate) fn pairing_check(&self, messages: Vec<FieldElement>, vk: &Verkey, params: &Params) -> bool {
        let mut Y_m_bases = VerkeyGroupVec::with_capacity(messages.len());
        let mut Y_m_exps = FieldElementVector::with_capacity(messages.len());
        for (i, msg) in messages.into_iter().enumerate() {
            Y_m_bases.push(vk.Y_tilde[i].clone());
            Y_m_exps.push(msg);
        }
        // Y_m = X_tilde * Y_tilde[1]^m_1 * Y_tilde[2]^m_2 * ...Y_tilde[i]^m_i
        let Y_m = &vk.X_tilde + &(Y_m_bases.multi_scalar_mul_var_time(Y_m_exps.as_ref()).unwrap());
        // e(sigma_1, Y_m) == e(sigma_2, g2) => e(sigma_1, Y_m) * e(-sigma_2, g2) == 1, if precomputation can be used, then
        // inverse in sigma_2 can be avoided since inverse of g_tilde can be precomputed
        let e = ate_2_pairing(&self.sigma_1, &Y_m, &(self.sigma_2.negation()), &params.g_tilde);
        e.is_one()
    }

    /// Generate first element of the signature by hashing the messages. Since all messages are of
    /// same size, the is no need of a delimiter between the byte representation of the messages.
    fn generate_sigma_1_from_messages(messages: &[FieldElement]) -> SignatureGroup {
        let mut msg_bytes = vec![];
        for i in messages {
            msg_bytes.append(&mut i.to_bytes());
        }
        SignatureGroup::from_msg_hash(&msg_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::keygen;
    // For benchmarking
    use std::time::{Duration, Instant};

    #[test]
    fn test_signature_all_known_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, vk) = keygen(count_msgs, &params);
            let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
            let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();
            assert!(sig.verify(msgs, &vk, &params).unwrap());
        }
    }

    #[test]
    fn test_deterministic_signature_all_known_messages() {
        let params = Params::new("test".as_bytes());
        for i in 0..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, vk) = keygen(count_msgs, &params);
            let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
            let sig = Signature::new_deterministic(msgs.as_slice(), &sk).unwrap();
            assert!(sig.verify(msgs, &vk, &params).unwrap());
        }
    }

    #[test]
    fn test_rss_sig(){
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(count_msgs, &params);
        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let signature = RSignature::rss_generate_signature(&msgs, &sk, &params);
        //let index = vec![];
        // let (redacted_signature, redacted_message) = RSignature::rss_derive_signature(pk, signature, &msgs, index);
        //let verification = RSignature::verifyrsignature(pk, signature, &msgs, index);
        //println!("{:?}", signature);
        //println!("{:?}", redacted_message); -> Redacts correctly
        //println!("{:?}", verification);
    }
// https://hackmd.io/UJFBOl2DToSbFjFoEoMbOA?view
}