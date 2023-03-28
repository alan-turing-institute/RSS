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

impl RSignature{
    pub fn rss_generate_signature(messages: &[FieldElement], sk: &SKrss, params: &Params) -> RSignature{
        let rss_sigma_1 = SignatureGroup::random(); // sigma_1 
        let mut x = 
        FieldElement::pow(&sk.x,&FieldElement::one()); // x
        let mut i_exponent = FieldElement::one(); // use as index
        
        let sigma_2_y_i = FieldElement::one(); // let it be 1 for now
        let mut sum_y_m = FieldElement::new();
        
        for i in 0.. messages.len(){
            
            let y_i = FieldElement::pow(&sk.y, &i_exponent); // calculate y^i
            sum_y_m = FieldElement::multiply(&messages[i], &y_i); // Calculate y^i * m_i
            i_exponent.add_assign_(&FieldElement::one()); // i+1
        }

        x.add_assign_(&sum_y_m); // x + sum of y^i * m_i
        let rss_sigma_2 =rss_sigma_1.scalar_mul_variable_time(&x); // Calculate sigma_2 
        let sigma_3_id = SignatureGroup::identity();
        let sigma_4_id = VerkeyGroup::identity();
        RSignature { sigma_1: (rss_sigma_1), sigma_2: (rss_sigma_2), sigma_3:(sigma_3_id), sigma_4: (sigma_4_id)}
    }

    pub fn rss_derive_signature(pk:PKrss, rsig: RSignature,messages: &[FieldElement],index: Vec<i32>) -> RSignature{
        let r = FieldElement::random(); // sample r 
        let t = FieldElement::random(); // sample t 
        let r_clone = FieldElement::clone(&r);
        let t_clone = FieldElement::clone(&t);
        let sigma_1_prime = rsig.sigma_1 * r; // sigma'1 = sigma1 * r 
        let sigma_2_r = rsig.sigma_2.scalar_mul_const_time(&r_clone); 
        let mut sigma_1_prime_t = sigma_1_prime.scalar_mul_const_time(&t_clone);
        let mut sigma_2_prime = sigma_1_prime_t+ sigma_2_r;
        // sigma'2 = (sigma2)^r * (sigma1')^t
        
        let mut i: i32= 1;
        let mut j= 1;
        let mut accumulator = pk.X_tilde.scalar_mul_const_time(&FieldElement::new()); // set to 0
        for _ in 0..messages.len(){
            if index.contains(&i){
                i += 1;
            } else{
                let Y_tilde_i = &pk.Y_tilde_i[j];
                let Y_tilde_i_mj = Y_tilde_i.scalar_mul_const_time(&messages[j]);
                accumulator += Y_tilde_i_mj;
                j += 1;
            }
        };
        let g_tilde_t = pk.g_tilde * t_clone;
        let sigma_prime_tilde = g_tilde_t + accumulator;

        let sigma_1_prime_string = sigma_1_prime.to_string();
        let sigma_2_prime_string = sigma_2_prime.to_string();
        let sigma_prime_tilde_string = sigma_prime_tilde.to_string();
        let clone_index = index.clone();
        let index_string = index.into_iter().map(|i| i.to_string()).collect::<String>();
        
        let mut c = vec![];

        let mut k:i32 = 1;
        for _ in 0..messages.len(){
            if clone_index.contains(&k){
                let k_index: String = k.to_string();
                let concantenated= String::clone(&sigma_1_prime_string) + &sigma_2_prime_string + &sigma_prime_tilde_string
                + &index_string+ &k_index;
                let concantenated_bytes = concantenated.as_bytes();
                let c_i : FieldElement= FieldElement::from_msg_hash(&concantenated_bytes);           
                c.push(c_i); // How is C_i a scalar???
                k += 1;
            } else{
                k+=1;
            }
        }
        let mut p: i32= 1;
        let mut jj: i32 =1;
        let mut z: usize =1;
        let mut sigma_3_prime = rsig.sigma_2.scalar_mul_const_time(&FieldElement::new());

        for _ in 0..messages.len(){
            if clone_index.contains(&p){
                let mut Y_index = messages.len()+1 as usize-i as usize;
                let mut Y_t = SignatureGroup::new();
                if (Y_index > messages.len()+1){
                    Y_t = pk.Y_k_nplus2_to_2n[Y_index].clone();
                } else {
                    Y_t = pk.Y_j_1_to_n[Y_index].clone();
                }
                Y_t = Y_t.scalar_mul_const_time(&t);
                let mut Y_mj = SignatureGroup::new();
                if clone_index.contains(&jj){
                    jj +=1;
                } else {
                    let mut Y_index_1 = messages.len() + 1 as usize-i as usize + jj as usize;
                    if (Y_index_1 > messages.len()+1){
                        Y_mj = pk.Y_k_nplus2_to_2n[Y_index_1].clone();
                    } else {
                        Y_mj = pk.Y_j_1_to_n[Y_index_1].clone();
                    }
                let mut product = Y_t + Y_mj;
                product = product.scalar_mul_const_time(&c[z]);
                sigma_3_prime += product;
                z+=1;
                }
            } else {
                p+=1;
            }
        }
        // need to derive a message that has been edited? 
        RSignature{sigma_1: (sigma_1_prime), sigma_2: (sigma_2_prime), sigma_3: (sigma_3_prime), sigma_4:(sigma_prime_tilde)}
    }
    // pk:PKrss, rsig: RSignature,messages: &[FieldElement],index: Vec<i32>
        // if rsig.sigma_1 = SignatureGroup::identity(){
            // return FALSE Bool
        // }
        //}
    // pub fn verifyrsignature(pk:PKrss, rsig:RSignature, ){
    
    //}
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
    fn test_rss(){
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(count_msgs, &params);
        
    }

}