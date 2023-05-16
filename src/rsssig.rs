// Scheme defined in 2016 paper, CT-RSA 2016 (eprint 2015/525), section 4.2.
// The idea for blind signatures can be taken from Coconut
use std::ops::Add;
use hex_literal::hex;
use sha2::{Sha256, Sha512, Digest};
use crate::errors::PSError;
use crate::{GT, ate_2_pairing, VerkeyGroup, VerkeyGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use crate::keys::{PKrss, SKrss, Params,Sigkey,Verkey,rsskeygen};


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

// pub fn did_to_fieldelements(message:DiD) -> FieldElement{
//     let mut context_bytes = message.context.into_bytes();
//     FieldElement;
// }
// Implement trait to convert from math index starting from 1 to a computational index starting from 0
impl Redact for Message {
    // RECALL: Index I is the set of stuff we want to keep!
    fn to_redacted_message(&self, index: Vec<usize>) -> RedactedMessage{
        let mut i = 0; // loop over index i for unredacted parts
        let mut j: usize = 0; // use it to reference parts of a message 
        let mut redacted_message :RedactedMessage = vec![None; self.len()]; // create empty vector for message 
        for _ in 0..self.len(){
            if index.contains(&i){
                redacted_message[j] = Some(self[j].clone()); // copy unredacted parts of a message
                i+=1; // increment
                j += 1; // increment
            } else {
                redacted_message[j] = None; // message is redacted
                i += 1; // increment
                j += 1; // increment         
            }
        }
        redacted_message
    } // Works as intended. We input an index I of things we want to keep, and output is correct. 
}

impl RSignature{
    // Given a secret key, a message of length n, and the parameters, output a signature and a redacted message
    // Seems correct to me -> I've been printing each output but of course no way to hand-check...
    pub fn rss_generate_signature(messages: &[FieldElement], sk: &SKrss) -> RSignature{
        let rss_sigma_1 = SignatureGroup::random(); // Generate sigma1, ok
        let mut x = sk.x.clone(); // x, ok
        //println!("{:?}", x);
        let mut i_exponent = FieldElement::one(); // use as index for y^i
        let mut sum_y_m = FieldElement::new(); // set sum of y^i mul mi at 0 
        for i in 0..messages.len(){
            let y_i = FieldElement::pow(&sk.y, &i_exponent); // calculate y^i, ok
            let y_i_m_i = &messages[i] * &y_i; // Calculate y^i * m_i, ok
            sum_y_m += y_i_m_i; // accumulate y^i * m_i for different i values, ok
            i_exponent = i_exponent.add(&FieldElement::one()); // increment i -> usable for 1 to n, ok
        }
        // println!("{:?}", i_exponent);
        // sum_y_m seems to be correct index wise...
        let exponent = &x + &sum_y_m; // x + sum of y^i * m_i, ok
        //println!("{:?}", x);
        //println!("{:?}", rss_sigma_1);
        let rss_sigma_2 =rss_sigma_1.scalar_mul_const_time(&exponent); // Calculate sigma_2 mul (x+sum of (y^i mul m_i)) 
        // RSS Signature is a bit different than the paper - we need the identity in sigma3 and sigma4 as part of verify for
        // unmodified signature
        // signature seems okay, like key generation its a simple case of addition and multiplication with the indexes checking out...
        RSignature { sigma_1:rss_sigma_1, sigma_2: rss_sigma_2, sigma_3:SignatureGroup::identity(), sigma_4: VerkeyGroup::identity()}
    } // sigma 3 and sigma 4 are correct -> lines up with identity element as needed

    // Given a public key, a signature, a message of length n, and an index of things we want to keep, 
    // output a derived signature and redacted message 
    pub fn rss_derive_signature(pk:PKrss, rsig: RSignature,messages: &[FieldElement],index: Vec<usize>) -> (RSignature, RedactedMessage){
        let r = FieldElement::random(); // Generate r
        let t = FieldElement::random(); // Generate t
        let sigma_1_prime = rsig.sigma_1.scalar_mul_const_time(&r); // sigma'1 = sigma1 * r 
        let sigma_2_r = rsig.sigma_2.scalar_mul_const_time(&r); // sigma2 mul r 
        let sigma_1_prime_t = sigma_1_prime.scalar_mul_const_time(&t); // sigma'1 mul t
        let sigma_2_prime = sigma_1_prime_t.add(sigma_2_r) ; // sigma'2 = (sigma2 mul r) + (sigma'1 mul t)
        let clone_index: Vec<usize> = index.clone(); // clone index

        let vec_in_I = clone_index.clone();
        let mut vec_not_in_I: Vec<usize> = Vec::new();
        for j in 0..messages.len(){
            if !clone_index.contains(&j){
            vec_not_in_I.push(j);
            }
        }

        let mut accumulator = VerkeyGroup::new(); // set to 0 for sum of Y~j mul mj
        for j in &vec_not_in_I{
                // let Y_tilde_i = ; // select Y~[j]
                let Y_tilde_i_mj = &pk.Y_tilde_i[*j].scalar_mul_const_time(&messages[*j]); // Y~[j] mul m[j]
                accumulator += Y_tilde_i_mj; // Sum Y~[i] mul m[j]
            
        };

        let g_tilde_t = pk.g_tilde.scalar_mul_const_time(&t) ; // g~ mul t
        let sigma_prime_tilde = g_tilde_t + accumulator; // sigma~' = g~ mul t + sum of (Y~[j] mul m[j])

        let sigma_1_prime_string = sigma_1_prime.to_string(); // convert sigma1' to string
        let sigma_2_prime_string = sigma_2_prime.to_string(); // convert sigma2' to string
        let sigma_prime_tilde_string = sigma_prime_tilde.to_string(); // convert sigma~' to string
        let index_string = index.into_iter().map(|i| i.to_string()).collect::<String>(); // convert each element of index to string
        
        let mut c = FieldElementVector::new(messages.len()); // create a vector to store c_i

        let mut i = 0; // create index to find i in Index
        for i in 0..messages.len(){
            if clone_index.contains(&i){
                let i_index: String = i.to_string(); // convert k to string
                let concantenated= String::clone(&sigma_1_prime_string) + &sigma_2_prime_string + &sigma_prime_tilde_string
                + &index_string+ &i_index; // create concantenation for hash input
                let concantenated_bytes = concantenated.as_bytes(); // convert hash input to bytes
                let c_i : FieldElement= FieldElement::from_msg_hash(&concantenated_bytes); // generate c_i          
                c[i]= (c_i); // add c_i to a vector
            } else {
                c[i]=(FieldElement::new());
            }
        }
        let mut sigma_3_prime = SignatureGroup::new(); // create an empty element for sigma_3
        //println!("{:?}", c);
        // NOTE: i is only for 1 to n, but we've been working with 0<=i<n. I changed Y^t_n+1-i to Y^t_n-i to account for this.

        for i in vec_in_I{
            let mut Y_mj = SignatureGroup::new(); // create blank to store Y^mj
            for j in &vec_not_in_I{
                let mut Y_mji = SignatureGroup::new();
                let Y_mj_index = messages.len() + 1 - i + j;
                //println!("{:?}", Y_mj_index);
                if Y_mj_index > (messages.len()+1){
                    // j = 1 and 2, Y_mj_index = 5 and 6
                    let new_index = Y_mj_index- messages.len()-2;
                    // new index for n+2 to 2n = 0 and 1
                    //println!("{:?}", new_index);
                    Y_mji = pk.Y_k_nplus2_to_2n[new_index].clone().scalar_mul_const_time(&messages[*j]);
                } else {
                    //println!("{:?}", Y_mj_index-1);
                    // need to figure out equation for index when index =< n
                    Y_mji = pk.Y_j_1_to_n[Y_mj_index-1].clone();
                }
                Y_mj +=Y_mji; // acumulate for Y_mj
            }
            let mut Y_t_i = SignatureGroup::new(); // create blank to find each constituent of Y^t
            // messages.len()-i-1 seems like the correct index -> take into account i from 0 and vector ranges 0 to n-1
            //println!("{:?}", messages.len()-i-1);
            Y_t_i = pk.Y_j_1_to_n[messages.len()-i-1].clone().scalar_mul_const_time(&t) + Y_mj;
            sigma_3_prime = Y_t_i.scalar_mul_const_time(&c[i]);
        }
        let redacted_message = messages.to_redacted_message(clone_index);
        (RSignature{sigma_1: (sigma_1_prime), sigma_2: (sigma_2_prime), sigma_3: (sigma_3_prime), sigma_4:(sigma_prime_tilde)},  redacted_message)
    }

    pub fn verifyrsignature(pk:PKrss, rsig:RSignature, messages: &[FieldElement], index: Vec<usize>)->bool{
        let mut test_check: bool = false; // start as false
        let index_clone = index.clone();
        if rsig.sigma_1 == SignatureGroup::identity(){ // check if sigma3 = identity
            println!("incorrect sigma_1"); 
        } else {
            let mut accumulator = pk.X_tilde.add(&rsig.sigma_4); // X~ + sigma~ correct
            for i in index_clone{
                accumulator = accumulator.add(pk.Y_tilde_i[i].scalar_mul_const_time(&messages[i])); 
            }
            let first_equation = GT::ate_pairing(&accumulator, &rsig.sigma_1);
            let second_equation = GT::ate_pairing(&pk.g_tilde, &rsig.sigma_2);

            if first_equation == second_equation{
                println!("Passed first test");
            } else {
               println!("Failed first test");
               return test_check;
            }
            // Given unredacted case, third and fourth equation is all zero
            let third_equation = GT::ate_pairing(&pk.g_tilde, &rsig.sigma_3); // correct
            let clone_index = index.clone();
            let mut c = FieldElementVector::new(messages.len()); // create a vector to store c_i
            let sigma_1_string = rsig.sigma_1.to_string();
            let sigma_2_string = rsig.sigma_2.to_string();
            let sigma_tilde_string = rsig.sigma_4.to_string();
            let index_string = index.into_iter().map(|i| i.to_string()).collect::<String>(); // convert each element of index to string
            
            for i in &clone_index{
                let concatenated = String::clone(&sigma_1_string) + &sigma_2_string 
                + &sigma_tilde_string + &index_string + &i.to_string();
                let concantenated_bytes = concatenated.as_bytes();
                let c_i : FieldElement= FieldElement::from_msg_hash(&concantenated_bytes); // generate c_i
                c[*i]=c_i; // add c_i to a vector
                     // I've checked c -> it is the same as when generating redacted signature
                }
            //println!("{:?}",c); 
            let mut accumulator_2 = SignatureGroup::new();
            let index_clone = clone_index.clone();
            for i in 0..messages.len(){
                if index_clone.contains(&i){
                    let index_value = messages.len()-i-1;
                    //println!("{:?}",index_value);
                    if index_value <= messages.len(){
                        accumulator_2 += pk.Y_j_1_to_n[index_value].scalar_mul_const_time(&c[i]);
                    } else {
                        accumulator_2 += pk.Y_k_nplus2_to_2n[index_value].scalar_mul_const_time(&c[i]);
                    }
                }
            }
            let fourth_equation = GT::ate_pairing(&rsig.sigma_4, &accumulator_2);
            if third_equation == fourth_equation{
                test_check = true;
                println!("Passed second test");
            } else {
                test_check = false;
               println!("Failed second test");
            }
        }
        return test_check;
    }


    pub fn verifyredactedsignature(pk:PKrss, rsig:RSignature, messages: RedactedMessage, index: Vec<usize>)->bool{
        let mut new_message: Vec<FieldElement> = vec![FieldElement::new();messages.len()];
        for i in 0..new_message.len(){
            if messages[i] == None{
                new_message[i]=FieldElement::new();
            } else {
                let clone_message = messages[i].clone();
                new_message[i]=clone_message.unwrap();
            }
        }
        let mut test_check: bool = false;
        let index_clone = index.clone();
        if rsig.sigma_1 == SignatureGroup::identity(){ // check if sigma3 = identity
            println!("incorrect sigma_1"); // if yes, it's an invalid signature
        } else {
            let mut accumulator = pk.X_tilde + &rsig.sigma_4; // X~ + sigma~ correct
            for i in index_clone{
                accumulator += pk.Y_tilde_i[i].scalar_mul_const_time(&new_message[i]); 
            }
            let first_equation = GT::ate_pairing(&accumulator, &rsig.sigma_1);
            let second_equation = GT::ate_pairing(&pk.g_tilde, &rsig.sigma_2);
            if first_equation == second_equation{ 
                println!("Passed first test");
            } else { 
                println!("Failed first test");
            }
            
            let third_equation = GT::ate_pairing(&pk.g_tilde, &rsig.sigma_3); // correct
            let clone_index = index.clone();
            let mut c = FieldElementVector::new(new_message.len()); // create a vector to store c_i
            let sigma_1_string = rsig.sigma_1.to_string();
            let sigma_2_string = rsig.sigma_2.to_string();
            let sigma_tilde_string = rsig.sigma_4.to_string();
            let index_string = index.into_iter().map(|i| i.to_string()).collect::<String>(); // convert each element of index to string
            
            for i in &clone_index{
                let concatenated = String::clone(&sigma_1_string) + &sigma_2_string 
                + &sigma_tilde_string + &index_string + &i.to_string();
                let concantenated_bytes = concatenated.as_bytes();
                let c_i : FieldElement= FieldElement::from_msg_hash(&concantenated_bytes); // generate c_i
                c[*i]=c_i; 
                }
            // c vector is correct, equivalent to c for redacted signature. 
            // println!("{:?}",c.len()); 
            let mut accumulator_2 = SignatureGroup::new(); // start from 0
            let index_clone = clone_index.clone();
            //println!("{:?}",index_clone);
            for i in 0..messages.len(){ // go through everything in index
                if index_clone.contains(&i){
                    let index_value = messages.len() -i - 1;
                    //println!("{:?}",index_value);
                    accumulator_2 += pk.Y_j_1_to_n[index_value].scalar_mul_const_time(&c[i]);
                    // n + 1 - i as original index, modified to suit value of i
                }
            }
            let fourth_equation = GT::ate_pairing(&rsig.sigma_4, &accumulator_2);
            //println!("{:?}",third_equation);
            println!("{:?}",fourth_equation);
            if third_equation == fourth_equation{
                test_check = true;
                println!("Passed second test");
            } else {
                test_check = false;
               println!("Failed second test");
            }
        }
        return test_check;
    }
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
    fn check_exponent() {
        let count_msgs = 1;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(count_msgs, &params);
        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let signature = RSignature::rss_generate_signature(&msgs, &sk);
        let index = vec![];
        let verify = RSignature::verifyrsignature(pk, signature, &msgs, index);
        //assert_eq!(SignatureGroup::identity(),signature.sigma_3);
    }


    #[test]
    fn generate_normal_rsig() {
        let count_msgs = 3; // n
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(count_msgs, &params);
        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let signature = RSignature::rss_generate_signature(&msgs, &sk);
        let index_kept = vec![0,1,2];
        let verify = RSignature::verifyrsignature(pk, signature, &msgs, index_kept);
        println!("{:?}", verify);
    }
    // test passes! when trying it out just remember to make sure the index is right
    // this test is for unredacted message, so index is every element
    // Recall index is the stuff we want to keep
    #[test]
    fn test_rss_sig(){
        let count_msgs = 3;
        let params = Params::new("test".as_bytes());
        let (sk, pk) = rsskeygen(count_msgs, &params);
        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let signature = RSignature::rss_generate_signature(&msgs, &sk);
        let index = vec![0];
        let index_clone = index.clone();
        let pk_new = pk.clone();
        let (redacted_signature, redacted_message) = RSignature::rss_derive_signature(pk, signature, &msgs, index);
        let verification = RSignature::verifyredactedsignature(pk_new, redacted_signature, redacted_message, index_clone);
        //println!("{:?}", redacted_message);
    }

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