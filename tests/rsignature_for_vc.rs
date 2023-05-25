use ps_sig::keys::{rsskeygen,Params, PKrss};
use ps_sig::message_structure::flat_vc::{FlatVC, Address};
use ps_sig::message_structure::signed_vc::SignedVC;
use ps_sig::message_structure::vc::{VC,CredentialSubject};
use ps_sig::rsssig::{RSignature, RSVerifyResult};



#[test]
fn test_rsignature_for_vc() {
    let (signed_full_vc,issuer_pk) = issuers_actions();

    // check full sig verifies -------------------------------------------------------
    let verify_full = verify_full_vc(signed_full_vc.clone(), &issuer_pk);
    assert_eq!(verify_full, RSVerifyResult::Valid);
    // -------------------------------------------------------------------------------

    let signed_redacted_vc = holders_actions(signed_full_vc, &issuer_pk);

    let verification = verifiers_actions(signed_redacted_vc, &issuer_pk);

    assert_eq!(verification, RSVerifyResult::Valid);
}

fn issuers_actions() -> (SignedVC, PKrss) {
    // The issuer generates the standart (possibly nested) vc
    let vc: VC = vc_example_1();

    // The issuer constructs a full RSignature on the (canonicalised & flattened) VC
    let unsigned_flat_vc: FlatVC = vc.clone().into();
    // IntoIter implimented for FlatVC
    let unsigned_flat_vc_iter = unsigned_flat_vc.clone().into_iter();

    // TODO Discussion about issuer public and private key depends on length of msgs!
    let params = Params::new("test".as_bytes());
    let (issuer_sk,issuer_pk) = rsskeygen(unsigned_flat_vc_iter.clone().count(), &params);

    // hashing each plaintext key-value attribute message
    // mapping each hash to a field element
    // assigning an index to each field element that matches the position of the corresponding 
    // key-value message in the canonical & flattened VC
    let (msgs,_,_) = RSignature::encode_json_msgs(unsigned_flat_vc_iter.as_slice());

    // the issuer constructs a full RSignature on the resulting vector of field elements
    let full_sig = RSignature::new(&msgs, &issuer_sk);

    // placing the signature in the VC’s proof field (as in the signed VC in Example 1).
    // then issuing that VC to the holder
    let signed_vc = SignedVC {
        vc,
        proof : full_sig.to_hex()
    };

    (signed_vc, issuer_pk)
}

fn holders_actions(signed_full_vc: SignedVC, issuer_pk: &PKrss) -> SignedVC {
    // decodes the byte representation of the signature
    let full_sig = RSignature::from_hex(&signed_full_vc.proof);

    // takes the VC and canonicalises & flattens it
    let flat_vc: FlatVC = signed_full_vc.vc.clone().into();

    // encodes the full set of messages and generates an idx lookup
    let (msgs,_,math_idx_lookup) = RSignature::encode_json_msgs(flat_vc.into_iter().as_slice());

    // Suppose the length of the field element vector is n and the holder wishes to disclose 
    // the information at indices idxs.
    let idxs = ["addressCountry","name"].map(|key| math_idx_lookup[key]);

    // the holder constructs a derived RSignature, given idxs.
    let (rsig,_) = full_sig.derive_signature(issuer_pk, &msgs, &idxs);

    // The holder then constructs (and presents) a redacted VC by:
    // taking the VC template
    // filling in the non-redacted message fields
    // leaving the redacted mesage fields empty
    // placing the derived RSignature in the VC’s proof field.
    SignedVC {
        vc : VC {
            credential_subject: CredentialSubject {
                address : Address {
                    address_country : signed_full_vc.vc.credential_subject.address.address_country,
                    address_locality : "".to_string(),
                    postal_code : "".to_string(),
                    street_address : "".to_string()
                },
                birth_date : "".to_string(),
                name : signed_full_vc.vc.credential_subject.name
            },
            id : "".to_string(),
            issuance_date: "".to_string(),
            issuer : "".to_string()
        },
        proof: rsig.to_hex()
    }
}

fn verifiers_actions(signed_redacted_vc: SignedVC, issuer_pk: &PKrss) -> RSVerifyResult {
    // The verifier:
    // takes the redacted VC and canonicalises & flattens it
    let flat_vc: FlatVC = signed_redacted_vc.vc.into();

    // assigns an index to each key-value pair in the resulting flattened VC (just as the issuer did)
    // identifies which fields are not redacted, and their indices (which will be the set idxs)
    // hashes each of the non-redacted messages and places the hashes at the correct indices in 
    // a vector of total length n.
    // places a dummy value (e.g. field element zero) in the vector of hashes at all indices except 
    // those in idxs
    let flat_vc_iter = flat_vc.clone().into_iter();
    let (msgs,idxs,math_idx_lookup) = RSignature::encode_json_msgs(flat_vc_iter.as_slice());

    // verifier can check that exactly the right fields are populated in the redacted vc
    assert_eq!(idxs,["addressCountry","name"].map(|key| math_idx_lookup[key]));

    // performs the RSS verification procedure on this vector of hashes.
    // If the derived RSignature is valid, the verifier concludes that the issuer signed a vector 
    // of messages of length n in which the messages at the indices in idxs were identical to the 
    // messages provided by the holder.
    let rsig = RSignature::from_hex(&signed_redacted_vc.proof);

    RSignature::verifyrsignature(issuer_pk, &rsig, &msgs, &idxs)
}

fn vc_example_1() -> VC {
    return serde_json::from_str(r##"{
        "credentialSubject" : {
           "address" : {
              "addressCountry" : "UK",
              "addressLocality" : "London",
              "postalCode" : "SE1 3WY",
              "streetAddress" : "10 Main Street"
           },
           "birthDate" : "1989-03-15",
           "name" : "J. Doe"
        },
        "id" : "http://example.edu/credentials/332",
        "issuanceDate" : "2020-08-19T21:41:50Z",
        "issuer" : "did:key:z6MkpbgE27YYYpSF8hd7ipazeJxiUGMEzQFT5EgN46TDwAeU"
        }"##).unwrap()
}

fn verify_full_vc(signed_full_vc: SignedVC, issuer_pk: &PKrss) -> RSVerifyResult {
    let full_sig = RSignature::from_hex(&signed_full_vc.proof);
    let flat_vc: FlatVC = signed_full_vc.vc.clone().into();
    let (msgs,_,_) = RSignature::encode_json_msgs(flat_vc.into_iter().as_slice());
    assert_eq!(9, msgs.len());

    // given full msgs length = 9
    let idxs = [1,2,3,4,5,6,7,8,9];
    
    RSignature::verifyrsignature(issuer_pk, &full_sig, &msgs, &idxs)
}