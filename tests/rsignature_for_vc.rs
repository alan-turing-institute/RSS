use ps_sig::keys::{rsskeygen,Params, PKrss};
use ps_sig::message_structure::message_encode::MessageEncode;
use ps_sig::message_structure::signed_vc::SignedVC;
use ps_sig::message_structure::vc::{VC,CredentialSubject, Address};
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

    // vc is flattened and encoded into a vec of FieldElements
    let encoded_msgs = vc.encode();

    // TODO Discussion about issuer public and private key depends on length of msgs!
    let params = Params::new("test".as_bytes());
    let (issuer_sk,issuer_pk) = rsskeygen(encoded_msgs.as_slice().len(), &params);

    // the issuer constructs a full RSignature
    let full_sig = RSignature::new(encoded_msgs.as_slice(), &issuer_sk);

    // placing the signature in the VC’s proof field (as in the signed VC in Example 1).
    // then issuing that VC to the holder
    let signed_vc = SignedVC {
        vc,
        proof : full_sig.to_hex()
    };

    println!("{}",serde_json::to_string_pretty(&signed_vc).unwrap());
    (signed_vc, issuer_pk)
}

fn holders_actions(signed_full_vc: SignedVC, issuer_pk: &PKrss) -> SignedVC {
    // decodes the hex representation of the signature
    let full_sig = RSignature::from_hex(&signed_full_vc.proof);

    // takes the VC and flattens and encodes
    let encoded_msgs = signed_full_vc.vc.encode();

    // generate a lookup table that maps the field names of the vc to their indexes in the 
    // flattened, encoded vc
    let math_idx_lookup = signed_full_vc.vc.field_idx_map();

    // Suppose the length of the field element vector is n and the holder wishes to disclose 
    // the information at indices idxs.
    let idxs = ["context","address_country","name"].map(|key| math_idx_lookup[key]);

    // the holder constructs a derived RSignature, given idxs.
    let rsig = full_sig.derive_signature(issuer_pk, encoded_msgs.as_slice(), &idxs);

    // The holder then constructs (and presents) a redacted VC by:
    // taking the VC template
    // filling in the non-redacted message fields
    // leaving the redacted mesage fields empty
    // placing the derived RSignature in the VC’s proof field.
    let signed_vc = SignedVC {
        vc : VC {
            context: signed_full_vc.vc.context,
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
            issuer : "".to_string(),
            _type: vec![]
        },
        proof: rsig.to_hex()
    };
    println!("{}",serde_json::to_string_pretty(&signed_vc).unwrap());
    signed_vc
}

fn verifiers_actions(signed_redacted_vc: SignedVC, issuer_pk: &PKrss) -> RSVerifyResult {
    // flattens and encodes the redacted vc
    // identifies which fields are not redacted, and their indices (which will be the set idxs)
    // hashes each of the non-redacted messages and places the hashes at the correct indices in 
    // a vector of total length n.
    // when the vc is partially redacted, the encode function places a dummy value (e.g. field
    // element zero) in the vector of hashes at all indices except those in idxs
    let encoded_msgs = signed_redacted_vc.vc.encode();
    let math_idx_lookup = signed_redacted_vc.vc.field_idx_map();

    // verifier can check that exactly the right fields are populated in the redacted vc
    assert_eq!(
        encoded_msgs.infered_idxs,
        ["context","address_country","name"].map(|key| math_idx_lookup[key])
    );

    // performs the RSS verification procedure on this vector of hashes.
    // If the derived RSignature is valid, the verifier concludes that the issuer signed a vector 
    // of messages of length n in which the messages at the indices in idxs were identical to the 
    // messages provided by the holder.
    let rsig = RSignature::from_hex(&signed_redacted_vc.proof);

    RSignature::verifyrsignature(issuer_pk, &rsig, encoded_msgs.as_slice(), &encoded_msgs.infered_idxs)
}

fn vc_example_1() -> VC {
    return serde_json::from_str(r##"{
        "@context" : [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org/"
        ],
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
        "issuer" : "did:key:z6MkpbgE27YYYpSF8hd7ipazeJxiUGMEzQFT5EgN46TDwAeU",
        "type" : [
            "VerifiableCredential",
            "IdentityCredential"
        ]
        }"##).unwrap()
}

fn verify_full_vc(signed_full_vc: SignedVC, issuer_pk: &PKrss) -> RSVerifyResult {
    let full_sig = RSignature::from_hex(&signed_full_vc.proof);

    // given full msgs length = 11
    let idxs = [1,2,3,4,5,6,7,8,9,10,11];
    
    RSignature::verifyrsignature(
        issuer_pk,
        &full_sig,
        signed_full_vc.vc.encode().as_slice(),
        &idxs
    )
}