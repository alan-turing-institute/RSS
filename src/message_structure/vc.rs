use canonical_flatten::CanonicalFlatten;
use crate::message_structure::message_encode::MessageEncode;

#[derive(Clone, Debug, Serialize, Deserialize, CanonicalFlatten)]
#[serde(rename_all = "camelCase")]
pub struct VC {
    #[serde(rename = "@context")]
    pub context : Vec<String>,
    pub credential_subject : CredentialSubject,
    pub id : String,
    pub issuance_date : String,
    pub issuer : String,
    #[serde(rename = "type")]
    pub _type : Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize, CanonicalFlatten)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub address : Address,
    pub birth_date : String,
    pub name : String
}

#[derive(Debug, Serialize, Deserialize, Clone, CanonicalFlatten)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub address_country : String,
    pub address_locality : String,
    pub postal_code : String,
    pub street_address : String
}

impl MessageEncode for VC {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialise() {
        let _: VC = serde_json::from_str(r##"{
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
            }"##).unwrap();
    }

    #[test]
    fn flatten() {
        let vc: VC = serde_json::from_str(r##"{
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
            }"##).unwrap();
        
        let flat_vc = vc.flatten();
        assert_eq!(vec![
            "context:[\"https://www.w3.org/2018/credentials/v1\", \"https://schema.org/\"]",
            "address_country:UK",
            "address_locality:London",
            "postal_code:SE1 3WY",
            "street_address:10 Main Street",
            "birth_date:1989-03-15",
            "name:J. Doe",
            "id:http://example.edu/credentials/332",
            "issuance_date:2020-08-19T21:41:50Z",
            "issuer:did:key:z6MkpbgE27YYYpSF8hd7ipazeJxiUGMEzQFT5EgN46TDwAeU",
            "_type:[\"VerifiableCredential\", \"IdentityCredential\"]",
        ], flat_vc);
    }
}