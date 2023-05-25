
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FlatVC {
    // context : Vec<String>,
    #[serde(flatten)]
    pub credential_subject : FlatCredentialSubject,
    pub id : String,
    pub issuance_date : String,
    pub issuer : String,
    // _type : Vec<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FlatCredentialSubject {
    #[serde(flatten)]
    pub address : Address,
    pub birth_date : String,
    pub name : String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub address_country : String,
    pub address_locality : String,
    pub postal_code : String,
    pub street_address : String
}

impl IntoIterator for FlatVC {
    type Item = String;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        vec![
            "addressCountry:".to_string() + &self.credential_subject.address.address_country,
            "addressLocality:".to_string() + &self.credential_subject.address.address_locality,
            "postalCode:".to_string() + &self.credential_subject.address.postal_code,
            "streetAddress:".to_string() + &self.credential_subject.address.street_address,
            "birthDate:".to_string() + &self.credential_subject.birth_date,
            "name:".to_string() + &self.credential_subject.name,
            "id:".to_string() + &self.id,
            "issuanceDate:".to_string() + &self.issuance_date,
            "issuer:".to_string() + &self.issuer

        ].into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialise() {
        let flat_vc = FlatVC {
            // context : vec![
            //     "https://www.w3.org/2018/credentials/v1".to_string(),
            //     "https://schema.org/".to_string()],
            credential_subject : FlatCredentialSubject {
                address: Address {
                    address_country : "UK".to_string(),
                    address_locality : "London".to_string(),
                    postal_code : "SE1 3WY".to_string(),
                    street_address : "10 Main Street".to_string()
                },
                birth_date: "1989-03-15".to_string(),
                name: "J. Doe".to_string()
            },
            id : "http://example.edu/credentials/332".to_string(),
            issuance_date : "2020-08-19T21:41:50Z".to_string(),
            issuer : "did:key:z6MkpbgE27YYYpSF8hd7ipazeJxiUGMEzQFT5EgN46TDwAeU".to_string(),
            // _type : vec![
            //    "VerifiableCredential".to_string(),
            //    "IdentityCredential".to_string()
            // ]
        };

        let serial = serde_json::to_string_pretty(&flat_vc).unwrap();
        assert_eq!(serial,
            "{\n  \"addressCountry\": \"UK\",
  \"addressLocality\": \"London\",
  \"postalCode\": \"SE1 3WY\",
  \"streetAddress\": \"10 Main Street\",
  \"birthDate\": \"1989-03-15\",
  \"name\": \"J. Doe\",
  \"id\": \"http://example.edu/credentials/332\",
  \"issuanceDate\": \"2020-08-19T21:41:50Z\",
  \"issuer\": \"did:key:z6MkpbgE27YYYpSF8hd7ipazeJxiUGMEzQFT5EgN46TDwAeU\"\n}");
        println!("{}",serial)
    }
}