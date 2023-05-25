use super::flat_vc::{FlatVC,Address, FlatCredentialSubject};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VC {
    // context : Vec<String>,
    pub credential_subject : CredentialSubject,
    pub id : String,
    pub issuance_date : String,
    pub issuer : String,
    // _type : Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub address : Address,
    pub birth_date : String,
    pub name : String
}

impl Into<FlatVC> for VC {
    fn into(self) -> FlatVC {
        FlatVC {
            credential_subject : FlatCredentialSubject {
                address : self.credential_subject.address,
                birth_date : self.credential_subject.birth_date,
                name : self.credential_subject.name
            },
            id : self.id,
            issuance_date : self.issuance_date,
            issuer : self.issuer
        }
    }
}