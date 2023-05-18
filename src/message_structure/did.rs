
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiD {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub type_field: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub name: String,
    pub address: Address,
    pub birth_date: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub street_address: String,
    pub postal_code: String,
    pub address_locality: String,
    pub address_country: String,
}