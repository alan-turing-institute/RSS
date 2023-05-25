use super::vc::VC;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedVC {
    pub vc : VC,
    pub proof : String
}