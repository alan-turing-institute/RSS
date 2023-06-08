use amcl_wrapper::field_elem::FieldElement;
use canonical_flatten::CanonicalFlatten;
use std::collections::HashMap;
use std::iter::zip;

pub trait MessageEncode: CanonicalFlatten {
    fn encode(&self) -> EncodedMessages {
        let data = self.flatten();
        let mut idxs = Vec::new();
        let msgs = data.iter().enumerate().map(|(i,m)| {
                // split value from keys to test for empty values
                let value = m.splitn(2,":").nth(1).unwrap();
                if value.len() == 0 || value == "[]" {
                    FieldElement::zero()
                } else {
                    // push "math index" to idxs
                    idxs.push(i+1);
                    FieldElement::from_msg_hash(m.as_bytes())
                }
            }).collect();
        EncodedMessages { msgs, infered_idxs: idxs }
    }

    fn field_idx_map(&self) -> HashMap<String,usize> {
        zip(
            self.flatten().to_owned().iter().map(|kv| kv.split(":").next().unwrap().to_string()),
            (0..self.flatten().len()).map(|i| i+1 ).collect::<Vec<usize>>()
        ).collect()
    }
}

pub struct EncodedMessages {
    msgs: Vec<FieldElement>,
    pub infered_idxs: Vec<usize>
}

impl EncodedMessages {
    pub fn as_slice(&self) -> &[FieldElement] {
        &self.msgs
    }

    pub fn to_vec(&self) -> Vec<FieldElement> {
        self.msgs.clone()
    }
}