use amcl_wrapper::field_elem::FieldElement;
use canonical_flatten::CanonicalFlatten;
use std::collections::HashMap;
use std::iter::zip;

pub trait MessageEncode: CanonicalFlatten {
    fn encode_demo(&self) -> EncodedMessages {
        let data = self.flatten();
        let mut idxs = Vec::new();
        let msgs = data
            .iter()
            .enumerate()
            .map(|(i, m)| {
                // split value from keys to test for empty values
                let value = m.splitn(2, ":").nth(1).unwrap();
                if value.len() == 0 || value == "[]" {
                    FieldElement::zero()
                } else {
                    // push "math index" to idxs
                    idxs.push(i + 1);
                    FieldElement::from_msg_hash(m.as_bytes())
                }
            })
            .collect();
        EncodedMessages {
            msgs,
            infered_idxs: idxs,
        }
    }

    fn field_idx_map_demo(&self) -> HashMap<String, usize> {
        zip(
            self.flatten()
                .iter()
                .map(|kv| kv.split(":").next().unwrap().to_string()),
            (0..self.flatten().len())
                .map(|i| i + 1)
                .collect::<Vec<usize>>(),
        )
        .collect()
    }
}

#[derive(Debug)]
pub struct EncodedMessages {
    msgs: Vec<FieldElement>,
    pub infered_idxs: Vec<usize>,
}

impl EncodedMessages {
    pub fn as_slice(&self) -> &[FieldElement] {
        &self.msgs
    }

    pub fn to_vec(&self) -> Vec<FieldElement> {
        self.msgs.clone()
    }
}

impl From<Vec<String>> for EncodedMessages {
    fn from(data: Vec<String>) -> Self {
        let mut idxs = Vec::new();
        let msgs = data
            .iter()
            .enumerate()
            .map(|(i, m)| {
                // test for empty values
                let tail = m.split(":").last().unwrap();
                if tail.len() == 0 || tail == "[" {
                    FieldElement::zero()
                } else {
                    // push "math index" to idxs
                    idxs.push(i + 1);
                    FieldElement::from_msg_hash(m.as_bytes())
                }
            })
            .collect();
        EncodedMessages {
            msgs,
            infered_idxs: idxs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(CanonicalFlatten)]
    struct Data {
        field_a: String,
        field_b: Vec<String>,
        field_c: SubStruct,
    }
    #[derive(CanonicalFlatten)]
    struct SubStruct {
        field_d: String,
        field_e: String,
        field_f: Vec<String>,
    }

    impl MessageEncode for Data {}

    #[test]
    fn encoded_from_vec() {
        let data: Vec<String> = vec![
            "degree:{college:College of Engineering",
            "degree:{name:Bachelor of Science and Arts",
            "degree:{nested:{key:value",
            "degree:{testArray:[element",
            "degree:{testArray:[objectInArray:{one:",
            "degree:{testArray:[objectInArray:{two:",
            "degree:{type:",
            "familyName:Doe",
            "givenName:",
        ]
        .into_iter()
        .map(|el| el.to_string())
        .collect();
        let encoded: EncodedMessages = data.into();
        assert_eq!(vec![1, 2, 3, 4, 8], encoded.infered_idxs);
    }

    #[test]
    fn encode_demo() {
        let d = Data {
            // test a value that includes colons
            field_a: String::from("value a^&$:@:"),
            field_b: vec![String::from("vec element 1"), String::from("vec element 2")],
            field_c: SubStruct {
                field_d: String::from("value d"),
                // test parsing empty fields of both type
                field_e: String::from(""),
                field_f: vec![],
            },
        };
        // assuming CanonicalFlatten has worked as expected, test the parsing of the colon
        // concatenated field-value strings
        // Note, CanonicalFlatten will produce the following Strings:
        //   field_e -> "field_e:"
        //   field_f -> "field_f:[]"
        // and these must be correctly parsed as being empty

        let encoded_msgs = d.encode_demo();
        assert_eq!(
            encoded_msgs.to_vec(),
            vec![
                FieldElement::from_msg_hash("field_a:value a^&$:@:".as_bytes()),
                FieldElement::from_msg_hash(
                    "field_b:[\"vec element 1\", \"vec element 2\"]".as_bytes()
                ),
                FieldElement::from_msg_hash("field_d:value d".as_bytes()),
                FieldElement::zero(),
                FieldElement::zero()
            ]
        );

        // test the math indicies of included (unredacted) msgs are correctly infered
        assert_eq!(encoded_msgs.infered_idxs, vec![1, 2, 3]);
    }

    #[test]
    fn field_idx_map_demo() {
        let d = Data {
            // test a value that includes colons
            field_a: String::from("value a^&$:@:"),
            field_b: vec![String::from("vec element 1"), String::from("vec element 2")],
            field_c: SubStruct {
                field_d: String::from("value d"),
                // test parsing empty fields of both type
                field_e: String::from(""),
                field_f: vec![],
            },
        };
        let mut map_calc: HashMap<String, usize> = HashMap::new();
        map_calc.insert(String::from("field_a"), 1);
        map_calc.insert(String::from("field_b"), 2);
        map_calc.insert(String::from("field_d"), 3);
        map_calc.insert(String::from("field_e"), 4);
        map_calc.insert(String::from("field_f"), 5);

        assert_eq!(d.field_idx_map_demo(), map_calc);
    }
}
