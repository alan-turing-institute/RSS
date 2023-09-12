use amcl_wrapper::field_elem::FieldElement;
use canonical_flatten::CanonicalFlatten;
use std::collections::HashMap;
use std::error::Error;
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
pub enum RedactError {
    InvalidSequenceElement(String),
    MissingKeyInSourceSequence,
}

pub fn redact(source: Vec<String>, idxs: Vec<usize>) -> Result<Vec<String>, RedactError> {
    source
        .iter()
        .enumerate()
        .map(|(i, m)| {
            // redact using math indexing
            if !idxs.contains(&(i + 1)) {
                let mut m_vec = m.split(":").collect::<Vec<&str>>();
                // special case if redacting metadata field (key-value seperates on first colon)
                if m_vec
                    .first()
                    .ok_or(RedactError::InvalidSequenceElement(m.to_owned()))?
                    == &"metadata"
                {
                    return Ok("metadata:".to_string());
                }
                // redact value from key value pair
                let tail = m_vec
                    .pop()
                    .ok_or(RedactError::InvalidSequenceElement(m.to_owned()))?;
                let mut rejoined = m_vec.join(":") + ":";
                // in the case that this index was an element in an array
                if tail
                    .chars()
                    .next()
                    .ok_or(RedactError::MissingKeyInSourceSequence)?
                    == '['
                {
                    // include array tag in the key after value has been redacted
                    rejoined += "["
                }
                Ok(rejoined)
            } else {
                Ok(m.to_owned())
            }
        })
        .collect::<Result<Vec<String>, RedactError>>()
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
    fn test_redact() {
        let data: Vec<String> = vec![
            "degree:{college:College of Engineering",
            "degree:{name:Bachelor of Science and Arts",
            "degree:{nested:{key:value",
            "degree:{testArray:[element",
            "degree:{testArray:[objectInArray:{one:valTwo",
            "degree:{testArray:[objectInArray:{two:valOne",
            "degree:{type:Degree Certificate",
            "familyName:Doe",
            "givenName:Jane",
            "metadata:Remove:After:First:Colon",
        ]
        .into_iter()
        .map(|el| el.to_string())
        .collect();
        assert_eq!(
            redact(data, vec![1, 2, 4, 6]).unwrap(),
            vec![
                "degree:{college:College of Engineering",
                "degree:{name:Bachelor of Science and Arts",
                "degree:{nested:{key:",
                "degree:{testArray:[element",
                "degree:{testArray:[objectInArray:{one:",
                "degree:{testArray:[objectInArray:{two:valOne",
                "degree:{type:",
                "familyName:",
                "givenName:",
                "metadata:"
            ]
        )
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
