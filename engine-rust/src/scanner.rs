use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub mod sanitizer;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionRequest {
    pub id: String,
    pub method: String,
    pub host: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionResponse {
    pub id: String,
    pub category: String,
    pub risk_level: String,
    pub findings: Vec<Finding>,
    pub sanitized_body: String,
}

pub fn inspect(request: &InspectionRequest) -> InspectionResponse {
    let category = classify(&request.host, &request.body);
    let (sanitized_body, findings) = sanitizer::sanitize_body(&request.body);
    let risk_level = if findings.is_empty() { "LOW" } else { "HIGH" };

    InspectionResponse {
        id: request.id.clone(),
        category,
        risk_level: risk_level.to_owned(),
        findings,
        sanitized_body,
    }
}

fn classify(host: &str, body: &str) -> String {
    let host = host.to_ascii_lowercase();
    let is_llm_host = host == "api.anthropic.com"
        || host == "api.openai.com"
        || host.ends_with(".api.anthropic.com")
        || host.ends_with(".api.openai.com");
    let json = serde_json::from_str::<Value>(body).ok();
    let has_prompt_key = json.as_ref().is_some_and(contains_prompt_key);

    if is_llm_host || has_prompt_key {
        "LLM_PROMPT".to_owned()
    } else if ["stripe", "paypal", "payment"]
        .iter()
        .any(|needle| host.contains(needle))
    {
        "PAYMENT_API".to_owned()
    } else if json.is_some() {
        "GENERIC_JSON".to_owned()
    } else {
        "UNKNOWN".to_owned()
    }
}

fn contains_prompt_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(key.to_ascii_lowercase().as_str(), "messages" | "prompt")
                || contains_prompt_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_prompt_key),
        _ => false,
    }
}

pub fn shannon_entropy(value: &str) -> f64 {
    let characters: Vec<char> = value.chars().collect();
    if characters.is_empty() {
        return 0.0;
    }

    let mut frequencies = HashMap::new();
    for character in &characters {
        *frequencies.entry(character).or_insert(0usize) += 1;
    }

    let length = characters.len() as f64;
    frequencies
        .values()
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::{inspect, shannon_entropy, InspectionRequest};

    fn request(host: &str, body: &str) -> InspectionRequest {
        InspectionRequest {
            id: "test-1".to_owned(),
            method: "POST".to_owned(),
            host: host.to_owned(),
            body: body.to_owned(),
        }
    }

    #[test]
    fn classifies_llm_hosts_and_prompt_keys() {
        assert_eq!(
            inspect(&request("api.openai.com", "{}")).category,
            "LLM_PROMPT"
        );
        assert_eq!(
            inspect(&request("example.com", r#"{"input":{"messages":[]}}"#)).category,
            "LLM_PROMPT"
        );
        assert_eq!(
            inspect(&request("example.com", r#"{"prompt":"hello"}"#)).category,
            "LLM_PROMPT"
        );
    }

    #[test]
    fn classifies_payment_and_generic_json() {
        assert_eq!(
            inspect(&request("api.stripe.com", "{}")).category,
            "PAYMENT_API"
        );
        assert_eq!(
            inspect(&request("example.com", r#"{"status":"ok"}"#)).category,
            "GENERIC_JSON"
        );
    }

    #[test]
    fn entropy_is_shannon_entropy_in_bits_per_character() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 0.0001);
    }

    #[test]
    fn detects_each_secret_rule() {
        let body = r#"{"a":"sk-ant-api03-abcdefghijklmnopqrstuvwx","b":"sk-proj-abcdefghijklmnopqrstuvwx","c":"sk-abcdefghijklmnopqrstuvwxyz123456","d":"AKIA1234567890ABCDEF","e":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature","f":"postgres://alice:secret@db.example.com/app"}"#;
        let result = inspect(&request("example.com", body));
        let kinds: Vec<&str> = result
            .findings
            .iter()
            .map(|finding| finding.kind.as_str())
            .collect();

        assert!(kinds.contains(&"ANTHROPIC_KEY"));
        assert!(kinds.contains(&"OPENAI_KEY"));
        assert!(kinds.contains(&"AWS_ACCESS_KEY"));
        assert!(kinds.contains(&"BEARER_JWT"));
        assert!(kinds.contains(&"DATABASE_URL_CREDENTIALS"));
    }

    #[test]
    fn detects_high_entropy_values_but_not_ordinary_long_urls() {
        let random_value = "aB3dE5fG7hJ9kL2mN4pQ6rT8";
        let body = format!(
            r#"{{"secret":"{random_value}","url":"https://example.com/articles/a-very-long-human-readable-path/with-normal-words"}}"#
        );
        let result = inspect(&request("example.com", &body));

        assert_eq!(
            result
                .findings
                .iter()
                .filter(|finding| finding.kind == "HIGH_ENTROPY")
                .count(),
            1
        );
        assert!(result.sanitized_body.contains(
            "https://example.com/articles/a-very-long-human-readable-path/with-normal-words"
        ));
    }
}
