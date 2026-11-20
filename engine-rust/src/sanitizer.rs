use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

use super::{shannon_entropy, Finding};

static ANTHROPIC_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{8,}").expect("valid Anthropic key regex"));
static OPENAI_PROJECT_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk-proj-[A-Za-z0-9_-]{16,}").expect("valid OpenAI project key regex")
});
static OPENAI_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9]{24,}").expect("valid OpenAI key regex"));
static AWS_ACCESS_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid AWS access key regex"));
static BEARER_JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
        .expect("valid bearer JWT regex")
});
static DATABASE_URL_CREDENTIALS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)postgres(?:ql)?://[^/:@\s]+:[^/@\s]+@")
        .expect("valid database URL credential regex")
});
static URL_SCHEME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://").expect("valid URL scheme regex"));

const SECRET_PATTERNS: [(&Lazy<Regex>, &str, &str); 6] = [
    (&ANTHROPIC_KEY, "ANTHROPIC_KEY", "[REDACTED_ANTHROPIC_KEY]"),
    (&OPENAI_PROJECT_KEY, "OPENAI_KEY", "[REDACTED_OPENAI_KEY]"),
    (&OPENAI_KEY, "OPENAI_KEY", "[REDACTED_OPENAI_KEY]"),
    (
        &AWS_ACCESS_KEY,
        "AWS_ACCESS_KEY",
        "[REDACTED_AWS_ACCESS_KEY]",
    ),
    (&BEARER_JWT, "BEARER_JWT", "[REDACTED_BEARER_JWT]"),
    (
        &DATABASE_URL_CREDENTIALS,
        "DATABASE_URL_CREDENTIALS",
        "[REDACTED_DATABASE_URL_CREDENTIALS]",
    ),
];

pub(crate) fn sanitize_body(body: &str) -> (String, Vec<Finding>) {
    match serde_json::from_str::<Value>(body) {
        Ok(mut value) => {
            let mut findings = Vec::new();
            sanitize_value(&mut value, "$", &mut findings);
            let sanitized = serde_json::to_string(&value).unwrap_or_else(|_| body.to_owned());
            (sanitized, findings)
        }
        Err(_) => {
            let mut findings = Vec::new();
            let sanitized = sanitize_string(body, "$", &mut findings);
            (sanitized, findings)
        }
    }
}

fn sanitize_value(value: &mut Value, path: &str, findings: &mut Vec<Finding>) {
    match value {
        Value::String(text) => *text = sanitize_string(text, path, findings),
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                sanitize_value(value, &format!("{path}[{index}]"), findings);
            }
        }
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                sanitize_value(value, &format!("{path}.{key}"), findings);
            }
        }
        _ => {}
    }
}

fn sanitize_string(value: &str, path: &str, findings: &mut Vec<Finding>) -> String {
    let mut matches = Vec::new();
    for (regex, kind, replacement) in SECRET_PATTERNS {
        for matched in regex.find_iter(value) {
            matches.push((matched.start(), matched.end(), kind, replacement));
        }
    }
    matches.sort_by_key(|matched| matched.0);

    if matches.is_empty() && value.chars().count() > 20 && !URL_SCHEME.is_match(value) {
        if shannon_entropy(value) > 4.5 {
            add_finding(findings, "HIGH_ENTROPY", path);
            return "[REDACTED_HIGH_ENTROPY]".to_owned();
        }
        return value.to_owned();
    }

    let mut sanitized = String::with_capacity(value.len());
    let mut cursor = 0;
    for (start, end, kind, replacement) in matches {
        if start < cursor {
            continue;
        }
        sanitized.push_str(&value[cursor..start]);
        sanitized.push_str(replacement);
        cursor = end;
        add_finding(findings, kind, path);
    }
    sanitized.push_str(&value[cursor..]);
    sanitized
}

fn add_finding(findings: &mut Vec<Finding>, kind: &str, path: &str) {
    if !findings
        .iter()
        .any(|finding| finding.kind == kind && finding.path == path)
    {
        findings.push(Finding {
            kind: kind.to_owned(),
            path: path.to_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_body;
    use serde_json::Value;

    #[test]
    fn redacts_secrets_and_keeps_nested_json_intact() {
        let input = r#"{"nested":{"key":"AKIA1234567890ABCDEF","safe":42},"text":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature"}"#;
        let (sanitized, findings) = sanitize_body(input);
        let parsed: Value = serde_json::from_str(&sanitized).expect("sanitized JSON stays valid");

        assert_eq!(parsed["nested"]["key"], "[REDACTED_AWS_ACCESS_KEY]");
        assert_eq!(parsed["nested"]["safe"], 42);
        assert_eq!(parsed["text"], "[REDACTED_BEARER_JWT]");
        assert!(findings
            .iter()
            .any(|finding| finding.path == "$.nested.key"));
    }

    #[test]
    fn redacts_database_credentials_without_removing_host() {
        let (sanitized, findings) =
            sanitize_body(r#"{"url":"postgres://alice:secret@db.example.com/app"}"#);

        assert!(sanitized.contains("[REDACTED_DATABASE_URL_CREDENTIALS]db.example.com/app"));
        assert!(findings
            .iter()
            .any(|finding| finding.kind == "DATABASE_URL_CREDENTIALS"));
    }

    #[test]
    fn redacts_plain_text_bodies_too() {
        let (sanitized, findings) =
            sanitize_body("credential=sk-ant-api03-abcdefghijklmnopqrstuvwx");

        assert!(sanitized.contains("[REDACTED_ANTHROPIC_KEY]"));
        assert_eq!(findings.len(), 1);
    }
}
