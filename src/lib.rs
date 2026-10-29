use chrono::{DateTime, Duration, SecondsFormat};
use plugin_sdk::{
    EmailInput, FieldCandidate, RecordContribution, RecordIdentity, RecordResult, SemanticUpdate,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

plugin_sdk::export_plugin!(extract);

/// Conservative English numeric-code parser. Unsupported or ambiguous mail stays ordinary mail.
pub fn extract(input: EmailInput) -> RecordResult {
    let sources = input
        .invocation
        .as_ref()
        .map(|i| i.sources.clone())
        .unwrap_or_default();
    let mut result = RecordResult {
        refresh_requests: Vec::new(),
        schema_version: "1".into(),
        sources,
        records: vec![],
    };
    let Some(source) = input
        .message
        .source_id
        .as_ref()
        .filter(|id| result.sources.iter().any(|s| &s.id == *id))
    else {
        return result;
    };
    let Some(date) = input.date.as_deref().and_then(|d| {
        DateTime::parse_from_rfc3339(d)
            .ok()
            .or_else(|| DateTime::parse_from_rfc2822(d).ok())
    }) else {
        return result;
    };
    let date = date.to_utc();
    let observed = date.to_rfc3339_opts(SecondsFormat::Secs, true);
    // Scan bounded ASCII tokens beside explicit authentication labels. Compiling
    // general regular expressions inside each invocation exceeds the host fuel budget.
    let texts = [&input.subject, input.text_body.as_deref().unwrap_or("")];
    let mut codes = BTreeSet::new();
    let mut durations = BTreeSet::new();
    for text in texts {
        let lower = text.to_ascii_lowercase();
        let tokens: Vec<_> = lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|s| !s.is_empty())
            .collect();
        for (index, token) in tokens.iter().enumerate() {
            if (4..=8).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_digit()) {
                let end = if index > 0 && tokens[index - 1] == "is" {
                    index - 1
                } else {
                    index
                };
                let prefix = &tokens[..end];
                if ["verification", "security", "login", "authentication", "use"]
                    .iter()
                    .any(|label| prefix.ends_with(&[label, "code"]))
                    || prefix.ends_with(&["sign", "in", "code"])
                    || prefix.ends_with(&["one", "time", "code"])
                {
                    codes.insert((*token).to_owned());
                }
            }
        }
        for parts in tokens.windows(4) {
            if ["expires", "expire", "valid"].contains(&parts[0])
                && ["in", "for"].contains(&parts[1])
                && ["minute", "minutes"].contains(&parts[3])
            {
                // Oversized or malformed durations also fail closed.
                durations.insert(parts[2].parse::<i64>().unwrap_or(-1));
            }
        }
    }
    if codes.len() != 1 {
        return result;
    }
    let code = codes.into_iter().next().unwrap();
    // Conflicting expiration statements cannot authorize Copy.
    if durations.len() > 1 {
        return result;
    }
    let expires = durations
        .first()
        .filter(|m| **m > 0 && **m <= 120)
        .map(|m| (date + Duration::minutes(*m)).to_rfc3339_opts(SecondsFormat::Secs, true));
    if !durations.is_empty() && expires.is_none() {
        return result;
    }
    let issuer = input.sender.domain.to_lowercase();
    if issuer.is_empty() {
        return result;
    }
    // Source UID/message ID never participates. Reprocessing and duplicate deliveries converge.
    // The issuance timestamp prevents a later challenge that reuses a code from colliding.
    let key = format!(
        "{:x}",
        Sha256::digest(format!("{issuer}\n{code}\n{observed}").as_bytes())
    );
    let mut fields = BTreeMap::new();
    for (name, value) in [
        ("code", json!(code)),
        ("issuer", json!(issuer)),
        ("issuedAt", json!(observed)),
    ] {
        fields.insert(
            name.into(),
            FieldCandidate {
                value,
                evidence: vec![source.clone()],
                basis: "extracted".into(),
                confidence: 1.0,
                observed_at: observed.clone(),
                revision: None,
            },
        );
    }
    if let Some(expiry) = expires {
        fields.insert(
            "expiresAt".into(),
            FieldCandidate {
                value: json!(expiry),
                evidence: vec![source.clone()],
                basis: "extracted".into(),
                confidence: 1.0,
                observed_at: observed.clone(),
                revision: None,
            },
        );
    }
    result.records.push(RecordContribution {
        identity: RecordIdentity { namespace: "verification-code".into(), key },
        record_type: "verification-code".into(),
        updates: vec![SemanticUpdate { key: "issued".into(), occurred_at: observed, summary: "Verification code received".into(), notify: true, evidence: vec![source.clone()], fields: fields.keys().cloned().collect(), supersedes: None }],
        fields, attention: vec![], links: vec![],
        presentation: json!({"family":"verification-code","version":1,"title":format!("{issuer} verification code")}),
        lifecycle: json!({"state":"active"}),
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(subject: &str, body: &str) -> EmailInput {
        let mut v: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/email-input.json")).unwrap();
        v["subject"] = json!(subject);
        v["textBody"] = json!(body);
        serde_json::from_value(v).unwrap()
    }
    #[test]
    fn rejects_unrelated_missing_ambiguous_and_invalid_dates() {
        for (subject, body) in [
            ("Order 123456", "Your order code is 123456"),
            ("Verification code", "Call 1234567890"),
            ("Security code 123456", "Use code 654321"),
            ("Security code 123456", "Expires in 0 minutes"),
        ] {
            assert!(extract(input(subject, body)).records.is_empty());
        }
        let mut i = input("Security code 123456", "");
        i.date = None;
        assert!(extract(i).records.is_empty());
    }
    #[test]
    fn identity_ignores_delivery_location_but_not_new_challenges() {
        let i = input("Security code 012345", "Expires in 10 minutes");
        let first = extract(i.clone());
        let mut duplicate = i.clone();
        duplicate.message.uid += 1;
        duplicate.message.message_id = "different".into();
        assert_eq!(
            first.records[0].identity,
            extract(duplicate).records[0].identity
        );
        let mut later = i;
        later.date = Some("2026-07-02T12:10:00Z".into());
        assert_ne!(
            first.records[0].identity,
            extract(later).records[0].identity
        );
        assert_eq!(first.records[0].fields["code"].value, "012345");
        assert!(!first.records[0].identity.key.contains("012345"));
        assert_eq!(
            first.records[0].fields["expiresAt"].value,
            "2026-07-01T12:20:00Z"
        );
    }
}
