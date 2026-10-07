//! Error types for the tunnelbana core framework.

use thiserror::Error;

/// The result type used throughout the proxy.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type. Carries enough structure to be mapped onto an HTTP
/// response by the binary layer (see [`Error::status_hint`]).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// No registered endpoint matched the request path.
    #[error("no endpoint bound to path: {0}")]
    NoBoundEndpoint(String),

    /// A referenced frontend/backend/microservice name does not exist.
    #[error("unknown module: {0}")]
    UnknownModule(String),

    /// The request was malformed (missing params, bad encoding, etc.).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Authentication failed somewhere in the flow.
    #[error("authentication error: {0}")]
    Authn(String),

    /// State cookie could not be sealed/unsealed.
    #[error("state error: {0}")]
    State(String),

    /// Configuration is invalid or could not be loaded.
    #[error("configuration error: {0}")]
    Config(String),

    /// Cryptographic / key-material failure.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Attribute mapping failure.
    #[error("attribute mapping error: {0}")]
    Attribute(String),

    /// Wrapper around the JOSE library errors.
    #[error("jose error: {0}")]
    Jose(#[from] jose_rs::JoseError),

    /// JSON (de)serialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Any other internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// An upstream HTTP exchange (token, UserInfo, JWKS, discovery) failed.
    #[error("{0}")]
    UpstreamHttp(Box<UpstreamHttpError>),
}

/// Details of a failed upstream HTTP exchange.
///
/// All text fields are sanitized: control and bidirectional-format characters
/// are escaped (for example `\u{1b}`) and lengths are capped, so the values
/// cannot inject terminal or log escapes.
///
/// Sanitizing does not make [`UpstreamHttpError::body`] safe to log verbatim:
/// upstream error bodies can echo submitted values (codes, `state`, PKCE
/// verifiers) or carry personal data. The `Debug` implementation therefore
/// redacts the body and prints only its length; do not copy `body` into logs
/// or into any HTTP, JSON or other serialized error surface.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpstreamHttpError {
    /// HTTP status code of the upstream response.
    pub status: Option<u16>,
    /// OAuth `error` code, from the JSON body or `WWW-Authenticate` header.
    pub error: Option<String>,
    /// OAuth `error_description`, from the JSON body or `WWW-Authenticate`.
    pub error_description: Option<String>,
    /// Response body, escaped and length capped. May contain echoed secrets or
    /// personal data: never log it verbatim or return it to end users.
    pub body: Option<String>,
    message: String,
    auth_failure: bool,
}

impl UpstreamHttpError {
    pub(crate) fn new(
        status: Option<u16>,
        error: Option<String>,
        error_description: Option<String>,
        body: Option<String>,
        message: String,
        auth_failure: bool,
    ) -> Self {
        Self {
            status,
            error,
            error_description,
            body,
            message,
            auth_failure,
        }
    }

    /// Whether the failed exchange was an authentication step (token or
    /// UserInfo request) as opposed to metadata retrieval (discovery, JWKS).
    /// Before 0.9 such failures were reported as [`Error::Authn`].
    pub fn is_auth_failure(&self) -> bool {
        self.auth_failure
    }

    /// The human-readable message (also the `Display` text).
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Debug for UpstreamHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let body = self
            .body
            .as_ref()
            .map(|b| format!("<redacted, {} chars>", b.chars().count()));
        f.debug_struct("UpstreamHttpError")
            .field("status", &self.status)
            .field("error", &self.error)
            .field("error_description", &self.error_description)
            .field("body", &body)
            .field("message", &self.message)
            .field("auth_failure", &self.auth_failure)
            .finish()
    }
}

impl std::fmt::Display for UpstreamHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub(crate) fn is_bidi_format(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Make an attacker-controlled value safe to interpolate into an error
/// message: escapes control and bidi formatting characters and caps length.
pub(crate) fn display_safe(s: &str) -> String {
    escape_upstream_text(s, 256)
}

/// Escape control and bidi/format characters in untrusted upstream text and
/// cap the output at `max_chars` characters (appending `…` when truncated).
pub(crate) fn escape_upstream_text(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    for c in s.chars() {
        let piece: String = if c.is_control() || is_bidi_format(c) {
            c.escape_unicode().to_string()
        } else {
            c.to_string()
        };
        let n = piece.chars().count();
        if count + n > max_chars {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
        count += n;
    }
    out
}

/// Parse `error` and `error_description` out of a `WWW-Authenticate` header
/// value using the `Bearer` (or `DPoP`) scheme. Lenient; `None` on failure.
pub(crate) fn parse_www_authenticate_bearer(
    value: &str,
) -> Option<(Option<String>, Option<String>)> {
    let value = value.trim_start();
    let (scheme, rest) = value.split_once(|c: char| c.is_ascii_whitespace())?;
    if !scheme.eq_ignore_ascii_case("bearer") && !scheme.eq_ignore_ascii_case("dpop") {
        return None;
    }
    let mut chars = rest.chars().peekable();
    let mut error = None;
    let mut description = None;
    loop {
        while matches!(chars.peek(), Some(c) if c.is_ascii_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ',' || c.is_ascii_whitespace() {
                break;
            }
            name.push(c);
            chars.next();
        }
        while matches!(chars.peek(), Some(c) if c.is_ascii_whitespace()) {
            chars.next();
        }
        if chars.next() != Some('=') {
            return None;
        }
        while matches!(chars.peek(), Some(c) if c.is_ascii_whitespace()) {
            chars.next();
        }
        let mut val = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            let mut closed = false;
            while let Some(c) = chars.next() {
                match c {
                    '\\' => val.push(chars.next()?),
                    '"' => {
                        closed = true;
                        break;
                    }
                    _ => val.push(c),
                }
            }
            if !closed {
                return None;
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' || c.is_ascii_whitespace() {
                    break;
                }
                val.push(c);
                chars.next();
            }
        }
        match name.to_ascii_lowercase().as_str() {
            "error" if error.is_none() => error = Some(val),
            "error_description" if description.is_none() => description = Some(val),
            _ => {}
        }
    }
    Some((error, description))
}

impl Error {
    /// The structured upstream HTTP failure details, if this is one.
    pub fn upstream_http(&self) -> Option<&UpstreamHttpError> {
        match self {
            Error::UpstreamHttp(e) => Some(e),
            _ => None,
        }
    }

    /// Suggested HTTP status code for surfacing this error to a client.
    /// Whether this error is an authentication failure: [`Error::Authn`], or an
    /// [`Error::UpstreamHttp`] from a token or UserInfo request (which 0.8
    /// reported as `Authn`). Prefer this to matching variant identity at
    /// re-authentication, session-teardown and alerting decision points.
    pub fn is_auth_failure(&self) -> bool {
        match self {
            Error::Authn(_) => true,
            Error::UpstreamHttp(e) => e.is_auth_failure(),
            _ => false,
        }
    }

    pub fn status_hint(&self) -> u16 {
        match self {
            Error::UpstreamHttp(_) => 502,
            Error::NoBoundEndpoint(_) => 404,
            Error::BadRequest(_) => 400,
            Error::UnknownModule(_) => 404,
            Error::Authn(_) => 401,
            Error::Config(_) | Error::Crypto(_) | Error::State(_) => 500,
            _ => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn upstream_http_error_debug_redacts_body() {
        let e = super::UpstreamHttpError::new(
            Some(400),
            Some("invalid_grant".into()),
            None,
            Some("code=SECRET-CODE verifier=SECRET".into()),
            "authentication error: token endpoint returned 400".into(),
            true,
        );
        let dbg = format!(
            "{e:?} {:?}",
            super::Error::UpstreamHttp(Box::new(e.clone()))
        );
        assert!(!dbg.contains("SECRET"), "{dbg}");
        assert!(dbg.contains("redacted"), "{dbg}");
        assert!(dbg.contains("invalid_grant"));
        // The body stays available to callers that ask for it.
        assert!(e.body.as_deref().unwrap().contains("SECRET-CODE"));
    }

    use super::*;

    #[test]
    fn escape_controls_and_bidi() {
        assert_eq!(escape_upstream_text("a\x1bb", 64), "a\\u{1b}b");
        assert_eq!(escape_upstream_text("x\u{202E}y", 64), "x\\u{202e}y");
        assert_eq!(escape_upstream_text("åäö", 64), "åäö");
    }

    #[test]
    fn escape_truncates_without_splitting_escape() {
        // "\u{1b}" is 6 chars; with a cap of 5 after "ab" it must not split.
        let out = escape_upstream_text("ab\x1bcd", 5);
        assert_eq!(out, "ab…");
        assert_eq!(escape_upstream_text("abcdef", 3), "abc…");
        assert_eq!(escape_upstream_text("abc", 3), "abc");
    }

    #[test]
    fn parse_bearer_basic_and_escapes() {
        let p = parse_www_authenticate_bearer(
            r#"Bearer realm="x", error="invalid_token", error_description="say \"hi\" \\ ok""#,
        )
        .unwrap();
        assert_eq!(p.0.as_deref(), Some("invalid_token"));
        assert_eq!(p.1.as_deref(), Some(r#"say "hi" \ ok"#));
        let p = parse_www_authenticate_bearer(r#"DPoP error="use_dpop_nonce""#).unwrap();
        assert_eq!(p.0.as_deref(), Some("use_dpop_nonce"));
        assert_eq!(p.1, None);
        let p = parse_www_authenticate_bearer("Bearer error=invalid_request").unwrap();
        assert_eq!(p.0.as_deref(), Some("invalid_request"));
    }

    #[test]
    fn parse_bearer_malformed_is_none() {
        assert!(parse_www_authenticate_bearer("").is_none());
        assert!(parse_www_authenticate_bearer("Basic realm=\"x\"").is_none());
        assert!(parse_www_authenticate_bearer("Bearer").is_none());
        assert!(parse_www_authenticate_bearer("Bearer error=\"unterminated").is_none());
        assert!(parse_www_authenticate_bearer("Bearer garbage").is_none());
        assert!(parse_www_authenticate_bearer("Bearer error=\"a\\").is_none());
    }
}
