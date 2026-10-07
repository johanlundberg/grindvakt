//! Framework-agnostic HTTP request/response types and an outbound client trait.
//!
//! Keeping these decoupled from actix lets the core and plugin crates be unit
//! tested without spinning up a server, and lets the OIDC library issue
//! outbound calls through an injected client.

use std::collections::BTreeMap;

/// A parsed inbound HTTP request, normalized for the proxy flow.
#[derive(Debug, Clone, Default)]
pub struct HttpRequestData {
    /// Request path with the leading slash stripped, e.g. `Saml2/acs/post`.
    pub path: String,
    /// HTTP method, uppercased.
    pub method: String,
    /// Full request URI (scheme://host/path?query) when available.
    pub uri: String,
    /// Ordered query-string parameters. Protocol parsers must consume this
    /// representation so duplicate names remain visible for rejection.
    pub query_pairs: Vec<(String, String)>,
    /// Convenience query map for non-protocol application lookups. Duplicate
    /// names have already been flattened; do not use it at a protocol boundary.
    pub query: BTreeMap<String, String>,
    /// Ordered form body parameters. Token endpoint handlers must consume this
    /// representation so duplicate names remain visible for rejection.
    pub form_pairs: Vec<(String, String)>,
    /// Convenience form map for non-protocol application lookups. Duplicate
    /// names have already been flattened; do not use it at a protocol boundary.
    pub form: BTreeMap<String, String>,
    /// Raw request body.
    pub body: Vec<u8>,
    /// Lower-cased header name -> value.
    pub headers: BTreeMap<String, String>,
    /// Parsed cookies: name -> value.
    pub cookies: BTreeMap<String, String>,
}

impl HttpRequestData {
    /// Look up a convenience parameter from the flattened query/form maps.
    /// Protocol handlers must instead pass `query_pairs` or `form_pairs` to
    /// their duplicate-rejecting entry points.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.query
            .get(key)
            .or_else(|| self.form.get(key))
            .map(|s| s.as_str())
    }

    /// The value of the `Authorization` header, if present.
    pub fn authorization(&self) -> Option<&str> {
        self.headers.get("authorization").map(|s| s.as_str())
    }

    /// Extract a Bearer token from the Authorization header.
    pub fn bearer_token(&self) -> Option<&str> {
        let auth = self.authorization()?;
        let (scheme, token) = auth.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("Bearer") {
            Some(token.trim())
        } else {
            None
        }
    }
}

/// A framework-agnostic HTTP response produced by a handler.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// 302 redirect to `location`.
    pub fn redirect(location: impl Into<String>) -> Self {
        Response::new(302).with_header("location", location)
    }

    /// A `text/html` response.
    pub fn html(body: impl Into<String>) -> Self {
        let body = body.into();
        Response::new(200)
            .with_header("content-type", "text/html; charset=utf-8")
            .with_body(body.into_bytes())
    }

    /// An `application/json` response from a serializable value.
    pub fn json<T: serde::Serialize>(value: &T) -> crate::error::Result<Self> {
        let body = serde_json::to_vec(value)?;
        Ok(Response::new(200)
            .with_header("content-type", "application/json")
            .with_body(body))
    }

    /// An `application/json` response with an explicit status.
    pub fn json_status<T: serde::Serialize>(status: u16, value: &T) -> crate::error::Result<Self> {
        let mut r = Response::json(value)?;
        r.status = status;
        Ok(r)
    }

    /// A plain-text response.
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Response::new(status)
            .with_header("content-type", "text/plain; charset=utf-8")
            .with_body(body.into().into_bytes())
    }
}

/// Trait for an outbound HTTP client, injected into the OIDC/federation logic so
/// the protocol library stays runtime-agnostic. Implemented in the binary with
/// `reqwest`.
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Issue a GET and return the body bytes (and status).
    async fn get(&self, url: &str) -> crate::error::Result<HttpFetchResponse>;

    /// Issue a form-encoded POST.
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> crate::error::Result<HttpFetchResponse>;
}

/// The result of an outbound fetch.
///
/// `HttpClient` implementations should fill in both `content_type` and
/// `headers`. Prefer [`HttpFetchResponse::new`] and
/// [`HttpFetchResponse::with_header`], or a struct literal ending in
/// `..Default::default()`, so new fields do not break the construction site.
/// `content_type` stays authoritative for existing readers such as
/// `federation::fetch_signed_jwks`; `headers` carries everything else
/// (for example `Cache-Control`).
#[derive(Debug, Clone, Default)]
pub struct HttpFetchResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    /// Response headers, names lower-cased, in order; repeated headers kept.
    pub headers: Vec<(String, String)>,
}

impl HttpFetchResponse {
    /// A response with a status and body and no headers.
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            ..Default::default()
        }
    }

    /// Append a header. The stored name is lower-cased. A `Content-Type`
    /// header also sets `content_type` when it is still unset.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into().to_ascii_lowercase();
        let value = value.into();
        if name == "content-type" && self.content_type.is_none() {
            self.content_type = Some(value.clone());
        }
        self.headers.push((name, value));
        self
    }

    /// The first header value with this name, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `Cache-Control` header value, if present.
    pub fn cache_control(&self) -> Option<&str> {
        self.header("cache-control")
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> crate::error::Result<T> {
        serde_json::from_slice(&self.body).map_err(crate::error::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lookup_is_case_insensitive_and_returns_first() {
        let r = HttpFetchResponse::new(200, "x")
            .with_header("X-Thing", "one")
            .with_header("x-thing", "two");
        assert_eq!(r.header("X-THING"), Some("one"));
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.header("missing"), None);
    }

    #[test]
    fn cache_control_reads_header() {
        let r = HttpFetchResponse::new(200, Vec::new()).with_header("Cache-Control", "max-age=60");
        assert_eq!(r.cache_control(), Some("max-age=60"));
        assert_eq!(HttpFetchResponse::default().cache_control(), None);
    }

    #[test]
    fn content_type_header_fills_content_type() {
        let r = HttpFetchResponse::new(200, Vec::new()).with_header("Content-Type", "text/plain");
        assert_eq!(r.content_type.as_deref(), Some("text/plain"));
        assert_eq!(r.headers[0].0, "content-type");
    }

    #[test]
    fn default_has_empty_headers() {
        let r = HttpFetchResponse::default();
        assert!(r.headers.is_empty());
        assert_eq!(r.status, 0);
    }
}
