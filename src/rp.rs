//! The relying-party (client) side of OIDC/OAuth2 — used by the OIDC backend.
//!
//! Runtime-agnostic: outbound HTTP goes through the injected
//! [`crate::HttpClient`].

use crate::error::{
    display_safe, escape_upstream_text, is_bidi_format, parse_www_authenticate_bearer, Error,
    Result, UpstreamHttpError,
};
use crate::http::{HttpClient, HttpFetchResponse};
use crate::jwt;
use crate::keys::SigningKey;
use crate::metadata::ProviderMetadata;
use crate::oauth_error::urlencode;
use crate::provider::CLIENT_ASSERTION_TYPE;
use crate::util::now_secs;
use jose_rs::algorithm::JwsAlgorithm;
use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Audience, Claims, Validation};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Minimal upstream provider info the RP needs.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
}

impl From<ProviderMetadata> for ProviderInfo {
    fn from(m: ProviderMetadata) -> Self {
        Self {
            issuer: m.issuer,
            authorization_endpoint: m.authorization_endpoint,
            token_endpoint: m.token_endpoint,
            userinfo_endpoint: m.userinfo_endpoint,
            jwks_uri: Some(m.jwks_uri),
        }
    }
}

impl ProviderInfo {
    /// The advertised `userinfo_endpoint`, or `Error::Config` when the
    /// provider does not advertise one (it is optional in OIDC Discovery).
    pub fn require_userinfo_endpoint(&self) -> Result<&str> {
        self.userinfo_endpoint
            .as_deref()
            .ok_or_else(|| Error::Config("provider does not advertise a userinfo_endpoint".into()))
    }

    /// The advertised `jwks_uri`, or `Error::Config` when the provider does
    /// not advertise one.
    pub fn require_jwks_uri(&self) -> Result<&str> {
        self.jwks_uri
            .as_deref()
            .ok_or_else(|| Error::Config("provider does not advertise a jwks_uri".into()))
    }

    /// Validate every endpoint before it can receive requests or credentials.
    pub fn validate(&self) -> Result<()> {
        validate_issuer(&self.issuer)?;
        validate_service_endpoint_for_issuer(
            "authorization_endpoint",
            &self.authorization_endpoint,
            &self.issuer,
        )?;
        validate_authorization_endpoint_query(&self.authorization_endpoint)?;
        validate_service_endpoint_for_issuer("token_endpoint", &self.token_endpoint, &self.issuer)?;
        if let Some(endpoint) = self.userinfo_endpoint.as_deref() {
            validate_service_endpoint_for_issuer("userinfo_endpoint", endpoint, &self.issuer)?;
        }
        if let Some(endpoint) = self.jwks_uri.as_deref() {
            validate_service_endpoint_for_issuer("jwks_uri", endpoint, &self.issuer)?;
        }
        Ok(())
    }
}

/// How the RP authenticates to the upstream token endpoint.
#[derive(Clone)]
pub enum ClientAuth {
    None,
    ClientSecretBasic(String),
    ClientSecretPost(String),
    /// `private_key_jwt` using the given signing key.
    PrivateKeyJwt(SigningKey),
}

/// RP client configuration.
#[derive(Clone)]
pub struct RpClient {
    pub client_id: String,
    pub redirect_uri: String,
    pub auth: ClientAuth,
    pub scope: String,
}

/// The result of a successful token exchange.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub id_token: String,
    pub token_type: String,
    pub raw: serde_json::Value,
}

/// Build the authorization request URL (redirect the user here).
pub fn authorization_url(
    provider: &ProviderInfo,
    client: &RpClient,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    extra: &[(&str, &str)],
) -> Result<String> {
    provider.validate()?;
    validate_redirect_uri(&client.redirect_uri)?;
    if !client
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
    {
        return Err(Error::BadRequest(
            "OIDC authorization requests require the openid scope".into(),
        ));
    }
    if matches!(&client.auth, ClientAuth::None) && code_challenge.is_none() {
        return Err(Error::BadRequest(
            "public clients must use S256 PKCE".into(),
        ));
    }
    if let Some(challenge) = code_challenge {
        if !crate::pkce::is_valid_s256_challenge(challenge) {
            return Err(Error::BadRequest("invalid S256 code_challenge".into()));
        }
    }
    validate_authorization_extras(&provider.authorization_endpoint, extra)?;
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", client.client_id.as_str()),
        ("redirect_uri", client.redirect_uri.as_str()),
        ("scope", client.scope.as_str()),
        ("state", state),
        ("nonce", nonce),
    ];
    if let Some(cc) = code_challenge {
        params.push(("code_challenge", cc));
        params.push(("code_challenge_method", "S256"));
    }
    params.extend_from_slice(extra);

    let qs: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let sep = if provider.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    Ok(format!("{}{}{}", provider.authorization_endpoint, sep, qs))
}

fn validate_authorization_extras(endpoint: &str, extra: &[(&str, &str)]) -> Result<()> {
    const RESERVED: &[&str] = &[
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ];
    // Seed the set from configured endpoint parameters so an application
    // cannot accidentally append a second, conflicting vendor parameter.
    let parsed = url::Url::parse(endpoint)
        .map_err(|e| Error::BadRequest(format!("invalid authorization_endpoint: {e}")))?;
    let mut seen = parsed
        .query_pairs()
        .filter(|(name, _)| name != "resource")
        .map(|(name, _)| name.into_owned())
        .collect::<BTreeSet<_>>();
    for (name, _) in extra {
        if RESERVED.contains(name) {
            return Err(Error::BadRequest(format!(
                "authorization extra parameter {} is library-controlled",
                display_safe(name)
            )));
        }
        // RFC 8707 permits repeated resource parameters. Other extension
        // parameters must remain unambiguous.
        if *name != "resource" && !seen.insert((*name).to_string()) {
            return Err(Error::BadRequest(format!(
                "duplicate authorization extra parameter: {}",
                display_safe(name)
            )));
        }
    }
    Ok(())
}

/// Build a signed request object (RFC 9101, "JAR") carrying the
/// authorization-request parameters as JWT claims.
///
/// OpenID Federation **automatic registration** needs this: a federation OP
/// authenticates the RP at the authorization endpoint by verifying the
/// request object against the keys published in the RP's resolved
/// `openid_relying_party` metadata, and implementations (e.g. the Shibboleth
/// OIDC OP plugin) use its presence as the trigger to resolve the RP's trust
/// chain on the fly. Pass the result as the `request` parameter — typically
/// via [`authorization_url`]'s `extra` — alongside the plain parameters so
/// OPs that ignore request objects keep working.
///
/// `key` must be (one of) the RP's published client keys; for a federation
/// RP that is the `private_key_jwt` key from its entity configuration.
#[allow(clippy::too_many_arguments)]
pub fn signed_request_object(
    provider: &ProviderInfo,
    client: &RpClient,
    key: &SigningKey,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
) -> Result<String> {
    provider.validate()?;
    validate_redirect_uri(&client.redirect_uri)?;
    if !client
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
    {
        return Err(Error::BadRequest(
            "OIDC authorization requests require the openid scope".into(),
        ));
    }
    if matches!(&client.auth, ClientAuth::None) && code_challenge.is_none() {
        return Err(Error::BadRequest(
            "public clients must use S256 PKCE".into(),
        ));
    }
    if let Some(challenge) = code_challenge {
        if !crate::pkce::is_valid_s256_challenge(challenge) {
            return Err(Error::BadRequest("invalid S256 code_challenge".into()));
        }
    }
    let now = now_secs();
    let mut c = Claims::default();
    c.iss = Some(client.client_id.clone());
    c.aud = Some(Audience::Single(provider.issuer.clone()));
    c.iat = Some(now);
    c.exp = Some(now + 300);
    c.jti = Some(crate::util::random_token(16));
    let extra = &mut c.extra;
    extra.insert("client_id".into(), client.client_id.clone().into());
    extra.insert("redirect_uri".into(), client.redirect_uri.clone().into());
    extra.insert("scope".into(), client.scope.clone().into());
    extra.insert("response_type".into(), "code".into());
    extra.insert("state".into(), state.into());
    extra.insert("nonce".into(), nonce.into());
    if let Some(cc) = code_challenge {
        extra.insert("code_challenge".into(), cc.into());
        extra.insert("code_challenge_method".into(), "S256".into());
    }
    jwt::sign(key, &c, None)
}

/// Discover provider metadata from an issuer.
///
/// The issuer URL must be https (plain http is only accepted for loopback
/// hosts, for local development), and per OIDC Discovery §4.3 the `issuer`
/// returned in the metadata MUST match the requested issuer exactly.
pub async fn discover(http: &Arc<dyn HttpClient>, issuer: &str) -> Result<ProviderMetadata> {
    let requested_issuer = issuer;
    validate_issuer(requested_issuer)?;
    let discovery_prefix = requested_issuer.trim_end_matches('/');
    let url = format!("{discovery_prefix}/.well-known/openid-configuration");
    let resp = http.get(&url).await?;
    if resp.status != 200 {
        return Err(upstream_error(
            format!(
                "internal error: discovery failed ({}) for {url}",
                resp.status
            ),
            &resp,
            false,
        ));
    }
    let metadata: ProviderMetadata = resp.json()?;
    if metadata.issuer != requested_issuer {
        return Err(Error::Authn(format!(
            "discovered issuer {} does not match requested issuer {}",
            display_safe(&metadata.issuer),
            display_safe(requested_issuer)
        )));
    }
    ProviderInfo::from(metadata.clone()).validate()?;
    Ok(metadata)
}

/// localhost / 127.0.0.1 / ::1 — the only hosts permitted over plain http.
/// `Url::host_str` serializes IPv6 hosts in bracketed form (`[::1]`), so the
/// brackets are stripped before parsing as an address.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn validate_endpoint(name: &str, endpoint: &str, allow_loopback_http: bool) -> Result<()> {
    // The URL parser discards some raw whitespace and control characters.
    // Reject them first because callers send or return the original string,
    // and validation must describe the same bytes that reach the sink.
    if endpoint.chars().any(|character| {
        character.is_whitespace() || character.is_control() || is_bidi_format(character)
    }) {
        return Err(Error::BadRequest(format!(
            "{name} must not contain whitespace, control or bidi formatting characters"
        )));
    }
    let parsed = url::Url::parse(endpoint).map_err(|e| {
        Error::BadRequest(format!(
            "invalid {name} URL {}: {e}",
            display_safe(endpoint)
        ))
    })?;
    let scheme_ok = parsed.scheme() == "https"
        || (allow_loopback_http
            && parsed.scheme() == "http"
            && parsed.host_str().is_some_and(is_loopback_host));
    if !scheme_ok || parsed.host_str().is_none() {
        let policy = if allow_loopback_http {
            "an absolute https URL (http allowed only for loopback hosts)"
        } else {
            "an absolute https URL"
        };
        return Err(Error::BadRequest(format!(
            "{name} must be {policy}: {}",
            display_safe(endpoint)
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::BadRequest(format!(
            "{name} must not contain userinfo: {}",
            display_safe(endpoint)
        )));
    }
    if parsed.fragment().is_some() {
        return Err(Error::BadRequest(format!(
            "{name} must not contain a fragment: {}",
            display_safe(endpoint)
        )));
    }
    Ok(())
}

/// Require an absolute HTTPS endpoint.
///
/// This context-free validator deliberately does not permit loopback HTTP: a
/// metadata-derived endpoint can only use the development exception when its
/// associated issuer or entity identifier is also a loopback HTTP origin.
pub fn validate_service_endpoint(name: &str, endpoint: &str) -> Result<()> {
    validate_endpoint(name, endpoint, false)
}

fn issuer_allows_loopback_http(issuer: &str) -> bool {
    if issuer.chars().any(|character| {
        character.is_whitespace() || character.is_control() || is_bidi_format(character)
    }) {
        return false;
    }
    url::Url::parse(issuer).is_ok_and(|parsed| {
        parsed.scheme() == "http"
            && parsed.host_str().is_some_and(is_loopback_host)
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
    })
}

/// Validate a metadata endpoint relative to its authenticated issuer/entity.
///
/// The endpoint must be an `https` URL; loopback `http` is allowed only when
/// `issuer` itself is a loopback `http` origin. `name` is used in error
/// messages. This does not validate `issuer`; call [`validate_issuer`] first.
pub fn validate_service_endpoint_for_issuer(
    name: &str,
    endpoint: &str,
    issuer: &str,
) -> Result<()> {
    validate_endpoint(name, endpoint, issuer_allows_loopback_http(issuer))
}

fn validate_authorization_endpoint_query(endpoint: &str) -> Result<()> {
    const RESERVED: &[&str] = &[
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ];
    let parsed = url::Url::parse(endpoint)
        .map_err(|e| Error::BadRequest(format!("invalid authorization_endpoint: {e}")))?;
    let mut seen = BTreeSet::new();
    for (name, _) in parsed.query_pairs() {
        if RESERVED.contains(&name.as_ref()) {
            return Err(Error::BadRequest(format!(
                "authorization_endpoint query parameter {} is library-controlled",
                display_safe(&name)
            )));
        }
        if name != "resource" && !seen.insert(name.into_owned()) {
            return Err(Error::BadRequest(
                "authorization_endpoint contains duplicate query parameters".into(),
            ));
        }
    }
    Ok(())
}

/// Validate an issuer identifier.
///
/// It must be an absolute `https` URL (`http` is accepted only for loopback
/// hosts) with no whitespace or control characters, userinfo, query or
/// fragment.
pub fn validate_issuer(issuer: &str) -> Result<()> {
    validate_endpoint("issuer", issuer, true)?;
    let parsed = url::Url::parse(issuer).map_err(|e| {
        Error::BadRequest(format!("invalid issuer URL {}: {e}", display_safe(issuer)))
    })?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::BadRequest(
            "issuer URL must not contain a query or fragment".into(),
        ));
    }
    Ok(())
}

/// Validate a redirect URI.
///
/// This only checks that it parses as an absolute URL and carries no
/// fragment. The scheme is not checked, so custom/native-app schemes such as
/// `com.example.app:/cb` are accepted.
pub fn validate_redirect_uri(redirect_uri: &str) -> Result<()> {
    let parsed = url::Url::parse(redirect_uri).map_err(|e| {
        Error::BadRequest(format!(
            "invalid redirect_uri {}: {e}",
            display_safe(redirect_uri)
        ))
    })?;
    if parsed.fragment().is_some() {
        return Err(Error::BadRequest(
            "redirect_uri must not contain a fragment".into(),
        ));
    }
    Ok(())
}

/// Fetch a JWKS document for an associated issuer.
///
/// The issuer context is mandatory because the loopback HTTP development
/// exception applies only when the issuer itself is a loopback HTTP origin.
pub async fn fetch_jwks(
    http: &Arc<dyn HttpClient>,
    jwks_uri: &str,
    issuer: &str,
) -> Result<JwkSet> {
    validate_issuer(issuer)?;
    validate_service_endpoint_for_issuer("jwks_uri", jwks_uri, issuer)?;
    let resp = http.get(jwks_uri).await?;
    if resp.status != 200 {
        return Err(upstream_error(
            format!("internal error: jwks fetch failed ({})", resp.status),
            &resp,
            false,
        ));
    }
    JwkSet::from_json(&resp.text()).map_err(Error::from)
}

/// Exchange an authorization code for tokens.
pub async fn exchange_code(
    http: &Arc<dyn HttpClient>,
    provider: &ProviderInfo,
    client: &RpClient,
    code: &str,
    code_verifier: Option<&str>,
) -> Result<TokenSet> {
    provider.validate()?;
    validate_redirect_uri(&client.redirect_uri)?;
    if matches!(&client.auth, ClientAuth::None) && code_verifier.is_none() {
        return Err(Error::BadRequest(
            "public clients must supply a PKCE code_verifier".into(),
        ));
    }
    if let Some(verifier) = code_verifier {
        if !crate::pkce::is_valid_verifier(verifier) {
            return Err(Error::BadRequest("invalid PKCE code_verifier".into()));
        }
    }
    let mut form: Vec<(String, String)> = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.to_string()),
        ("redirect_uri".into(), client.redirect_uri.clone()),
        ("client_id".into(), client.client_id.clone()),
    ];
    if let Some(v) = code_verifier {
        form.push(("code_verifier".into(), v.to_string()));
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    apply_client_auth(client, provider, &mut form, &mut headers)?;

    let resp = http
        .post_form(&provider.token_endpoint, &form, &headers)
        .await?;
    if resp.status != 200 {
        return Err(upstream_error(
            format!(
                "authentication error: token endpoint returned {}: {}",
                resp.status,
                sanitize_error_body(&resp.text())
            ),
            &resp,
            true,
        ));
    }
    let raw: serde_json::Value = resp.json()?;
    let access_token = raw
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(String::from)
        .ok_or_else(|| Error::Authn("token response missing access_token".into()))?;
    let id_token = raw
        .get("id_token")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(String::from)
        .ok_or_else(|| Error::Authn("token response missing id_token".into()))?;
    let token_type = raw
        .get("token_type")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(String::from)
        .ok_or_else(|| Error::Authn("token response missing token_type".into()))?;
    // This RP currently sends access tokens using the Bearer scheme. RFC 6749
    // section 7.1 forbids using a token type the client does not understand.
    if !token_type.eq_ignore_ascii_case("Bearer") {
        return Err(Error::Authn(format!(
            "unsupported token_type in token response: {}",
            display_safe(&token_type)
        )));
    }
    Ok(TokenSet {
        access_token,
        id_token,
        token_type,
        raw,
    })
}

/// Verify an id_token against the provider JWKS, issuer, audience and nonce.
///
/// Uses jose-rs's default 60-second clock-skew leeway. See
/// [`verify_id_token_with`] to tune the leeway or to enforce `max_age`, `acr`
/// and `at_hash`.
pub fn verify_id_token(
    jwks: &JwkSet,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_nonce: Option<&str>,
    allowed_algorithms: &[JwsAlgorithm],
    trusted_additional_audiences: &[&str],
) -> Result<Claims> {
    verify_id_token_with(
        jwks,
        id_token,
        issuer,
        client_id,
        expected_nonce,
        allowed_algorithms,
        trusted_additional_audiences,
        &IdTokenOptions::default(),
    )
}

/// Mirrors jose-rs `Validation::default()`'s leeway (seconds); used for the
/// `auth_time` checks when [`IdTokenOptions::leeway`] is `None`.
const DEFAULT_LEEWAY: u64 = 60;

/// Largest accepted [`IdTokenOptions::leeway`] (seconds). Skew tolerance is
/// meant to absorb clock drift, not to revive expired id_tokens; larger values
/// are rejected as a configuration error.
pub const MAX_ID_TOKEN_LEEWAY: u64 = 300;

/// Extra id_token checks for [`verify_id_token_with`].
///
/// The struct is `#[non_exhaustive]`: construct it with [`IdTokenOptions::new`]
/// and the `with_*` builders.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct IdTokenOptions<'a> {
    /// Clock-skew tolerance (seconds) for exp/nbf/iat and the future-`auth_time`
    /// check. None = jose-rs default (60s). Values above
    /// [`MAX_ID_TOKEN_LEEWAY`] are rejected with `Error::BadRequest`. It is not
    /// added to `max_age`.
    pub leeway: Option<u64>,
    /// OIDC max_age: requires numeric `auth_time` with now <= auth_time + max_age.
    /// Clock-skew leeway is deliberately not added to the session age.
    pub max_age: Option<u64>,
    /// If set, `acr` must be present (string) and in this list. Empty list = configuration error (Error::BadRequest).
    pub acr_values: Option<&'a [&'a str]>,
    /// If set and the token has `at_hash`, it must equal oidc_token_hash(header alg, access_token).
    /// A token without `at_hash` is accepted unless `require_at_hash` is set.
    pub access_token: Option<&'a str>,
    /// Fail when the id_token has no `at_hash`. Requires `access_token`; without
    /// one the options are a configuration error (`Error::BadRequest`).
    pub require_at_hash: bool,
    /// If set and the token has `c_hash`, it must equal oidc_token_hash(header alg, code).
    /// A token without `c_hash` is accepted unless `require_c_hash` is set.
    pub authorization_code: Option<&'a str>,
    /// Fail when the id_token has no `c_hash`. Requires `authorization_code`;
    /// without one the options are a configuration error (`Error::BadRequest`).
    pub require_c_hash: bool,
}

impl<'a> IdTokenOptions<'a> {
    /// Options that add no checks beyond [`verify_id_token`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the clock-skew tolerance in seconds (at most [`MAX_ID_TOKEN_LEEWAY`]).
    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = Some(seconds);
        self
    }

    /// Require `auth_time` to be no older than `seconds` (plus leeway).
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Require `acr` to be one of `values`.
    pub fn with_acr_values(mut self, values: &'a [&'a str]) -> Self {
        self.acr_values = Some(values);
        self
    }

    /// Validate `at_hash` against this access token.
    ///
    /// This only checks `at_hash` when the id_token carries it, so an id_token
    /// without `at_hash` is **not** bound to the access token. Combine with
    /// [`IdTokenOptions::with_required_at_hash`] when the binding must hold, as
    /// for implicit and hybrid flows or any flow where the OP is known to emit it.
    pub fn with_access_token(mut self, access_token: &'a str) -> Self {
        self.access_token = Some(access_token);
        self
    }

    /// Reject id_tokens that carry no `at_hash`. Needs
    /// [`IdTokenOptions::with_access_token`].
    pub fn with_required_at_hash(mut self) -> Self {
        self.require_at_hash = true;
        self
    }

    /// Validate `c_hash` against this authorization code (OIDC Core §3.3.2.11).
    ///
    /// Like [`IdTokenOptions::with_access_token`], this only checks `c_hash`
    /// when the id_token carries it. Hybrid flows (`code id_token`,
    /// `code id_token token`) must also call
    /// [`IdTokenOptions::with_required_c_hash`] to bind the front-channel
    /// id_token to the delivered code.
    pub fn with_authorization_code(mut self, code: &'a str) -> Self {
        self.authorization_code = Some(code);
        self
    }

    /// Reject id_tokens that carry no `c_hash`. Needs
    /// [`IdTokenOptions::with_authorization_code`].
    pub fn with_required_c_hash(mut self) -> Self {
        self.require_c_hash = true;
        self
    }
}

/// Like [`verify_id_token`] with additional [`IdTokenOptions`].
///
/// The extra checks run after the `sub`, `aud`, `azp` and `nonce` checks.
/// `max_age` is checked against `auth_time` (not `iat`) and rejects tokens
/// without a numeric `auth_time`.
#[allow(clippy::too_many_arguments)]
pub fn verify_id_token_with(
    jwks: &JwkSet,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_nonce: Option<&str>,
    allowed_algorithms: &[JwsAlgorithm],
    trusted_additional_audiences: &[&str],
    options: &IdTokenOptions<'_>,
) -> Result<Claims> {
    if allowed_algorithms.is_empty() {
        return Err(Error::BadRequest(
            "at least one allowed id_token signing algorithm is required".into(),
        ));
    }
    if options.require_at_hash && options.access_token.is_none() {
        return Err(Error::BadRequest(
            "require_at_hash needs an access_token to check against".into(),
        ));
    }
    if options.require_c_hash && options.authorization_code.is_none() {
        return Err(Error::BadRequest(
            "require_c_hash needs an authorization_code to check against".into(),
        ));
    }
    if options.leeway.is_some_and(|l| l > MAX_ID_TOKEN_LEEWAY) {
        return Err(Error::BadRequest(format!(
            "id_token leeway must be at most {MAX_ID_TOKEN_LEEWAY} seconds"
        )));
    }
    if options.acr_values.is_some_and(<[&str]>::is_empty) {
        return Err(Error::BadRequest(
            "acr_values must not be empty when set".into(),
        ));
    }
    let mut validation = Validation::new()
        .with_issuer(issuer)
        .with_audience(client_id)
        .require_exp()
        .require_iat()
        .with_allowed_algorithms(allowed_algorithms.to_vec());
    if let Some(leeway) = options.leeway {
        validation = validation.with_leeway(leeway);
    }
    let claims = jwt::verify_with_jwks(jwks, id_token, &validation)?;

    if claims.sub.as_deref().is_none_or(str::is_empty) {
        return Err(Error::Authn("id_token missing sub".into()));
    }
    if let Some(Audience::Multiple(values)) = claims.aud.as_ref() {
        let mut seen = BTreeSet::new();
        for audience in values {
            if !seen.insert(audience) {
                return Err(Error::Authn("id_token contains duplicate audiences".into()));
            }
            if audience != client_id
                && !trusted_additional_audiences
                    .iter()
                    .any(|trusted| audience == trusted)
            {
                return Err(Error::Authn(format!(
                    "id_token contains untrusted audience: {}",
                    display_safe(audience)
                )));
            }
        }
        if values.len() > 1
            && claims.extra.get("azp").and_then(|value| value.as_str()) != Some(client_id)
        {
            return Err(Error::Authn(
                "multi-audience id_token requires azp equal to client_id".into(),
            ));
        }
    }
    if let Some(azp) = claims.extra.get("azp") {
        if azp.as_str() != Some(client_id) {
            return Err(Error::Authn("id_token azp mismatch".into()));
        }
    }

    if let Some(nonce) = expected_nonce {
        let got = claims.extra.get("nonce").and_then(|v| v.as_str());
        if got != Some(nonce) {
            return Err(Error::Authn("id_token nonce mismatch".into()));
        }
    }

    if let Some(max_age) = options.max_age {
        let leeway = options.leeway.unwrap_or(DEFAULT_LEEWAY);
        let auth_time = claims
            .extra
            .get("auth_time")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| Error::Authn("id_token missing auth_time required by max_age".into()))?;
        let now = now_secs();
        // Skew tolerance is not added to max_age: it is a session-age policy.
        if now > auth_time.saturating_add(max_age) {
            return Err(Error::Authn(
                "id_token auth_time is older than max_age".into(),
            ));
        }
        if auth_time > now.saturating_add(leeway) {
            return Err(Error::Authn("id_token auth_time is in the future".into()));
        }
    }

    if let Some(allowed) = options.acr_values {
        let acr = claims.extra.get("acr").and_then(|v| v.as_str());
        if !acr.is_some_and(|acr| allowed.contains(&acr)) {
            return Err(Error::Authn(
                "id_token acr missing or not in the accepted list".into(),
            ));
        }
    }

    check_token_hash(
        &claims,
        id_token,
        "at_hash",
        options.access_token,
        options.require_at_hash,
    )?;
    check_token_hash(
        &claims,
        id_token,
        "c_hash",
        options.authorization_code,
        options.require_c_hash,
    )?;
    Ok(claims)
}

/// Check an `at_hash` / `c_hash` claim against `value` using the hash for the
/// id_token's (already verified) JWS `alg`.
fn check_token_hash(
    claims: &Claims,
    id_token: &str,
    claim: &str,
    value: Option<&str>,
    required: bool,
) -> Result<()> {
    let present = claims.extra.get(claim);
    if required && present.is_none() {
        return Err(Error::Authn(format!("id_token missing {claim}")));
    }
    if let (Some(value), Some(present)) = (value, present) {
        let claimed = present
            .as_str()
            .ok_or_else(|| Error::Authn(format!("id_token {claim} is not a string")))?;
        let alg = JwsAlgorithm::from_str(&jwt::peek_header(id_token)?.alg)?;
        let expected = jwt::oidc_token_hash(alg, value)?;
        if !crate::mac::constant_time_eq(expected.as_bytes(), claimed.as_bytes()) {
            return Err(Error::Authn(format!("id_token {claim} mismatch")));
        }
    }
    Ok(())
}

/// How [`fetch_userinfo_response`] sends the UserInfo request (OIDC Core §5.3.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UserinfoMethod {
    /// `POST` with an empty form body (the default).
    #[default]
    Post,
    /// `GET`. Requires [`HttpClient::get_with_headers`].
    Get,
}

/// Fetch UserInfo with a Bearer access token and return the raw 200 response.
///
/// Validates the issuer and endpoint exactly as [`fetch_userinfo`] does, sends
/// the request with `method`, and returns the response unchanged. Use this for
/// signed `application/jwt` UserInfo: the caller verifies the JWS (and, per
/// OIDC Core §5.3.2, `iss` and `aud`) and must compare `sub` itself. For JSON
/// responses use [`userinfo_json_claims`]. Encrypted (JWE) responses are not
/// supported.
pub async fn fetch_userinfo_response(
    http: &Arc<dyn HttpClient>,
    userinfo_endpoint: &str,
    access_token: &str,
    issuer: &str,
    method: UserinfoMethod,
) -> Result<HttpFetchResponse> {
    validate_issuer(issuer)?;
    validate_service_endpoint_for_issuer("userinfo_endpoint", userinfo_endpoint, issuer)?;
    let headers = vec![(
        "authorization".to_string(),
        format!("Bearer {access_token}"),
    )];
    let resp = match method {
        UserinfoMethod::Post => http.post_form(userinfo_endpoint, &[], &headers).await?,
        UserinfoMethod::Get => http.get_with_headers(userinfo_endpoint, &headers).await?,
    };
    if resp.status != 200 {
        return Err(upstream_error(
            format!("authentication error: userinfo returned {}", resp.status),
            &resp,
            true,
        ));
    }
    Ok(resp)
}

/// Parse a JSON UserInfo response and bind it to the id_token subject.
///
/// Rejects `application/jwt` (signed UserInfo); verify those yourself using
/// [`fetch_userinfo_response`]. Other or missing content types are parsed as
/// JSON.
pub fn userinfo_json_claims(
    resp: &HttpFetchResponse,
    expected_sub: &str,
) -> Result<serde_json::Value> {
    let content_type = resp.content_type.as_deref().or(resp.header("content-type"));
    if let Some(ct) = content_type {
        let media_type = ct.split(';').next().unwrap_or("").trim();
        if media_type.eq_ignore_ascii_case("application/jwt") {
            return Err(Error::Authn(
                "userinfo is a signed JWT (application/jwt); use rp::fetch_userinfo_response and verify it yourself".into(),
            ));
        }
    }
    let claims: serde_json::Value = resp.json()?;
    if claims.get("sub").and_then(|value| value.as_str()) != Some(expected_sub) {
        return Err(Error::Authn(
            "userinfo sub does not match the validated id_token subject".into(),
        ));
    }
    Ok(claims)
}

/// Fetch UserInfo with a Bearer access token for an associated issuer.
///
/// The issuer context is mandatory because the loopback HTTP development
/// exception applies only when the issuer itself is a loopback HTTP origin.
/// Uses POST and expects a JSON response. For GET, or for signed
/// `application/jwt` UserInfo, use [`fetch_userinfo_response`] with
/// [`userinfo_json_claims`].
pub async fn fetch_userinfo(
    http: &Arc<dyn HttpClient>,
    userinfo_endpoint: &str,
    access_token: &str,
    expected_sub: &str,
    issuer: &str,
) -> Result<serde_json::Value> {
    let resp = fetch_userinfo_response(
        http,
        userinfo_endpoint,
        access_token,
        issuer,
        UserinfoMethod::Post,
    )
    .await?;
    userinfo_json_claims(&resp, expected_sub)
}

/// Build a `private_key_jwt` client assertion (RFC 7523) for token-endpoint auth.
pub fn build_client_assertion(key: &SigningKey, client_id: &str, audience: &str) -> Result<String> {
    let now = now_secs();
    let mut c = Claims::default();
    c.iss = Some(client_id.to_string());
    c.sub = Some(client_id.to_string());
    c.aud = Some(Audience::Single(audience.to_string()));
    c.iat = Some(now);
    c.exp = Some(now + 300);
    c.jti = Some(crate::util::random_token(16));
    jwt::sign(key, &c, None)
}

/// Build a structured [`Error::UpstreamHttp`] from a non-success response.
///
/// `error` / `error_description` come from a JSON object body with a string
/// `error` (RFC 6749 §5.2); otherwise from the `WWW-Authenticate` header.
/// `message` is the full `Display` text. `auth_failure` marks token and
/// UserInfo requests, which 0.8 reported as `Error::Authn`.
fn upstream_error(message: String, resp: &HttpFetchResponse, auth_failure: bool) -> Error {
    let mut error = None;
    let mut description = None;
    if let Ok(serde_json::Value::Object(obj)) =
        serde_json::from_slice::<serde_json::Value>(&resp.body)
    {
        if let Some(code) = obj.get("error").and_then(|v| v.as_str()) {
            error = Some(escape_upstream_text(code, 64));
            description = obj
                .get("error_description")
                .and_then(|v| v.as_str())
                .map(|d| escape_upstream_text(d, 256));
        }
    }
    if error.is_none() {
        if let Some((e, d)) = resp
            .header("www-authenticate")
            .and_then(parse_www_authenticate_bearer)
        {
            error = e.map(|e| escape_upstream_text(&e, 64));
            description = d.map(|d| escape_upstream_text(&d, 256));
        }
    }
    let body = if resp.body.is_empty() {
        None
    } else {
        Some(escape_upstream_text(
            &String::from_utf8_lossy(&resp.body),
            512,
        ))
    };
    Error::UpstreamHttp(Box::new(UpstreamHttpError::new(
        Some(resp.status),
        error,
        description,
        body,
        message,
        auth_failure,
    )))
}

/// Sanitize an upstream token-endpoint error body before embedding it in our
/// error: control and bidi/format characters are stripped (log/terminal
/// injection) and the text is truncated to 512 chars so a hostile or broken OP
/// cannot blow up our logs or responses.
fn sanitize_error_body(body: &str) -> String {
    body.chars()
        .filter(|c| !c.is_control() && !crate::error::is_bidi_format(*c))
        .take(512)
        .collect()
}

fn apply_client_auth(
    client: &RpClient,
    provider: &ProviderInfo,
    form: &mut Vec<(String, String)>,
    headers: &mut Vec<(String, String)>,
) -> Result<()> {
    match &client.auth {
        ClientAuth::None => {}
        ClientAuth::ClientSecretPost(secret) => {
            form.push(("client_secret".into(), secret.clone()));
        }
        ClientAuth::ClientSecretBasic(secret) => {
            use base64::Engine;
            let raw = format!("{}:{}", urlencode(&client.client_id), urlencode(secret));
            let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            headers.push(("authorization".into(), format!("Basic {b64}")));
        }
        ClientAuth::PrivateKeyJwt(key) => {
            let assertion =
                build_client_assertion(key, &client.client_id, &provider.token_endpoint)?;
            form.push((
                "client_assertion_type".into(),
                CLIENT_ASSERTION_TYPE.to_string(),
            ));
            form.push(("client_assertion".into(), assertion));
        }
    }
    Ok(())
}

/// Convert a userinfo / id_token claims object into the proxy's external
/// attribute map shape (`name -> [values]`).
pub fn claims_to_attributes(claims: &serde_json::Value) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    if let Some(obj) = claims.as_object() {
        for (k, v) in obj {
            let values = match v {
                serde_json::Value::String(s) => vec![s.clone()],
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                serde_json::Value::Number(n) => vec![n.to_string()],
                serde_json::Value::Bool(b) => vec![b.to_string()],
                _ => continue,
            };
            if !values.is_empty() {
                out.insert(k.clone(), values);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::signing_key_from_jwk_json;

    fn client_and_provider() -> (RpClient, ProviderInfo, SigningKey) {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let key = signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some("rp-1"))
            .unwrap();
        let client = RpClient {
            client_id: "https://rp.example.com".into(),
            redirect_uri: "https://rp.example.com/callback".into(),
            auth: ClientAuth::PrivateKeyJwt(key.clone()),
            scope: "openid email".into(),
        };
        let provider = ProviderInfo {
            issuer: "https://op.example.org".into(),
            authorization_endpoint: "https://op.example.org/authorize".into(),
            token_endpoint: "https://op.example.org/token".into(),
            userinfo_endpoint: None,
            jwks_uri: None,
        };
        (client, provider, key)
    }

    #[test]
    fn service_endpoints_reject_raw_whitespace_and_controls() {
        for endpoint in [
            "https://op.example.\torg/token",
            "ht\ntps://op.example.org/token",
            " https://op.example.org/token",
            "https://op.example.org/token\x1f",
            "https://op.example.org/token\r\nX-Test: injected",
        ] {
            assert!(
                validate_service_endpoint("token_endpoint", endpoint).is_err(),
                "unsafe raw endpoint must be rejected: {endpoint:?}"
            );
        }

        // Encoded octets do not create a parser/use mismatch, and endpoint
        // queries remain valid.
        for endpoint in [
            "https://op.example.org/token?label=hello%20world",
            "https://op.example.org/%09/%0A",
        ] {
            validate_service_endpoint("token_endpoint", endpoint)
                .unwrap_or_else(|error| panic!("valid endpoint {endpoint:?}: {error}"));
        }

        // A context-free URL must never inherit the development exception.
        for endpoint in [
            "http://localhost:8080/token",
            "http://127.0.0.1:8080/token",
            "http://[::1]:8080/token",
        ] {
            assert!(validate_service_endpoint("token_endpoint", endpoint).is_err());
        }
    }

    #[test]
    fn loopback_http_endpoints_require_a_loopback_http_issuer() {
        let (_, provider, _) = client_and_provider();
        for field in [
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ] {
            let mut contaminated = provider.clone();
            let endpoint = "http://127.0.0.1:8080/path".to_string();
            match field {
                "authorization_endpoint" => contaminated.authorization_endpoint = endpoint,
                "token_endpoint" => contaminated.token_endpoint = endpoint,
                "userinfo_endpoint" => contaminated.userinfo_endpoint = Some(endpoint),
                "jwks_uri" => contaminated.jwks_uri = Some(endpoint),
                _ => unreachable!(),
            }
            assert!(
                contaminated.validate().is_err(),
                "remote issuer must not authorize loopback HTTP {field}"
            );
        }

        let local = ProviderInfo {
            issuer: "http://localhost:8080".into(),
            authorization_endpoint: "http://localhost:8080/authorize".into(),
            token_endpoint: "http://127.0.0.1:8080/token".into(),
            userinfo_endpoint: Some("http://[::1]:8080/userinfo".into()),
            jwks_uri: Some("http://localhost:8080/jwks".into()),
        };
        local
            .validate()
            .expect("loopback issuer may use loopback HTTP endpoints");
    }

    #[test]
    fn provider_info_rejects_controls_in_every_endpoint_field() {
        let (_, provider, _) = client_and_provider();
        for field in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ] {
            let mut contaminated = provider.clone();
            let endpoint = "https://op.example.org/path\r\nX-Test: injected".to_string();
            match field {
                "issuer" => contaminated.issuer = endpoint,
                "authorization_endpoint" => contaminated.authorization_endpoint = endpoint,
                "token_endpoint" => contaminated.token_endpoint = endpoint,
                "userinfo_endpoint" => contaminated.userinfo_endpoint = Some(endpoint),
                "jwks_uri" => contaminated.jwks_uri = Some(endpoint),
                _ => unreachable!(),
            }
            assert!(
                contaminated.validate().is_err(),
                "unsafe {field} must be rejected"
            );
        }
    }

    #[test]
    fn signed_request_object_carries_request_params_and_verifies() {
        let (client, provider, key) = client_and_provider();
        let challenge = crate::pkce::s256_challenge(&"v".repeat(43));
        let jar = signed_request_object(&provider, &client, &key, "st-1", "n-1", Some(&challenge))
            .unwrap();

        // Verifies against the RP's published public keys, audience = OP issuer.
        let validation = Validation::new()
            .with_issuer(&client.client_id)
            .with_audience(&provider.issuer);
        let claims = jwt::verify_with_jwks(&key.to_public_jwks(), &jar, &validation).unwrap();

        assert_eq!(claims.extra["client_id"], client.client_id);
        assert_eq!(claims.extra["redirect_uri"], client.redirect_uri);
        assert_eq!(claims.extra["response_type"], "code");
        assert_eq!(claims.extra["scope"], "openid email");
        assert_eq!(claims.extra["state"], "st-1");
        assert_eq!(claims.extra["nonce"], "n-1");
        assert_eq!(claims.extra["code_challenge"], challenge);
        assert_eq!(claims.extra["code_challenge_method"], "S256");
        assert!(claims.jti.is_some(), "jti for replay detection");
        let (iat, exp) = (claims.iat.unwrap(), claims.exp.unwrap());
        assert!(exp > iat && exp <= iat + 300);

        // Header: alg + kid, no typ (interop with Shibboleth's OIDC plugin,
        // which expects a plain JWT request object).
        let header = jwt::peek_header(&jar).unwrap();
        assert_eq!(header.kid.as_deref(), Some("rp-1"));
        assert!(header.typ.is_none());
    }

    #[test]
    fn signed_request_object_omits_pkce_when_absent() {
        let (client, provider, key) = client_and_provider();
        let jar = signed_request_object(&provider, &client, &key, "st", "n", None).unwrap();
        let claims = jwt::peek_claims_unverified(&jar).unwrap();
        assert!(!claims.extra.contains_key("code_challenge"));
        assert!(!claims.extra.contains_key("code_challenge_method"));
    }

    #[test]
    fn authorization_url_rejects_query_collisions_across_configuration_and_extras() {
        let (client, mut provider, _) = client_and_provider();
        provider.authorization_endpoint =
            "https://op.example.org/authorize?tenant=configured".into();

        let err = authorization_url(
            &provider,
            &client,
            "state",
            "nonce",
            None,
            &[("tenant", "override")],
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate authorization extra"));

        // RFC 8707 deliberately permits repeated resource indicators.
        let url = authorization_url(
            &provider,
            &client,
            "state",
            "nonce",
            None,
            &[("resource", "https://api.example.org")],
        )
        .unwrap();
        assert!(url.contains("tenant=configured"));
        assert!(url.contains("resource=https%3A%2F%2Fapi.example.org"));
    }

    /// Minimal in-memory [`HttpClient`] for discovery / token-endpoint tests.
    struct MockHttp {
        get: Option<crate::http::HttpFetchResponse>,
        post: Option<crate::http::HttpFetchResponse>,
    }

    #[async_trait::async_trait]
    impl HttpClient for MockHttp {
        async fn get(&self, _url: &str) -> Result<crate::http::HttpFetchResponse> {
            self.get
                .clone()
                .ok_or_else(|| Error::Internal("unexpected GET".into()))
        }

        async fn post_form(
            &self,
            _url: &str,
            _form: &[(String, String)],
            _headers: &[(String, String)],
        ) -> Result<crate::http::HttpFetchResponse> {
            self.post
                .clone()
                .ok_or_else(|| Error::Internal("unexpected POST".into()))
        }
    }

    fn metadata_response(issuer: &str) -> crate::http::HttpFetchResponse {
        let metadata = ProviderMetadata::new(issuer, issuer);
        crate::http::HttpFetchResponse {
            status: 200,
            body: serde_json::to_vec(&metadata).unwrap(),
            content_type: Some("application/json".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn discover_rejects_plain_http_for_non_loopback() {
        // The mock has no GET response: the request must be refused before any
        // fetch happens.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: None,
        });
        assert!(discover(&http, "http://op.example.com").await.is_err());
    }

    #[tokio::test]
    async fn discover_allows_http_for_loopback() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(metadata_response("http://127.0.0.1:8080")),
            post: None,
        });
        let metadata = discover(&http, "http://127.0.0.1:8080").await.unwrap();
        assert_eq!(metadata.issuer, "http://127.0.0.1:8080");
    }

    #[tokio::test]
    async fn fetch_jwks_binds_loopback_http_exception_to_issuer() {
        let rejected_http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: None,
        });
        let error = fetch_jwks(
            &rejected_http,
            "http://127.0.0.1:8080/jwks",
            "https://remote.example",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("absolute https URL"));

        let (_, _, key) = client_and_provider();
        let local_http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse {
                status: 200,
                body: key.to_public_jwks().to_json().unwrap().into_bytes(),
                content_type: Some("application/json".into()),
                ..Default::default()
            }),
            post: None,
        });
        let fetched = fetch_jwks(
            &local_http,
            "http://127.0.0.1:8080/jwks",
            "http://localhost:8080",
        )
        .await
        .expect("loopback issuer may fetch a loopback HTTP JWKS");
        assert_eq!(fetched.keys.len(), 1);
    }

    #[tokio::test]
    async fn discover_allows_http_for_ipv6_loopback() {
        // Url::host_str yields the bracketed form ("[::1]"); it must still be
        // recognized as loopback.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(metadata_response("http://[::1]:8080")),
            post: None,
        });
        let metadata = discover(&http, "http://[::1]:8080").await.unwrap();
        assert_eq!(metadata.issuer, "http://[::1]:8080");

        // Non-loopback IPv6 stays rejected over plain http.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: None,
        });
        assert!(discover(&http, "http://[2001:db8::1]").await.is_err());
    }

    fn json_response(body: serde_json::Value) -> crate::http::HttpFetchResponse {
        crate::http::HttpFetchResponse {
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
            content_type: Some("application/json".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn discover_accepts_metadata_without_userinfo_endpoint() {
        let issuer = "https://op.example.com";
        let mut body = ProviderMetadata::new(issuer, issuer).to_json();
        body.as_object_mut().unwrap().remove("userinfo_endpoint");
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(json_response(body)),
            post: None,
        });
        let metadata = discover(&http, issuer).await.unwrap();
        assert!(metadata.userinfo_endpoint.is_none());
        let info = ProviderInfo::from(metadata);
        assert!(info.userinfo_endpoint.is_none());
        let err = info.require_userinfo_endpoint().unwrap_err();
        assert!(err.to_string().contains("userinfo_endpoint"));
        assert!(info.require_jwks_uri().is_ok());
    }

    #[tokio::test]
    async fn discover_rejects_loopback_http_userinfo_under_remote_issuer() {
        let issuer = "https://op.example.com";
        let mut body = ProviderMetadata::new(issuer, issuer).to_json();
        body["userinfo_endpoint"] = "http://127.0.0.1:8080/userinfo".into();
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(json_response(body)),
            post: None,
        });
        assert!(discover(&http, issuer).await.is_err());
    }

    #[test]
    fn require_jwks_uri_errors_when_missing() {
        let (_, provider, _) = client_and_provider();
        let err = provider.require_jwks_uri().unwrap_err();
        assert!(err.to_string().contains("jwks_uri"));
    }

    #[tokio::test]
    async fn discover_rejects_issuer_mismatch() {
        // OIDC Discovery §4.3: the returned issuer must match the requested one.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(metadata_response("https://evil.example.com")),
            post: None,
        });
        assert!(discover(&http, "https://op.example.com").await.is_err());
    }

    #[tokio::test]
    async fn exchange_code_error_body_is_sanitized() {
        let (client, provider, _key) = client_and_provider();
        // A hostile upstream: >512 chars, laced with ANSI escapes and newlines.
        let body = "oops\x1b[31m\n".repeat(200);
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: Some(crate::http::HttpFetchResponse {
                status: 400,
                body: body.into_bytes(),
                content_type: None,
                ..Default::default()
            }),
        });
        let err = exchange_code(&http, &provider, &client, "code-1", None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.len() < 600,
            "upstream body must be truncated: {}",
            msg.len()
        );
        assert!(
            !msg.chars().any(|c| c.is_control()),
            "control characters must be stripped: {msg:?}"
        );
    }

    fn mock_post(resp: crate::http::HttpFetchResponse) -> Arc<dyn HttpClient> {
        Arc::new(MockHttp {
            get: None,
            post: Some(resp),
        })
    }

    #[tokio::test]
    async fn upstream_errors_classify_auth_failures() {
        let (client, provider, _key) = client_and_provider();
        // Token endpoint rejection: formerly Authn.
        let http = mock_post(crate::http::HttpFetchResponse::new(400, "{}"));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        assert!(err.is_auth_failure());
        assert!(!matches!(err, Error::Authn(_)));
        // UserInfo rejection: formerly Authn.
        let http = mock_post(crate::http::HttpFetchResponse::new(401, ""));
        let err = fetch_userinfo(
            &http,
            "https://op.example.org/userinfo",
            "at",
            "sub",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        assert!(err.is_auth_failure());
        // JWKS fetch failure: formerly Internal, not an auth failure.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse::new(500, "")),
            post: None,
        });
        let err = fetch_jwks(
            &http,
            "https://op.example.org/jwks",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        assert!(err.upstream_http().is_some());
        assert!(!err.is_auth_failure());
        // Plain Authn still counts.
        assert!(Error::Authn("x".into()).is_auth_failure());
        assert!(!Error::Internal("x".into()).is_auth_failure());
    }

    #[tokio::test]
    async fn token_error_is_structured_and_escaped() {
        let (client, provider, _key) = client_and_provider();
        let body = r#"{"error":"invalid_grant","error_description":"bad\u001b[31m code"}"#;
        let http = mock_post(crate::http::HttpFetchResponse::new(400, body));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        let up = err.upstream_http().expect("upstream variant");
        assert_eq!(up.status, Some(400));
        assert_eq!(up.error.as_deref(), Some("invalid_grant"));
        let d = up.error_description.as_deref().unwrap();
        assert!(d.contains("\\u{1b}"), "{d}");
        assert!(!d.chars().any(|c| c.is_control()));
        assert_eq!(
            err.to_string(),
            format!(
                "authentication error: token endpoint returned 400: {}",
                sanitize_error_body(body)
            )
        );
        assert_eq!(
            err.to_string(),
            "authentication error: token endpoint returned 400: {\"error\":\"invalid_grant\",\"error_description\":\"bad\\u001b[31m code\"}"
        );
        assert_eq!(err.status_hint(), 502);
    }

    #[tokio::test]
    async fn token_error_body_field_is_capped_and_bidi_escaped() {
        let (client, provider, _key) = client_and_provider();
        let body = format!("oops\x1b[31m\n{}\u{202E}", "x".repeat(2000));
        let http = mock_post(crate::http::HttpFetchResponse::new(400, body.clone()));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        let up = err.upstream_http().unwrap();
        let b = up.body.as_deref().unwrap();
        assert!(!b.chars().any(|c| c.is_control()));
        assert!(b.chars().count() <= 513);
        assert!(b.ends_with('…'));
        assert_eq!(up.error, None);

        let http = mock_post(crate::http::HttpFetchResponse::new(400, "a\u{202E}b"));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        assert_eq!(
            err.upstream_http().unwrap().body.as_deref(),
            Some("a\\u{202e}b")
        );
        // The Display text must not carry the bidi override either.
        let shown = err.to_string();
        assert!(!shown.contains('\u{202E}'));
        assert_eq!(
            shown,
            "authentication error: token endpoint returned 400: ab"
        );
    }

    #[tokio::test]
    async fn userinfo_error_parses_www_authenticate() {
        let resp = crate::http::HttpFetchResponse::new(401, "").with_header(
            "WWW-Authenticate",
            r#"Bearer error="invalid_token", error_description="expired""#,
        );
        let http = mock_post(resp);
        let err = fetch_userinfo(
            &http,
            "https://op.example.org/userinfo",
            "tok",
            "sub",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        let up = err.upstream_http().unwrap();
        assert_eq!(up.status, Some(401));
        assert_eq!(up.error.as_deref(), Some("invalid_token"));
        assert_eq!(up.error_description.as_deref(), Some("expired"));
        assert_eq!(up.body, None);
        assert_eq!(
            err.to_string(),
            "authentication error: userinfo returned 401"
        );
        assert_eq!(err.status_hint(), 502);
    }

    type RecordedCall = (String, String, Vec<(String, String)>);

    /// Records every call as `(method, url, headers)`.
    struct RecordingHttp {
        calls: std::sync::Mutex<Vec<RecordedCall>>,
        resp: crate::http::HttpFetchResponse,
        get_supported: bool,
    }

    impl RecordingHttp {
        fn new(resp: crate::http::HttpFetchResponse, get_supported: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: Default::default(),
                resp,
                get_supported,
            })
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for RecordingHttp {
        async fn get(&self, _url: &str) -> Result<crate::http::HttpFetchResponse> {
            Err(Error::Internal("unexpected GET".into()))
        }

        async fn post_form(
            &self,
            url: &str,
            _form: &[(String, String)],
            headers: &[(String, String)],
        ) -> Result<crate::http::HttpFetchResponse> {
            self.calls
                .lock()
                .unwrap()
                .push(("POST".into(), url.into(), headers.to_vec()));
            Ok(self.resp.clone())
        }

        async fn get_with_headers(
            &self,
            url: &str,
            headers: &[(String, String)],
        ) -> Result<crate::http::HttpFetchResponse> {
            if !self.get_supported {
                return Err(Error::Config("no get_with_headers".into()));
            }
            self.calls
                .lock()
                .unwrap()
                .push(("GET".into(), url.into(), headers.to_vec()));
            Ok(self.resp.clone())
        }
    }

    fn json_userinfo(content_type: &str) -> crate::http::HttpFetchResponse {
        crate::http::HttpFetchResponse {
            status: 200,
            body: br#"{"sub":"s1","name":"A"}"#.to_vec(),
            content_type: Some(content_type.into()),
            ..Default::default()
        }
    }

    const UI_URL: &str = "https://op.example.org/userinfo";
    const UI_ISS: &str = "https://op.example.org";

    #[tokio::test]
    async fn userinfo_get_sends_bearer_without_post() {
        let rec = RecordingHttp::new(json_userinfo("application/json"), true);
        let http: Arc<dyn HttpClient> = rec.clone();
        let resp = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Get)
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "GET");
        assert_eq!(calls[0].1, UI_URL);
        assert_eq!(
            calls[0].2,
            vec![("authorization".to_string(), "Bearer at".to_string())]
        );
    }

    #[tokio::test]
    async fn userinfo_get_without_client_support_errors() {
        let rec = RecordingHttp::new(json_userinfo("application/json"), false);
        let http: Arc<dyn HttpClient> = rec.clone();
        let res = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Get).await;
        assert!(res.is_err());
        assert!(rec.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn userinfo_post_matches_fetch_userinfo() {
        let rec = RecordingHttp::new(json_userinfo("application/json"), true);
        let http: Arc<dyn HttpClient> = rec.clone();
        let claims = fetch_userinfo(&http, UI_URL, "at", "s1", UI_ISS)
            .await
            .unwrap();
        assert_eq!(claims["name"], "A");
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "POST");
        assert_eq!(
            calls[0].2,
            vec![("authorization".to_string(), "Bearer at".to_string())]
        );
    }

    #[tokio::test]
    async fn userinfo_raw_jwt_returned_untouched_but_rejected_as_json() {
        let jwt_resp = crate::http::HttpFetchResponse {
            status: 200,
            body: b"a.b.c".to_vec(),
            content_type: Some("Application/JWT; charset=utf-8".into()),
            ..Default::default()
        };
        let rec = RecordingHttp::new(jwt_resp, true);
        let http: Arc<dyn HttpClient> = rec.clone();
        let resp = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Post)
            .await
            .unwrap();
        assert_eq!(resp.body, b"a.b.c");
        let err = userinfo_json_claims(&resp, "s1").unwrap_err();
        assert!(err.to_string().contains("fetch_userinfo_response"), "{err}");
        assert!(fetch_userinfo(&http, UI_URL, "at", "s1", UI_ISS)
            .await
            .is_err());
    }

    #[test]
    fn userinfo_json_claims_accepts_charset_and_binds_sub() {
        let resp = json_userinfo("application/json; charset=utf-8");
        assert_eq!(userinfo_json_claims(&resp, "s1").unwrap()["sub"], "s1");
        let err = userinfo_json_claims(&resp, "other").unwrap_err();
        assert!(err.to_string().contains("userinfo sub does not match"));
    }

    #[tokio::test]
    async fn userinfo_loopback_endpoint_under_remote_issuer_rejected_before_http() {
        let rec = RecordingHttp::new(json_userinfo("application/json"), true);
        let http: Arc<dyn HttpClient> = rec.clone();
        for method in [UserinfoMethod::Get, UserinfoMethod::Post] {
            let res = fetch_userinfo_response(
                &http,
                "http://127.0.0.1:8080/userinfo",
                "at",
                UI_ISS,
                method,
            )
            .await;
            assert!(res.is_err());
        }
        assert!(rec.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn discover_and_jwks_failures_are_upstream_http() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse::new(404, "nope")),
            post: None,
        });
        let err = discover(&http, "https://op.example.com").await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "internal error: discovery failed (404) for https://op.example.com/.well-known/openid-configuration"
        );
        assert_eq!(err.upstream_http().unwrap().status, Some(404));

        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse::new(500, "")),
            post: None,
        });
        let err = fetch_jwks(
            &http,
            "https://op.example.org/jwks",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "internal error: jwks fetch failed (500)");
        assert_eq!(err.upstream_http().unwrap().body, None);
    }

    #[test]
    fn verify_id_token_requires_exp_and_iat() {
        let (_client, _provider, key) = client_and_provider();
        let jwks = key.to_public_jwks();
        let now = now_secs();

        // No exp -> rejected.
        let mut c = Claims::default();
        c.iss = Some("https://op.example.org".into());
        c.sub = Some("subject".into());
        c.aud = Some(Audience::Single("https://rp.example.com".into()));
        c.iat = Some(now);
        let token = jwt::sign(&key, &c, None).unwrap();
        assert!(
            verify_id_token(
                &jwks,
                &token,
                "https://op.example.org",
                "https://rp.example.com",
                None,
                &[JwsAlgorithm::ES256],
                &[],
            )
            .is_err(),
            "id_token without exp must be rejected"
        );

        // No iat -> rejected.
        let mut c = Claims::default();
        c.iss = Some("https://op.example.org".into());
        c.sub = Some("subject".into());
        c.aud = Some(Audience::Single("https://rp.example.com".into()));
        c.exp = Some(now + 300);
        let token = jwt::sign(&key, &c, None).unwrap();
        assert!(
            verify_id_token(
                &jwks,
                &token,
                "https://op.example.org",
                "https://rp.example.com",
                None,
                &[JwsAlgorithm::ES256],
                &[],
            )
            .is_err(),
            "id_token without iat must be rejected"
        );

        // Both present -> accepted.
        let mut c = Claims::default();
        c.iss = Some("https://op.example.org".into());
        c.sub = Some("subject".into());
        c.aud = Some(Audience::Single("https://rp.example.com".into()));
        c.iat = Some(now);
        c.exp = Some(now + 300);
        let token = jwt::sign(&key, &c, None).unwrap();
        verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[JwsAlgorithm::ES256],
            &[],
        )
        .unwrap();
    }

    #[test]
    fn verify_id_token_accepts_single_element_array_audience_without_azp() {
        let (_client, _provider, key) = client_and_provider();
        let jwks = key.to_public_jwks();
        let now = now_secs();
        let client_id = "https://rp.example.com";

        let mut claims = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Multiple(vec![client_id.into()])),
            iat: Some(now),
            exp: Some(now + 300),
            ..Default::default()
        };
        let token = jwt::sign(&key, &claims, None).unwrap();
        verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            client_id,
            None,
            &[JwsAlgorithm::ES256],
            &[],
        )
        .expect("a one-element aud array does not require azp");

        // An azp claim is optional for one audience, but still must identify
        // this client when the issuer includes it.
        claims.extra.insert("azp".into(), "another-client".into());
        let token = jwt::sign(&key, &claims, None).unwrap();
        assert!(
            verify_id_token(
                &jwks,
                &token,
                "https://op.example.org",
                client_id,
                None,
                &[JwsAlgorithm::ES256],
                &[],
            )
            .is_err(),
            "a supplied azp must match client_id"
        );
    }

    fn opts_token(key: &SigningKey, tweak: impl FnOnce(&mut Claims)) -> (String, JwkSet) {
        let now = now_secs();
        let mut c = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Single("https://rp.example.com".into())),
            iat: Some(now),
            exp: Some(now + 300),
            ..Default::default()
        };
        tweak(&mut c);
        (jwt::sign(key, &c, None).unwrap(), key.to_public_jwks())
    }

    fn verify_with(
        jwks: &JwkSet,
        token: &str,
        alg: JwsAlgorithm,
        options: &IdTokenOptions<'_>,
    ) -> Result<Claims> {
        verify_id_token_with(
            jwks,
            token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[alg],
            &[],
            options,
        )
    }

    #[test]
    fn default_leeway_constant_matches_jose() {
        assert_eq!(Validation::default().leeway, DEFAULT_LEEWAY);
    }

    #[test]
    fn id_token_options_leeway() {
        let (_c, _p, key) = client_and_provider();
        let now = now_secs();
        let (token, jwks) = opts_token(&key, |c| c.exp = Some(now - 30));
        let es = JwsAlgorithm::ES256;
        verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[es],
            &[],
        )
        .unwrap();
        assert!(verify_with(&jwks, &token, es, &IdTokenOptions::new().with_leeway(0)).is_err());
        verify_with(&jwks, &token, es, &IdTokenOptions::new().with_leeway(60)).unwrap();
    }

    #[test]
    fn id_token_options_leeway_is_bounded_and_not_added_to_max_age() {
        let (_c, _p, key) = client_and_provider();
        let es = JwsAlgorithm::ES256;
        let now = now_secs();

        // A leeway above the cap is a configuration error, even for a valid token.
        let (token, jwks) = opts_token(&key, |_| {});
        let err = verify_with(
            &jwks,
            &token,
            es,
            &IdTokenOptions::new().with_leeway(MAX_ID_TOKEN_LEEWAY + 1),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
        assert!(verify_with(
            &jwks,
            &token,
            es,
            &IdTokenOptions::new().with_leeway(u64::MAX)
        )
        .is_err());
        verify_with(
            &jwks,
            &token,
            es,
            &IdTokenOptions::new().with_leeway(MAX_ID_TOKEN_LEEWAY),
        )
        .unwrap();

        // An expired token is not revived by a huge leeway.
        let (token, jwks) = opts_token(&key, |c| c.exp = Some(now - 86_400 * 365));
        assert!(verify_with(
            &jwks,
            &token,
            es,
            &IdTokenOptions::new().with_leeway(u64::MAX)
        )
        .is_err());

        // Leeway does not stretch max_age: 100s old with max_age 60 fails
        // even with the maximum leeway.
        let (token, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), (now - 100).into());
        });
        let opts = IdTokenOptions::new()
            .with_max_age(60)
            .with_leeway(MAX_ID_TOKEN_LEEWAY);
        assert!(verify_with(&jwks, &token, es, &opts).is_err());
        let opts = IdTokenOptions::new().with_max_age(120);
        verify_with(&jwks, &token, es, &opts).unwrap();
    }

    #[test]
    fn id_token_options_default_equals_verify_id_token() {
        let (_c, _p, key) = client_and_provider();
        let (token, jwks) = opts_token(&key, |_| {});
        let a = verify_with(
            &jwks,
            &token,
            JwsAlgorithm::ES256,
            &IdTokenOptions::default(),
        )
        .unwrap();
        let b = verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[JwsAlgorithm::ES256],
            &[],
        )
        .unwrap();
        assert_eq!(a.sub, b.sub);
        assert_eq!(a.exp, b.exp);
    }

    #[test]
    fn id_token_options_max_age() {
        let (_c, _p, key) = client_and_provider();
        let now = now_secs();
        let es = JwsAlgorithm::ES256;
        let opts = IdTokenOptions::new().with_max_age(300);

        let (t, jwks) = opts_token(&key, |_| {});
        let err = verify_with(&jwks, &t, es, &opts).unwrap_err();
        assert!(err.to_string().contains("auth_time"), "{err}");

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), (now - 1000).into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), (now - 10).into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), (now + 3600).into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), "123".into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), 1.5.into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        // Old iat (still within exp) but recent auth_time: max_age is not iat-based.
        let (t, jwks) = opts_token(&key, |c| {
            c.iat = Some(now - 5000);
            c.exp = Some(now + 300);
            c.extra.insert("auth_time".into(), (now - 10).into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();
    }

    #[test]
    fn id_token_options_acr() {
        let (_c, _p, key) = client_and_provider();
        let es = JwsAlgorithm::ES256;
        let allowed = ["urn:acr:high", "urn:acr:mid"];
        let opts = IdTokenOptions::new().with_acr_values(&allowed);

        let (t, jwks) = opts_token(&key, |_| {});
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("acr".into(), "urn:acr:low".into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("acr".into(), 2.into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("acr".into(), "urn:acr:mid".into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();

        let empty: [&str; 0] = [];
        let err = verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new().with_acr_values(&empty),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[test]
    fn id_token_options_at_hash() {
        let (_c, _p, key) = client_and_provider();
        let es = JwsAlgorithm::ES256;
        let at = "access-token-value";
        let opts = IdTokenOptions::new().with_access_token(at);

        let good = jwt::oidc_token_hash(es, at).unwrap();
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), good.clone().into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();
        // Present without the option: not checked.
        verify_with(&jwks, &t, es, &IdTokenOptions::new()).unwrap();
        // Different access token: mismatch.
        assert!(verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new().with_access_token("other")
        )
        .is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), "AAAA".into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), 5.into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        // Absent at_hash is accepted unless explicitly required.
        let (t, jwks) = opts_token(&key, |_| {});
        verify_with(&jwks, &t, es, &opts).unwrap();
        let required = IdTokenOptions::new()
            .with_access_token(at)
            .with_required_at_hash();
        assert!(verify_with(&jwks, &t, es, &required).is_err());
        // Required and present and matching passes.
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), good.clone().into());
        });
        verify_with(&jwks, &t, es, &required).unwrap();
        // Requiring at_hash without an access token is a configuration error.
        let err = verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions {
                require_at_hash: true,
                ..IdTokenOptions::new()
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[test]
    fn id_token_options_c_hash() {
        let (_c, _p, key) = client_and_provider();
        let es = JwsAlgorithm::ES256;
        let code = "authorization-code-value";
        let opts = IdTokenOptions::new().with_authorization_code(code);
        let required = IdTokenOptions::new()
            .with_authorization_code(code)
            .with_required_c_hash();

        let good = jwt::oidc_token_hash(es, code).unwrap();
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("c_hash".into(), good.clone().into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();
        verify_with(&jwks, &t, es, &required).unwrap();
        // Present without the option: not checked.
        verify_with(&jwks, &t, es, &IdTokenOptions::new()).unwrap();
        // A different code does not match.
        assert!(verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new().with_authorization_code("other")
        )
        .is_err());
        // c_hash does not satisfy at_hash and vice versa.
        assert!(verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new()
                .with_access_token(code)
                .with_required_at_hash()
        )
        .is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("c_hash".into(), "AAAA".into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("c_hash".into(), 5.into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        // Absent c_hash is accepted unless required.
        let (t, jwks) = opts_token(&key, |_| {});
        verify_with(&jwks, &t, es, &opts).unwrap();
        let err = verify_with(&jwks, &t, es, &required).unwrap_err();
        assert!(err.to_string().contains("missing c_hash"));
        // Requiring c_hash without a code is a configuration error.
        let err = verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions {
                require_c_hash: true,
                ..IdTokenOptions::new()
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[test]
    fn id_token_options_at_hash_uses_header_alg() {
        let mut jwk = jose_rs::jwk::generate_ec("P-384").unwrap();
        jwk.alg = Some("ES384".into());
        let key = signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES384"), Some("k384"))
            .unwrap();
        let at = "access-token-value";
        let opts = IdTokenOptions::new().with_access_token(at);
        let es384 = JwsAlgorithm::ES384;

        let good = jwt::oidc_token_hash(es384, at).unwrap();
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), good.clone().into());
        });
        verify_with(&jwks, &t, es384, &opts).unwrap();

        let sha256 = jwt::oidc_token_hash(JwsAlgorithm::ES256, at).unwrap();
        assert_ne!(sha256, good);
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), sha256.clone().into());
        });
        assert!(verify_with(&jwks, &t, es384, &opts).is_err());
    }

    #[test]
    fn public_validators_enforce_documented_rules() {
        assert!(validate_issuer("https://op/?q").is_err());
        assert!(validate_issuer("https://op/#f").is_err());
        assert!(validate_issuer("http://op.example").is_err());
        assert!(validate_issuer("http://localhost:8080").is_ok());
        assert!(validate_redirect_uri("https://rp.example/cb#frag").is_err());
        assert!(validate_redirect_uri("com.example.app:/cb").is_ok());
    }

    #[tokio::test]
    async fn discover_issuer_mismatch_escapes_bidi_characters() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(metadata_response("https://evil.example.com/\u{202E}x")),
            post: None,
        });
        let text = discover(&http, "https://op.example.com")
            .await
            .unwrap_err()
            .to_string();
        assert!(text.contains("\\u{202e}"), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
    }

    #[tokio::test]
    async fn unsupported_token_type_escapes_bidi_characters() {
        let (client, provider, _key) = client_and_provider();
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: Some(crate::http::HttpFetchResponse {
                status: 200,
                body: serde_json::json!({
                    "access_token": "a",
                    "id_token": "i",
                    "token_type": "x\u{202E}y",
                })
                .to_string()
                .into_bytes(),
                content_type: Some("application/json".into()),
                ..Default::default()
            }),
        });
        let text = exchange_code(&http, &provider, &client, "code-1", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(text.contains("\\u{202e}"), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
    }

    #[test]
    fn untrusted_audience_escapes_bidi_characters() {
        let (_client, _provider, key) = client_and_provider();
        let jwks = key.to_public_jwks();
        let now = now_secs();
        let claims = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Multiple(vec![
                "https://rp.example.com".into(),
                "evil\u{202E}".into(),
            ])),
            iat: Some(now),
            exp: Some(now + 300),
            ..Default::default()
        };
        let token = jwt::sign(&key, &claims, None).unwrap();
        let text = verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[JwsAlgorithm::ES256],
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(text.contains("\\u{202e}"), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
    }

    #[test]
    fn endpoint_validation_rejects_bidi_formatting_characters() {
        let err = validate_issuer("https://op.example.com/\u{202E}x").unwrap_err();
        assert!(err.to_string().contains("bidi"), "{err}");
        assert!(validate_service_endpoint("jwks_uri", "https://op.example.com/\u{200F}").is_err());
        assert!(!issuer_allows_loopback_http("http://localhost/\u{202E}"));
    }
}
