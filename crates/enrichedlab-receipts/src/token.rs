// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! Verification of the bearer token the gateway sends with every interceptor call.
//!
//! The checks follow `OpenShell`'s extension contract: the `typ` header is `openshell-ext+jwt`, the
//! algorithm is pinned to `EdDSA` (never read from the token), the signature, expiry and exact audience
//! are valid, the issuer is `openshell-gateway:<gateway id>`, and the caller is the gateway itself
//! (subject equal to the issuer, no sandbox id). A token that lives longer than `OpenShell`'s maximum
//! extension lifetime is refused.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode_header};
use openshell_extension_core::{
    EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims, MAX_EXTENSION_TOKEN_TTL,
};

/// Why a call's token was refused. The text never includes the token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("the call carries no bearer token")]
    Missing,
    #[error("the token header cannot be read")]
    Header,
    #[error("the token is not an EdDSA extension token")]
    Kind,
    #[error("the token was signed with another key")]
    KeyId,
    #[error("the token's signature, expiry, issuer or audience is invalid")]
    Claims,
    #[error("the token was not issued to the gateway itself")]
    Caller,
    #[error("the token lives longer than an extension token may")]
    Lifetime,
}

/// Verifies gateway extension tokens with the gateway's public signing key.
pub struct TokenVerifier {
    key: DecodingKey,
    kid: Option<String>,
    issuer: String,
    audience: String,
}

impl TokenVerifier {
    /// Builds a verifier from the gateway's PEM public key (SPKI), its key id when known, the
    /// gateway id and this service's registered audience.
    pub fn new(
        public_key_pem: &[u8],
        kid: Option<String>,
        gateway_id: &str,
        audience: &str,
    ) -> Result<Self, String> {
        if gateway_id.trim().is_empty() || audience.trim().is_empty() {
            return Err("the gateway id and audience must not be empty".to_string());
        }
        let key = DecodingKey::from_ed_pem(public_key_pem).map_err(|error| {
            format!("the gateway public key is not an Ed25519 PEM key: {error}")
        })?;
        Ok(Self {
            key,
            kid: kid
                .map(|kid| kid.trim().to_string())
                .filter(|kid| !kid.is_empty()),
            issuer: format!("openshell-gateway:{gateway_id}"),
            audience: audience.to_string(),
        })
    }

    /// The audience this service expects, returned in `Describe` so the gateway refuses to start on a
    /// mismatch.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Checks an `authorization` header value.
    pub fn verify(&self, authorization: Option<&str>) -> Result<ExtensionJwtClaims, TokenError> {
        let token = authorization
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or(TokenError::Missing)?;
        let header = decode_header(token).map_err(|_| TokenError::Header)?;
        if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some(EXTENSION_JWT_TYP) {
            return Err(TokenError::Kind);
        }
        if let Some(kid) = &self.kid
            && header.kid.as_deref() != Some(kid.as_str())
        {
            return Err(TokenError::KeyId);
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp"]);
        let claims =
            openshell_crypto::jwt::decode::<ExtensionJwtClaims>(token, &self.key, &validation)
                .map_err(|_| TokenError::Claims)?
                .claims;
        if claims.caller_kind != ExtensionCallerKind::Gateway
            || claims.sandbox_id.is_some()
            || claims.sub != self.issuer
        {
            return Err(TokenError::Caller);
        }
        let lifetime = claims.exp.saturating_sub(claims.iat);
        let limit = i64::try_from(MAX_EXTENSION_TOKEN_TTL.as_secs()).unwrap_or(i64::MAX);
        if lifetime <= 0 || lifetime > limit {
            return Err(TokenError::Lifetime);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    struct Keys {
        signing: EncodingKey,
        public_pem: Vec<u8>,
    }

    fn keys() -> Keys {
        let pair = openshell_crypto::pki::generate_jwt_keypair().expect("keypair");
        let signing_pem = pair.serialize_pem().expect("signing key PEM");
        Keys {
            signing: EncodingKey::from_ed_pem(signing_pem.as_bytes()).expect("signing key"),
            public_pem: pair.public_key_pem().into_bytes(),
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn claims(caller_kind: ExtensionCallerKind, sandbox_id: Option<&str>) -> ExtensionJwtClaims {
        ExtensionJwtClaims {
            iss: "openshell-gateway:openshell".to_string(),
            aud: "urn:openshell:extension:interceptor:receipts".to_string(),
            sub: "openshell-gateway:openshell".to_string(),
            iat: now(),
            exp: now() + 600,
            jti: "token-1".to_string(),
            caller_kind,
            sandbox_id: sandbox_id.map(str::to_string),
        }
    }

    fn token(
        keys: &Keys,
        claims: &ExtensionJwtClaims,
        typ: Option<&str>,
        kid: Option<&str>,
    ) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = typ.map(str::to_string);
        header.kid = kid.map(str::to_string);
        openshell_crypto::jwt::encode(&header, claims, &keys.signing).expect("token")
    }

    fn verifier(keys: &Keys) -> TokenVerifier {
        TokenVerifier::new(
            &keys.public_pem,
            Some("kid-1".to_string()),
            "openshell",
            "urn:openshell:extension:interceptor:receipts",
        )
        .expect("verifier")
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    #[test]
    fn accepts_a_gateway_token() {
        let keys = keys();
        let token = token(
            &keys,
            &claims(ExtensionCallerKind::Gateway, None),
            Some(EXTENSION_JWT_TYP),
            Some("kid-1"),
        );
        assert!(verifier(&keys).verify(Some(&bearer(&token))).is_ok());
    }

    #[test]
    fn refuses_missing_and_malformed_tokens() {
        let keys = keys();
        let verifier = verifier(&keys);
        assert_eq!(verifier.verify(None), Err(TokenError::Missing));
        assert_eq!(verifier.verify(Some("Basic abc")), Err(TokenError::Missing));
        assert_eq!(verifier.verify(Some("Bearer ")), Err(TokenError::Missing));
        assert_eq!(
            verifier.verify(Some("Bearer not.a.token")),
            Err(TokenError::Header)
        );
    }

    #[test]
    fn refuses_a_token_without_the_extension_type() {
        let keys = keys();
        let untyped = token(
            &keys,
            &claims(ExtensionCallerKind::Gateway, None),
            None,
            Some("kid-1"),
        );
        let bootstrap = token(
            &keys,
            &claims(ExtensionCallerKind::Gateway, None),
            Some("JWT"),
            Some("kid-1"),
        );
        assert_eq!(
            verifier(&keys).verify(Some(&bearer(&untyped))),
            Err(TokenError::Kind)
        );
        assert_eq!(
            verifier(&keys).verify(Some(&bearer(&bootstrap))),
            Err(TokenError::Kind)
        );
    }

    #[test]
    fn refuses_another_key_id_and_another_key() {
        let keys = keys();
        let other_kid = token(
            &keys,
            &claims(ExtensionCallerKind::Gateway, None),
            Some(EXTENSION_JWT_TYP),
            Some("kid-2"),
        );
        assert_eq!(
            verifier(&keys).verify(Some(&bearer(&other_kid))),
            Err(TokenError::KeyId)
        );
        let other_keys = self::keys();
        let forged = token(
            &other_keys,
            &claims(ExtensionCallerKind::Gateway, None),
            Some(EXTENSION_JWT_TYP),
            Some("kid-1"),
        );
        assert_eq!(
            verifier(&keys).verify(Some(&bearer(&forged))),
            Err(TokenError::Claims)
        );
    }

    #[test]
    fn refuses_wrong_audience_issuer_and_expired_tokens() {
        let keys = keys();
        let verifier = verifier(&keys);
        let mut wrong_audience = claims(ExtensionCallerKind::Gateway, None);
        wrong_audience.aud = "urn:openshell:extension:interceptor:other".to_string();
        let mut wrong_issuer = claims(ExtensionCallerKind::Gateway, None);
        wrong_issuer.iss = "openshell-gateway:other".to_string();
        wrong_issuer.sub = wrong_issuer.iss.clone();
        let mut expired = claims(ExtensionCallerKind::Gateway, None);
        expired.iat = now() - 7200;
        expired.exp = now() - 3600;
        for claims in [wrong_audience, wrong_issuer, expired] {
            let token = token(&keys, &claims, Some(EXTENSION_JWT_TYP), Some("kid-1"));
            assert_eq!(
                verifier.verify(Some(&bearer(&token))),
                Err(TokenError::Claims)
            );
        }
    }

    #[test]
    fn refuses_supervisor_tokens_and_other_subjects() {
        let keys = keys();
        let verifier = verifier(&keys);
        let supervisor = claims(ExtensionCallerKind::Supervisor, Some("sandbox-1"));
        let mut gateway_with_sandbox = claims(ExtensionCallerKind::Gateway, None);
        gateway_with_sandbox.sandbox_id = Some("sandbox-1".to_string());
        let mut other_subject = claims(ExtensionCallerKind::Gateway, None);
        other_subject.sub = "someone".to_string();
        for claims in [supervisor, gateway_with_sandbox, other_subject] {
            let token = token(&keys, &claims, Some(EXTENSION_JWT_TYP), Some("kid-1"));
            assert_eq!(
                verifier.verify(Some(&bearer(&token))),
                Err(TokenError::Caller)
            );
        }
    }

    #[test]
    fn refuses_a_token_longer_than_the_extension_limit() {
        let keys = keys();
        let mut long = claims(ExtensionCallerKind::Gateway, None);
        long.exp = long.iat + 2 * 3600;
        let token = token(&keys, &long, Some(EXTENSION_JWT_TYP), Some("kid-1"));
        assert_eq!(
            verifier(&keys).verify(Some(&bearer(&token))),
            Err(TokenError::Lifetime)
        );
    }
}
