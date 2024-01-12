package com.example.authserver

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType

import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken

class OtpCodeGrantAuthenticationToken(
    val phoneNumber: String,
    val code: String,
    clientPrincipal: Authentication,
    additionalParameters: Map<String, Any?>?
): OAuth2AuthorizationGrantAuthenticationToken(
    AuthorizationGrantType("otp"),
    clientPrincipal,
    additionalParameters,
) {
}
