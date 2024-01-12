package com.example.authserver

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator

fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
    var clientPrincipal: OAuth2ClientAuthenticationToken? = null
    if (OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(
            authentication.principal.javaClass
        )
    ) {
        clientPrincipal = authentication.principal as OAuth2ClientAuthenticationToken
    }
    if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
        return clientPrincipal
    }
    throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
}

fun createTokenContext(
    tokenType: OAuth2TokenType,
    registeredClient: RegisteredClient,
    clientPrincipal: Authentication,
    authentication: OAuth2AuthorizationGrantAuthenticationToken,
): OAuth2TokenContext = DefaultOAuth2TokenContext.builder()
        .registeredClient(registeredClient)
        .principal(clientPrincipal)
        .authorizationServerContext(AuthorizationServerContextHolder.getContext())
        .tokenType(tokenType)
        .authorizationGrantType(authentication.grantType)
        .authorizationGrant(authentication)
        .build()

fun generateJwtToken(
    tokenType: OAuth2TokenType,
    registeredClient: RegisteredClient,
    clientPrincipal: Authentication,
    authentication: OAuth2AuthorizationGrantAuthenticationToken,
    tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>
): Jwt {
    val tokenContext = createTokenContext(
        tokenType,
        registeredClient,
        clientPrincipal,
        authentication,
    )

    return tokenGenerator.generate(tokenContext) as Jwt?
        ?: throw OAuth2AuthenticationException(
            OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the refresh token.", null
            )
        )
}

fun generateAccessToken(
    registeredClient: RegisteredClient,
    clientPrincipal: Authentication,
    authentication: OAuth2AuthorizationGrantAuthenticationToken,
    tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>
): Pair<Jwt, OAuth2AccessToken> {
    val jwtToken = generateJwtToken(
        OAuth2TokenType.ACCESS_TOKEN,
        registeredClient,
        clientPrincipal,
        authentication,
        tokenGenerator,
    )

    val oauth2Token = OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER,
        jwtToken.tokenValue,
        jwtToken.issuedAt,
        jwtToken.expiresAt,
        null
    )

    return Pair(jwtToken, oauth2Token)
}

fun generateRefreshToken(
    registeredClient: RegisteredClient,
    clientPrincipal: Authentication,
    authentication: OAuth2AuthorizationGrantAuthenticationToken,
    tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>
): Pair<Jwt, OAuth2RefreshToken> {
    val jwtToken = generateJwtToken(
        OAuth2TokenType.REFRESH_TOKEN,
        registeredClient,
        clientPrincipal,
        authentication,
        tokenGenerator,
    )

    val oauth2Token = OAuth2RefreshToken(
        jwtToken.tokenValue,
        jwtToken.issuedAt,
        jwtToken.expiresAt
    )

    return Pair(jwtToken, oauth2Token)
}
