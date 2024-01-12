package com.example.authserver

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.ClaimAccessor
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator

class OtpCodeGrantAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>,
): AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val customCodeGrantAuthentication = authentication as OtpCodeGrantAuthenticationToken

        // Ensure the client is authenticated
        val clientPrincipal: OAuth2ClientAuthenticationToken = getAuthenticatedClientElseThrowInvalidClient(customCodeGrantAuthentication)
        val registeredClient = clientPrincipal.registeredClient!!

        // Ensure the client is configured to use this authorization grant type
        if (registeredClient?.authorizationGrantTypes?.contains(customCodeGrantAuthentication.grantType) == false) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        }

        // validation
        if (customCodeGrantAuthentication.code != "ABCDEF") {
            throw BadCredentialsException("OtpCodeGranter grant failed")
        }

        val (generatedAccessToken, accessToken) = generateAccessToken(
            registeredClient,
            clientPrincipal,
            customCodeGrantAuthentication,
        )
        val (generatedRefreshToken, refreshToken) = generateRefreshToken(
            registeredClient,
            clientPrincipal,
            customCodeGrantAuthentication,
        )

        // Initialize the OAuth2Authorization
        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(clientPrincipal.name)
            .authorizationGrantType(customCodeGrantAuthentication.grantType)

        if (generatedAccessToken is ClaimAccessor) {
            authorizationBuilder.token(accessToken) { metadata: MutableMap<String?, Any?> ->
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
                    (generatedAccessToken as ClaimAccessor).claims
            }
        } else {
            authorizationBuilder.accessToken(accessToken)
        }
        authorizationBuilder.refreshToken(refreshToken)

        val authorization = authorizationBuilder.build()

        // Save the OAuth2Authorization
        authorizationService.save(authorization)

        return OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken)
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return OtpCodeGrantAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    private fun generateAccessToken(
        registeredClient: RegisteredClient,
        clientPrincipal: Authentication,
        customCodeGrantAuthentication: OtpCodeGrantAuthenticationToken,
    ): Pair<Jwt, OAuth2AccessToken> {
        // Generate the access token
        val tokenContext: OAuth2TokenContext = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(customCodeGrantAuthentication.grantType)
            .authorizationGrant(customCodeGrantAuthentication)
            .build()

        val jwtAccessToken = tokenGenerator.generate(tokenContext) as Jwt

        if (jwtAccessToken == null) {
            val error = OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the access token.", null
            )
            throw OAuth2AuthenticationException(error)
        }

        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            jwtAccessToken.tokenValue,
            jwtAccessToken.issuedAt,
            jwtAccessToken.expiresAt,
            null
        )

        return Pair(jwtAccessToken, accessToken)
    }

    private fun generateRefreshToken(
        registeredClient: RegisteredClient,
        clientPrincipal: Authentication,
        customCodeGrantAuthentication: OtpCodeGrantAuthenticationToken,
    ): Pair<OAuth2Token, OAuth2RefreshToken> {
        // Refresh 토큰 컨텍스트 설정
        val refreshTokenContext: OAuth2TokenContext = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(OAuth2TokenType.REFRESH_TOKEN) // Refresh 토큰 유형 설정
            .authorizationGrantType(customCodeGrantAuthentication.grantType)
            .authorizationGrant(customCodeGrantAuthentication)
            .build()

        // Refresh 토큰 생성
        val generatedRefreshToken = tokenGenerator.generate(refreshTokenContext)

        if (generatedRefreshToken == null) {
            val error = OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the refresh token.", null
            )
            throw OAuth2AuthenticationException(error)
        }

        val refreshToken = OAuth2RefreshToken(
            generatedRefreshToken.tokenValue,
            generatedRefreshToken.issuedAt,
            generatedRefreshToken.expiresAt
        )

        return Pair(generatedRefreshToken, refreshToken)
    }

    private fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
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
}
