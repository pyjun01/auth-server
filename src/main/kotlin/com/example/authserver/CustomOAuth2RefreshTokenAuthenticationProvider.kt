package com.example.authserver

import java.security.Principal
import org.apache.commons.logging.LogFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClaimAccessor
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.util.Assert

/**
 * OAuth2RefreshTokenAuthenticationProvider 커스텀 버전
 */
class CustomOAuth2RefreshTokenAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val refreshTokenAuthentication = authentication as OAuth2RefreshTokenAuthenticationToken

        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(refreshTokenAuthentication)
        val registeredClient = clientPrincipal.registeredClient
        var authorization = authorizationService.findByToken(
            refreshTokenAuthentication.refreshToken, OAuth2TokenType.REFRESH_TOKEN
        ) ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)

        if (registeredClient!!.id != authorization.registeredClientId) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)
        }

        if (!registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        }

        val refreshToken = authorization.refreshToken

        if (refreshToken?.isActive == false) {
            // As per https://tools.ietf.org/html/rfc6749#section-5.2
            // invalid_grant: The provided authorization grant (e.g., authorization code,
            // resource owner credentials) or refresh token is invalid, expired, revoked [...].
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)
        }

        // As per https://tools.ietf.org/html/rfc6749#section-6
        // The requested scope MUST NOT include any scope not originally granted by the resource owner,
        // and if omitted is treated as equal to the scope originally granted by the resource owner.
        var scopes = refreshTokenAuthentication.scopes
        val authorizedScopes = authorization.authorizedScopes
        if (!authorizedScopes.containsAll(scopes)) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE)
        }

        if (scopes.isEmpty()) {
            scopes = authorizedScopes
        }

        val (generatedAccessToken, accessToken) = generateAccessToken(
            registeredClient,
            clientPrincipal,
            refreshTokenAuthentication,
        )

        // Initialize the OAuth2Authorization
        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(clientPrincipal.name)
            .authorizationGrantType(refreshTokenAuthentication.grantType)

        if (generatedAccessToken is ClaimAccessor) {
            authorizationBuilder.token(accessToken) { metadata: MutableMap<String?, Any?> ->
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
                    (generatedAccessToken as ClaimAccessor).claims
            }
        } else {
            authorizationBuilder.accessToken(accessToken)
        }

        // ----- Refresh token -----
        var currentRefreshToken = refreshToken?.token
        if (!registeredClient.tokenSettings.isReuseRefreshTokens) {
            val (generatedRefreshToken, refreshToken) = generateRefreshToken(
                registeredClient,
                clientPrincipal,
                refreshTokenAuthentication,
            )

            currentRefreshToken = refreshToken
            authorizationBuilder.refreshToken(currentRefreshToken)
        }

        authorization = authorizationBuilder.build()
        authorizationService.save(authorization)

        var additionalParameters: Map<String?, Any?> = emptyMap<String?, Any>()

        return OAuth2AccessTokenAuthenticationToken(
            registeredClient, clientPrincipal, accessToken, currentRefreshToken, additionalParameters
        )
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return OAuth2RefreshTokenAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    private fun generateAccessToken(
        registeredClient: RegisteredClient,
        clientPrincipal: Authentication,
        refreshTokenAuthentication: OAuth2RefreshTokenAuthenticationToken,
    ): Pair<Jwt, OAuth2AccessToken> {
        // Generate the access token
        val tokenContext: OAuth2TokenContext = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(refreshTokenAuthentication.grantType)
            .authorizationGrant(refreshTokenAuthentication)
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
        refreshTokenAuthentication: OAuth2RefreshTokenAuthenticationToken,
    ): Pair<OAuth2Token, OAuth2RefreshToken> {
        // Refresh 토큰 컨텍스트 설정
        val refreshTokenContext: OAuth2TokenContext = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(OAuth2TokenType.REFRESH_TOKEN) // Refresh 토큰 유형 설정
            .authorizationGrantType(refreshTokenAuthentication.grantType)
            .authorizationGrant(refreshTokenAuthentication)
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

    companion object {
        private const val ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
        private val ID_TOKEN_TOKEN_TYPE = OAuth2TokenType(OidcParameterNames.ID_TOKEN)
    }
}
