package com.example.authserver

import java.security.Principal
import org.apache.commons.logging.LogFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
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
import org.springframework.security.oauth2.jwt.JwtClaimNames
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
        // AuthorizationService에서 Authorization 찾아오기
        var authorization = authorizationService.findByToken(
            refreshTokenAuthentication.refreshToken, OAuth2TokenType.REFRESH_TOKEN
        ) ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)
        // Token<OAuth2Autorization>
        val refreshToken = authorization.refreshToken ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)
        // sub id
        val id = (refreshToken.metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] as Map<String?, Any?>?)?.get(JwtClaimNames.SUB) as String? ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR)
        val user = UserData().mapper[id]?.user ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR)

        if (registeredClient!!.id != authorization.registeredClientId) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)
        } else if (!registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        } else if (!refreshToken.isActive || !UserData().mapper.contains(id)) {
            // As per https://tools.ietf.org/html/rfc6749#section-5.2
            // invalid_grant: The provided authorization grant (e.g., authorization code,
            // resource owner credentials) or refresh token is invalid, expired, revoked [...].
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)
        }

        val authentication = UsernamePasswordAuthenticationToken(user, null, user.authorities)

        val (generatedAccessToken, accessToken) = generateAccessToken(
            registeredClient,
            authentication,
            refreshTokenAuthentication,
            tokenGenerator,
        )

        // ----- Refresh token -----
        var currentRefreshToken = refreshToken.token
        if (!registeredClient.tokenSettings.isReuseRefreshTokens) {
            currentRefreshToken = generateRefreshToken(
                registeredClient,
                authentication,
                refreshTokenAuthentication,
                tokenGenerator,
            ).second
        }

        // Initialize the OAuth2Authorization
        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(authentication.name)
            .authorizationGrantType(refreshTokenAuthentication.grantType)

        authorizationBuilder.token(accessToken) { metadata: MutableMap<String?, Any?> ->
            if (generatedAccessToken.claims.isNotEmpty()) {
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
                    (generatedAccessToken as ClaimAccessor).claims
            }
        }
        authorizationBuilder.token(currentRefreshToken) { metadata: MutableMap<String?, Any?> ->
            metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
                refreshToken.metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME]
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
}
