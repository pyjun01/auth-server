package com.example.authserver

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.ClaimAccessor
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator

class OtpCodeGrantAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>,
): AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val otpCodeGrantAuthentication = authentication as OtpCodeGrantAuthenticationToken

        // Ensure the client is authenticated
        val clientPrincipal: OAuth2ClientAuthenticationToken = getAuthenticatedClientElseThrowInvalidClient(otpCodeGrantAuthentication)
        val registeredClient = clientPrincipal.registeredClient!!

        // Ensure the client is configured to use this authorization grant type
        if (registeredClient?.authorizationGrantTypes?.contains(otpCodeGrantAuthentication.grantType) == false) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        }

        // validation
        val customUser = UserData().mapper[otpCodeGrantAuthentication.phoneNumber]
        if (customUser == null || customUser.code != otpCodeGrantAuthentication.code) {
            throw BadCredentialsException("OtpCodeGranter grant failed")
        }
        val user = customUser.user

//        val user = externalAuthUserService.loadUserByAppAuthenticationToken(
//            DriverAppAuthenticationInfo(
//                DriverIdentifierType.PHONE,
//                otpCodeGrantAuthentication.phoneNumber
//            )
//        )

        val authentication = UsernamePasswordAuthenticationToken(user, null, user.authorities)

        val (generatedAccessToken, accessToken) = generateAccessToken(
            registeredClient,
            authentication,
            otpCodeGrantAuthentication,
            tokenGenerator,
        )
        val (generatedRefreshToken, refreshToken) = generateRefreshToken(
            registeredClient,
            authentication,
            otpCodeGrantAuthentication,
            tokenGenerator,
        )

        // Initialize the OAuth2Authorization
        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(clientPrincipal.name)
            .authorizationGrantType(otpCodeGrantAuthentication.grantType)

        authorizationBuilder.token(accessToken) { metadata: MutableMap<String?, Any?> ->
            if (generatedAccessToken.claims.isNotEmpty()) {
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
                    (generatedAccessToken as ClaimAccessor).claims
            }
        }
        authorizationBuilder.token(refreshToken) { metadata: MutableMap<String?, Any?> ->
            if (generatedRefreshToken.claims.isNotEmpty()) {
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
                    (generatedRefreshToken as ClaimAccessor).claims
            }
        }

        val authorization = authorizationBuilder.build()

        // Save the OAuth2Authorization
        authorizationService.save(authorization)

        return OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken)
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return OtpCodeGrantAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}
