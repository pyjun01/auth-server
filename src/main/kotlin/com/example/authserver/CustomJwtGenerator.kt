package com.example.authserver

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.UUID
import org.springframework.lang.Nullable
import org.springframework.security.core.Authentication
import org.springframework.security.core.session.SessionInformation
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.util.Assert
import org.springframework.util.CollectionUtils
import org.springframework.util.StringUtils


/**
 * JwtGenerator 커스텀 버전
 * :78만 추가함
 */
class CustomJwtGenerator(
    private val jwtEncoder: JwtEncoder
) : OAuth2TokenGenerator<Jwt?> {
    private var jwtCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>? = null

    @Nullable
    override fun generate(context: OAuth2TokenContext): Jwt? {
        if (
            context.tokenType == null ||
            !(OAuth2TokenType.ACCESS_TOKEN == context.tokenType ||
            OAuth2TokenType.REFRESH_TOKEN == context.tokenType)
        ) {
            return null
        }
        if (OAuth2TokenFormat.SELF_CONTAINED != context.registeredClient.tokenSettings.accessTokenFormat) {
            return null
        }

        var issuer: String? = null
        if (context.authorizationServerContext != null) {
            issuer = context.authorizationServerContext.issuer
        }
        val registeredClient = context.registeredClient
        val issuedAt = Instant.now()
        val expiresAt = issuedAt.plus(when(context.tokenType) {
            OAuth2TokenType.REFRESH_TOKEN -> registeredClient.tokenSettings.refreshTokenTimeToLive
            OAuth2TokenType.ACCESS_TOKEN -> registeredClient.tokenSettings.accessTokenTimeToLive
            else -> registeredClient.tokenSettings.accessTokenTimeToLive
        })
        var jwsAlgorithm: JwsAlgorithm? = SignatureAlgorithm.RS256

        val claimsBuilder = JwtClaimsSet.builder()
        if (StringUtils.hasText(issuer)) {
            claimsBuilder.issuer(issuer)
        }
        claimsBuilder
            .subject(context.getPrincipal<Authentication>().name)
            .audience(listOf(registeredClient.clientId))
            .issuedAt(issuedAt)
            .expiresAt(expiresAt)
            .id(UUID.randomUUID().toString())
            // add authorities
            .claim("authorities", listOf<String>("ROLE_DRIVER"))
        claimsBuilder.notBefore(issuedAt)

        if (!CollectionUtils.isEmpty(context.authorizedScopes)) {
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.authorizedScopes)
        }

        val jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm)
        if (jwtCustomizer != null) {
            // @formatter:off
            val jwtContextBuilder = JwtEncodingContext.with(jwsHeaderBuilder, claimsBuilder)
                .registeredClient(context.registeredClient)
                .principal(context.getPrincipal())
                .authorizationServerContext(context.authorizationServerContext)
                .authorizedScopes(context.authorizedScopes)
                .tokenType(context.tokenType)
                .authorizationGrantType(context.authorizationGrantType)
            if (context.authorization != null) {
                jwtContextBuilder.authorization(context.authorization)
            }
            if (context.getAuthorizationGrant<Authentication?>() != null) {
                jwtContextBuilder.authorizationGrant(context.getAuthorizationGrant())
            }
            if (OidcParameterNames.ID_TOKEN == context.tokenType.value) {
                val sessionInformation =
                    context.get(SessionInformation::class.java)
                if (sessionInformation != null) {
                    jwtContextBuilder.put(SessionInformation::class.java, sessionInformation)
                }
            }
            // @formatter:on
            val jwtContext = jwtContextBuilder.build()
            jwtCustomizer!!.customize(jwtContext)
        }
        val jwsHeader = jwsHeaderBuilder.build()
        val claims = claimsBuilder.build()
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims))
    }

    /**
     * Sets the [OAuth2TokenCustomizer] that customizes the
     * [JWS headers][JwtEncodingContext.getJwsHeader] and/or
     * [claims][JwtEncodingContext.getClaims] for the generated [Jwt].
     *
     * @param jwtCustomizer the [OAuth2TokenCustomizer] that customizes the headers and/or claims for the generated `Jwt`
     */
    fun setJwtCustomizer(jwtCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>?) {
        Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null")
        this.jwtCustomizer = jwtCustomizer
    }
}
