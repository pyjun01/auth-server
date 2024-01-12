package com.example.authserver

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationConverter
import kotlin.time.DurationUnit
import kotlin.time.toDuration
import kotlin.time.toJavaDuration


@Configuration
@EnableWebSecurity(debug = true)
class SecurityConfig(
    private val oAuth2ClientConfig: OAuth2ClientConfig,
) {
    @Bean
    fun filterChain(
        http: HttpSecurity,
        registeredClientRepository: RegisteredClientRepository,
        authorizationService: OAuth2AuthorizationService,
        userDetailsService: UserDetailsService,
        tokenGenerator: OAuth2TokenGenerator<OAuth2Token>,
    ): SecurityFilterChain {
//        val tokenGenerator = JwtGenerator(jwtEncoder);
        val otpCodeGrantAuthenticationProvider = OtpCodeGrantAuthenticationProvider(authorizationService, tokenGenerator)
        val customOAuth2RefreshTokenAuthenticationProvider = CustomOAuth2RefreshTokenAuthenticationProvider(authorizationService, tokenGenerator)

        // for authorization server
        OAuth2AuthorizationServerConfigurer()
            .apply { http.with(this, Customizer.withDefaults()) }
            .registeredClientRepository(registeredClientRepository)
            .authorizationService(authorizationService)
            .tokenGenerator(tokenGenerator)
            .tokenEndpoint { tokenEndpoint ->
                tokenEndpoint
                    .accessTokenRequestConverters { accessTokenRequestConverters ->
                        accessTokenRequestConverters.clear()
                        accessTokenRequestConverters.addAll(
                            listOf(
                                OtpCodeGrantAuthenticationConverter(),
                                OAuth2RefreshTokenAuthenticationConverter(),
                            )
                        )
                    }
                    .authenticationProviders { authenticationProviders ->
                        authenticationProviders.clear()
                        authenticationProviders.addAll(
                            listOf(
                                otpCodeGrantAuthenticationProvider,
                                customOAuth2RefreshTokenAuthenticationProvider,
                            )
                        )
                    }
            }

        // for resource server
        http
            .authorizeHttpRequests { auth -> auth
                .requestMatchers("/v1/users/otp").hasAnyAuthority("DRIVER_APP")
                .requestMatchers("/v1/users/me").hasAnyRole("DRIVER")
                .anyRequest().authenticated()
            }
            .authenticationProvider(basicAuthenticationProvider(userDetailsService))
            .authenticationProvider(otpCodeGrantAuthenticationProvider)
            .httpBasic(Customizer.withDefaults())
            .csrf { csrf -> csrf.disable() }
            .formLogin { formLogin -> formLogin.disable() }
            .cors { cors -> cors.disable() }
            .logout { logout -> logout.disable() }
            .anonymous { anonymous -> anonymous.disable() }
            .sessionManagement { sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .oauth2ResourceServer { oauth2 -> oauth2.jwt { jwt -> jwt.jwtAuthenticationConverter(getJwtAuthenticationConverter()) } }

        return http.build()
    }

    fun getJwtAuthenticationConverter(): Converter<Jwt, AbstractAuthenticationToken> {
        val converter = JwtAuthenticationConverter()
        converter.setJwtGrantedAuthoritiesConverter(JwtScopeAndPermissionGrantedAuthoritiesConverter())
        return converter
    }

    /**
     * for http basic
     */
    fun basicAuthenticationProvider(userDetailsService: UserDetailsService): DaoAuthenticationProvider {
        val daoAuthenticationProvider = DaoAuthenticationProvider()
        daoAuthenticationProvider.setUserDetailsService(userDetailsService)

        return daoAuthenticationProvider
    }
    @Bean
    fun userDetailsService(): UserDetailsService {
        val userList = oAuth2ClientConfig.clients.map { client ->
            User.builder()
                .username(client.appId)
                .password("{noop}${client.secret}")
                .authorities(client.authority)
                .build()
        }

        return InMemoryUserDetailsManager(userList)
    }

    /**
     * register oauth2 client
     */
    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val registrations = oAuth2ClientConfig.clients.map { client ->
            RegisteredClient.withId(UUID.randomUUID().toString())
                .clientName(client.appId)
                .clientId(client.appId)
                .clientSecret("{noop}${client.secret}")
                .scope("read")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Authorization: Basic {base64 encoded String}
                .authorizationGrantType(AuthorizationGrantType("otp"))
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(
                    TokenSettings.builder()
                        .accessTokenTimeToLive(client.accessTokenExpires.toDuration(DurationUnit.SECONDS).toJavaDuration())
                        .refreshTokenTimeToLive(client.refreshTokenExpires.toDuration(DurationUnit.SECONDS).toJavaDuration())
                        .reuseRefreshTokens(false)
                        .build()
                )
                .build()
        }.toMutableList()

        return InMemoryRegisteredClientRepository(registrations)
    }

    @Bean
    fun authorizationService(): OAuth2AuthorizationService =
        InMemoryOAuth2AuthorizationService()

    /**
     * jwt 생성에 필요한 RSA키 generate
     */
    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair: KeyPair = generateRsaKey()
        val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
        val privateKey: RSAPrivateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    private fun generateRsaKey(): KeyPair =
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder =
        NimbusJwtEncoder(jwkSource)

    @Bean
    fun tokenGenerator(
        jwtEncoder: JwtEncoder,
    ): OAuth2TokenGenerator<OAuth2Token> {
        val jwtGenerator = CustomJwtGenerator(jwtEncoder) { context ->
            val authentication = context.getPrincipal() as UsernamePasswordAuthenticationToken

            if (authentication !is UsernamePasswordAuthenticationToken) {
                throw OAuth2AuthenticationException(
                    OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR,
                        "Invalid Authorization Type", null
                    )
                )
            }

            val claimsBuilder = context.claims

            claimsBuilder.claims { claims ->
                claims.remove(JwtClaimNames.AUD)
                claims.remove(JwtClaimNames.ISS)
                claims.remove(JwtClaimNames.NBF)
                claims.remove("client_id")
                claims.put(JwtClaimNames.SUB, authentication.name)
                claims.put("authorities", authentication.authorities.toList().map { it.toString() })
            }
        }

        return DelegatingOAuth2TokenGenerator(
            jwtGenerator
        )
    }
}
