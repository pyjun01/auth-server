package com.example.authserver

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("oauth2")
data class OAuth2ClientConfig(
    val clients: List<OAuth2Client>
) {
    data class OAuth2Client(
        val appId: String,
        val secret: String,
        val authority: String,
        val accessTokenExpires: Int = 3600 * 24 * 14, // 2 weeks
        val refreshTokenExpires: Int = 3600 * 24 * 90 // 90 days
    )
}
