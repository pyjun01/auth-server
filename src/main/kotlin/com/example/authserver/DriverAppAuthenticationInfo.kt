package com.example.authserver

data class DriverAppAuthenticationInfo(
    val type: DriverIdentifierType,
    val identifier: String
)
