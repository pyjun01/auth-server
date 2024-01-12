package com.example.authserver

import org.springframework.core.convert.converter.Converter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.util.Assert


class JwtScopeAndPermissionGrantedAuthoritiesConverter : Converter<Jwt, Collection<GrantedAuthority>> {
    private var authorityPrefix = SCOPE_AUTHORITY_PREFIX
    private var authoritiesClaimName: String? = null

    override fun convert(jwt: Jwt): Collection<GrantedAuthority> {
        val grantedAuthorities: MutableCollection<GrantedAuthority> = ArrayList()

        for (authority in getPermissionAuthorities(jwt)) {
            grantedAuthorities.add(SimpleGrantedAuthority(authority))
        }

        for (authority in getScopeAuthorities(jwt)) {
            grantedAuthorities.add(SimpleGrantedAuthority(authorityPrefix + authority))
        }

        return grantedAuthorities
    }

    private fun getScopeAuthoritiesClaimName(jwt: Jwt): String? {
        if (authoritiesClaimName != null) {
            return authoritiesClaimName
        }
        for (claimName in WELL_KNOWN_SCOPE_AUTHORITIES_CLAIM_NAMES) {
            if (jwt.hasClaim(claimName)) {
                return claimName
            }
        }
        return null
    }

    private fun getScopeAuthorities(jwt: Jwt): Collection<String> {
        val claimName = getScopeAuthoritiesClaimName(jwt) ?: return emptyList()
        val authorities = jwt.getClaim<Any>(claimName)
        if (authorities is String) {
            return if (authorities.isNotBlank()) {
                listOf(*authorities.split(" ").toTypedArray())
            } else {
                emptyList()
            }
        } else if (authorities is Collection<*>) {
            @Suppress("UNCHECKED_CAST")
            return authorities as Collection<String>
        }
        return emptyList()
    }

    private fun getPermissionAuthoritiesClaimName(jwt: Jwt): String? {
        for (claimName in WELL_KNOWN_PERMISSION_AUTHORITIES_CLAIM_NAMES) {
            if (jwt.hasClaim(claimName)) {
                return claimName
            }
        }
        return null
    }

    private fun getPermissionAuthorities(jwt: Jwt): Collection<String> {
        val claimName = getPermissionAuthoritiesClaimName(jwt) ?: return emptyList()
        val authorities = jwt.getClaim<Any>(claimName)
        if (authorities is String) {
            return if (authorities.isNotBlank()) {
                listOf(*authorities.split(" ").toTypedArray())
            } else {
                emptyList()
            }
        } else if (authorities is Collection<*>) {
            @Suppress("UNCHECKED_CAST")
            return authorities as Collection<String>
        }
        return emptyList()
    }

    companion object {
        private const val SCOPE_AUTHORITY_PREFIX = "SCOPE_"
        private val WELL_KNOWN_SCOPE_AUTHORITIES_CLAIM_NAMES: Collection<String> = listOf("scope", "scp")
        private val WELL_KNOWN_PERMISSION_AUTHORITIES_CLAIM_NAMES: Collection<String> = listOf("authorities")
    }
}
