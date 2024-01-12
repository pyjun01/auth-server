package com.example.authserver

import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails

data class CustomUser(
    val phoneNumber: String,
    val code: String,
    val user: UserDetails,
)

@Configuration
class UserData {
    val mapper = mapOf<String, CustomUser>(
        Pair("01012341234", CustomUser(
            "01012341234",
            "000000",
            User.builder()
                .username("01012341234")
                .password("")
                .roles("DRIVER")
                .build()
        )),
        Pair("01099999999", CustomUser(
            "01099999999",
            "111111",
            User.builder()
                .username("01099999999")
                .password("")
                .roles("DRIVER")
                .build()
        )),
    )
}
