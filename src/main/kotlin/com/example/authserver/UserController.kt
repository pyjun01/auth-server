package com.example.authserver

import java.security.InvalidParameterException
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RequestMapping("/v1/users")
@RestController
class UserController(
    private val userData: UserData,
) {
    data class OtpResponse(
        val code: String,
    )
    @GetMapping("/otp")
    fun getOtp(@RequestParam phoneNumber: String): OtpResponse =
        OtpResponse(userData.mapper[phoneNumber]?.let { it.code } ?: throw InvalidParameterException())

    data class UserInfoResponse(
        val id: String,
    )
    @GetMapping("/me")
    fun getMyInfo(client: Authentication): UserInfoResponse =
        UserInfoResponse(client.name)
}
