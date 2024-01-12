package com.example.authserver

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RequestMapping("/v1/users")
@RestController
class UserController {
    data class OtpResponse(
        val code: String,
    )
    @GetMapping("/otp")
    fun getOtp(): OtpResponse =
        OtpResponse("ABCDEF")

    data class UserInfoResponse(
        val id: String,
    )
    @GetMapping("/me")
    fun getMyInfo(): UserInfoResponse =
        UserInfoResponse("Justin")
}
