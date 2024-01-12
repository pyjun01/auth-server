package com.example.authserver

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component

class OtpCodeGrantAuthenticationConverter: AuthenticationConverter {
    override fun convert(request: HttpServletRequest): Authentication? {
        // grant_type
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if ("otp" != grantType) {
            return null;
        }

        val clientPrincipal = SecurityContextHolder.getContext().authentication

        val parameters = request.parameterMap

        // code (REQUIRED)
        val phoneNumber = parameters["phoneNumber"]?.get(0)
        val code = parameters["code"]?.get(0)
        if (phoneNumber.isNullOrBlank() || code.isNullOrBlank()) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        val additionalParameters = hashMapOf<String, Any>()

        parameters.forEach { (key, value) ->
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                !key.equals(OAuth2ParameterNames.CODE)
            ) {
                additionalParameters.put(key, value[0]);
            }
        }

        return OtpCodeGrantAuthenticationToken(phoneNumber, code, clientPrincipal, additionalParameters);
    }
}
