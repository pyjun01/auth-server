package com.example.authserver

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

enum class DriverIdentifierType(@get:JsonValue val value: String) {
    PHONE("phone"),
    ;

    companion object {
        private val map = values().associateBy(DriverIdentifierType::value)

        @JsonCreator
        @JvmStatic
        fun fromValue(value: String) = map.getOrDefault(value, PHONE)
    }
}
