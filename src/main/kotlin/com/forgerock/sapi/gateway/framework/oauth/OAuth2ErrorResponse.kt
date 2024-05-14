package com.forgerock.sapi.gateway.framework.oauth

import com.fasterxml.jackson.annotation.JsonProperty

data class OAuth2ErrorResponse(
    val error: String?,
    @JsonProperty("error_description")
    val errorDescription: String?
)