package com.forgerock.sapi.gateway.framework.trusteddirectory

import com.forgerock.sapi.gateway.framework.apiclient.ApiClientRegistrationConfig
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server

interface SoftwareStatementProvider {

    fun getSoftwareStatementAssertion(
        apiClientRegistrationConfig: ApiClientRegistrationConfig,
        oauth2Server: OAuth2Server,
        directorySsaUrl: String,
        scopesToAccessSsa: String
    ): String
}