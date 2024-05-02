package com.forgerock.sapi.gateway.framework.trusteddirectory.SoftwareStatementProviders

import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.trusteddirectory.SoftwareStatementProvider
import com.github.kittinunf.fuel.core.isSuccessful

class OAuth2SoftwareStatementProvider : SoftwareStatementProvider {

    override fun getSoftwareStatementAssertion(
        apiClient: ApiClient,
        oauth2Server: OAuth2Server,
        directorySsaUrl: String,
        scopesToAccessSsa: String
    ): String {
        val accessToken = oauth2Server.getAccessToken(apiClient, scopesToAccessSsa)

        val (_, certResult, r) = apiClient.fuelManager.get(directorySsaUrl)
            .header("Accept", "application/jws+json")
            .header("Authorization", "Bearer ${accessToken.access_token}")
            .responseString()
        if (!certResult.isSuccessful) throw AssertionError(
            "Could not get requested SSA data from ${directorySsaUrl}: ${
                String(
                    certResult.data
                )
            }", r.component2()
        )
        return r.get()
    }
}