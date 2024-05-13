package com.forgerock.sapi.gateway.framework.trusteddirectory.SoftwareStatementProviders

import com.forgerock.sapi.gateway.common.constants.OAuth2TokenClientAssertionTypes.Companion.CLIENT_ASSERTION_TYPE_JWT_BEARER
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenGrantTypes.Companion.CLIENT_CREDENTIALS
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.CLIENT_ASSERTION
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.CLIENT_ASSERTION_TYPE
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.GRANT_TYPE
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.SCOPE
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.oauth.TokenEndpointAuthMethod
import com.forgerock.sapi.gateway.framework.trusteddirectory.SoftwareStatementProvider
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT

class OAuth2SoftwareStatementProvider : SoftwareStatementProvider {

    override fun getSoftwareStatementAssertion(
        apiClient: ApiClient,
        oauth2Server: OAuth2Server,
        directorySsaUrl: String,
        scopesToAccessSsa: String
    ): String {
        val accessToken = getSoftwareStatementProviderAccessToken(oauth2Server, apiClient, scopesToAccessSsa)

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

    // Specialised version of client_credentials flow that works with the Trusted Directory
    private fun getSoftwareStatementProviderAccessToken(oauth2Server: OAuth2Server, apiClient: ApiClient, scopes: String): AccessToken {
        val oidcWellKnown = oauth2Server.oidcWellKnown
        if (oidcWellKnown.tokenEndpointAuthMethodsSupported.contains(TokenEndpointAuthMethod.private_key_jwt)) {

            val jwt: SignedJWT = apiClient.getClientAssertionJwt(
                aud = oidcWellKnown.tokenEndpoint,
                jwsSigningAlgorithm = JWSAlgorithm.PS256 //ToDO: Get supported alg from oidc well known response
            )
            println("signed jwt is ${jwt.serialize()}")

            val parameters = mutableListOf(
                CLIENT_ASSERTION_TYPE to CLIENT_ASSERTION_TYPE_JWT_BEARER,
                GRANT_TYPE to CLIENT_CREDENTIALS,
                CLIENT_ASSERTION to jwt.serialize(),
                SCOPE to scopes
            )

            val (_, certResult, r) = apiClient.fuelManager.post(
                oidcWellKnown.tokenEndpoint, parameters
            ).responseObject<AccessToken>()


            if (!certResult.isSuccessful) throw AssertionError(
                "Could not get requested access token data from ${oidcWellKnown.tokenEndpoint}. x-fapi-interaction-id: ${
                    certResult.headers.get(
                        "x-fapi-interaction-id"
                    )
                } ${
                    String(
                        certResult.data
                    )
                }, Response $r", r.component2()
            )
            return r.get()

        } else {
            throw Exception("OAuth2 server ${oidcWellKnown.issuer} does not support 'private_key_jwt' as a token_endpoint_auth_method")
        }
    }


}