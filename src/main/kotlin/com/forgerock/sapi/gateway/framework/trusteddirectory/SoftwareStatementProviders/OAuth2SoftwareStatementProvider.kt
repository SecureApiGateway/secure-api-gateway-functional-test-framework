package com.forgerock.sapi.gateway.framework.trusteddirectory.SoftwareStatementProviders

import com.forgerock.sapi.gateway.common.constants.OAuth2TokenClientAssertionTypes.Companion.CLIENT_ASSERTION_TYPE_JWT_BEARER
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenGrantTypes.Companion.CLIENT_CREDENTIALS
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.CLIENT_ASSERTION
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.CLIENT_ASSERTION_TYPE
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.GRANT_TYPE
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.SCOPE
import com.forgerock.sapi.gateway.framework.apiclient.ApiClientRegistrationConfig
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.oauth.TokenEndpointAuthMethod
import com.forgerock.sapi.gateway.framework.trusteddirectory.SoftwareStatementProvider
import com.forgerock.sapi.gateway.framework.utils.KeyUtils
import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID

class OAuth2SoftwareStatementProvider : SoftwareStatementProvider {

    override fun getSoftwareStatementAssertion(
        apiClientRegistrationConfig: ApiClientRegistrationConfig,
        oauth2Server: OAuth2Server,
        directorySsaUrl: String,
        scopesToAccessSsa: String
    ): String {
        val fuelManager = getFuelManager(apiClientRegistrationConfig.socketFactory)
        val accessToken = getSoftwareStatementProviderAccessToken(oauth2Server, apiClientRegistrationConfig, scopesToAccessSsa, fuelManager)

        val (_, certResult, r) = fuelManager.get(directorySsaUrl)
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
    private fun getSoftwareStatementProviderAccessToken(oauth2Server: OAuth2Server, apiClient: ApiClientRegistrationConfig, scopes: String, fuelManager: FuelManager): AccessToken {
        val oidcWellKnown = oauth2Server.oidcWellKnown
        if (oidcWellKnown.tokenEndpointAuthMethodsSupported.contains(TokenEndpointAuthMethod.private_key_jwt)) {

            val expTime = KeyUtils.getExpirationDateMinsInFuture(3L)
            val jwtClaimsBuilder = JWTClaimsSet.Builder()
                .audience(oidcWellKnown.tokenEndpoint)
                .expirationTime(expTime)
                .issueTime(Date())
                .jwtID(UUID.randomUUID().toString())
                .issuer(apiClient.softwareId)
                .subject(apiClient.softwareId)

            val jwtClaims = jwtClaimsBuilder.build()

            val jwsHeader = JWSHeader.Builder(JWSAlgorithm.PS256)
                .keyID(apiClient.signingKeys.keyID)
                .type(JOSEObjectType.JWT)
                .build()
            val signedJWT = SignedJWT(jwsHeader, jwtClaims)
            signedJWT.sign(
                RSASSASigner(apiClient.signingKeys.privateKey)
            )
            println("signed jwt is ${signedJWT.serialize()}")

            val parameters = mutableListOf(
                CLIENT_ASSERTION_TYPE to CLIENT_ASSERTION_TYPE_JWT_BEARER,
                GRANT_TYPE to CLIENT_CREDENTIALS,
                CLIENT_ASSERTION to signedJWT.serialize(),
                SCOPE to scopes
            )

            val (_, certResult, r) = fuelManager.post(
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