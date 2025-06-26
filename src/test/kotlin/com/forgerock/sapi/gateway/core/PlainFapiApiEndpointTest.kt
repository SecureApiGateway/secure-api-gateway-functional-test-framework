package com.forgerock.sapi.gateway.core

import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.isEqualTo
import assertk.assertions.isTrue
import assertk.fail
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.forgerock.sapi.gateway.common.constants.OAuth2AuthorizeRequestJwtClaims
import com.forgerock.sapi.gateway.common.constants.OAuth2Constants
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.apiUnderTest
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.data.RequestParameters
import com.forgerock.sapi.gateway.framework.fapi.PLAIN_FAPI_ACR_CLAIM
import com.forgerock.sapi.gateway.framework.oauth.OAuth2ErrorResponse
import com.forgerock.sapi.gateway.framework.utils.GsonUtils
import com.forgerock.sapi.gateway.framework.utils.MultipleApiClientTest
import com.github.kittinunf.fuel.core.Headers
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.util.JSONObjectUtils
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.UUID

/**
 * Tests for the SAPI-G core Plain FAPI API endpoint (/rs/fapi/api).
 */
class PlainFapiApiEndpointTest : MultipleApiClientTest() {

    private val plainFapiEndpointUrl = apiUnderTest.getEndpointUrl("plainFapiEndpoint")
    private val objectMapper = ObjectMapper().registerModule(
        KotlinModule.Builder().build()
    )

    @BeforeEach
    fun beforeEach() {
    }

    @ParameterizedTest
    @MethodSource("getApiClients")
    fun successApiClientsDoPlainFapi(apiClient: ApiClient) {
        val accessToken = getAuthorizationCodeAccessToken(apiClient)

        val (_, response, result) = apiClient.fuelManager.get(plainFapiEndpointUrl)
            .header(Headers.AUTHORIZATION, "Bearer ${accessToken.access_token}").responseString()

        assertThat(response.isSuccessful).isTrue()
        assertThat(result.get()).contains("user")
    }

    private fun getAuthorizationCodeAccessToken(
        apiClient: ApiClient
    ): AccessToken {
        val scopes = "openid accounts"
        val resourceOwner = apiUnderTest.resourceOwners[0]
        val responseTypes = "code id_token"
        val additionalClaims: List<Pair<String, Any>> = getPlainFapiClaims()
        val accessToken = apiUnderTest.oauth2Server.getAuthorizationCodeAccessToken(
            apiClient,
            apiUnderTest,
            scopes,
            resourceOwner,
            responseTypes,
            additionalClaims
        )
        return accessToken
    }

    @Test
    fun failsToAccessProtectedEndpointWhenNoAccessTokenProvided() {
        val apiClient = getApiClients().first()

        val (_, response, _) = apiClient.fuelManager.get(plainFapiEndpointUrl).responseString()
        assertThat(response.statusCode).isEqualTo(401)
    }

    @Test
    fun failsToAccessProtectedEndpointWhenInvalidAccessTokenProvided() {
        val apiClient = getApiClients().first()

        val (_, response, _) = apiClient.fuelManager.get(plainFapiEndpointUrl)
            .header("Authorization", "Bearer invalid")
            .responseString()

        assertThat(response.statusCode).isEqualTo(401)
    }

    @Test
    fun failsToAccessProtectedEndpointWhenClientCredentialsAccessTokenProvided() {
        val apiClient = getApiClients().first()

        val clientCredentialsAccessToken = apiUnderTest.oauth2Server.getClientCredentialsAccessToken(apiClient, "openid accounts")
        val (_, response, _) = apiClient.fuelManager.get(plainFapiEndpointUrl)
            .header("Authorization", "Bearer ${clientCredentialsAccessToken.access_token}")
            .responseString()

        assertThat(response.statusCode).isEqualTo(401)
        val responseJson = response.body().asString("application/json")
        val errorResponse = objectMapper.readValue(responseJson, OAuth2ErrorResponse::class.java)
        assertThat(errorResponse.error).isEqualTo("invalid_grant")
        var errorDescription: CharSequence = ""
        errorResponse.errorDescription?.let {
            errorDescription = it
        }
        assertThat(errorDescription).contains("Token grant type must be: ", ignoreCase = true)
        assertThat(errorDescription).contains("authorization_code", ignoreCase = false)
        assertThat(errorDescription).contains("refresh_token", ignoreCase = false)
    }

    @Test
    fun failsWhenDifferentClientTriesToUseAccessToken() {
        val client1 = getApiClients()[0]
        val client2 = getApiClients()[1]

        val accessTokenForClient1 = getAuthorizationCodeAccessToken(client1)

        // Validate that client1 can access the resource
        val (_, response1, result1) = client1.fuelManager.get(plainFapiEndpointUrl)
            .header(Headers.AUTHORIZATION, "Bearer ${accessTokenForClient1.access_token}").responseString()
        assertThat(response1.isSuccessful).isTrue()
        assertThat(result1.get()).contains("user")

        // Validate that client2 cannot access the resource using client1's token
        val (_, response2, _) = client2.fuelManager.get(plainFapiEndpointUrl)
            .header(Headers.AUTHORIZATION, "Bearer ${accessTokenForClient1.access_token}").responseString()
        assertThat(response2.statusCode).isEqualTo(401)
    }

    private fun getPlainFapiClaims(): List<Pair<String, Any>> {
        val idToken = RequestParameters.Claims.IdToken(
            RequestParameters.Claims.IdToken.Acr(true, PLAIN_FAPI_ACR_CLAIM), null
        )

        val claims = RequestParameters.Claims(idToken, null)
        val jsonClaims = JSONObjectUtils.parse(GsonUtils.gson.toJson(claims))
        val claimPair = Pair(OAuth2AuthorizeRequestJwtClaims.CLAIMS, jsonClaims)
        val nonce = Pair(OAuth2Constants.NONCE, UUID.randomUUID().toString())
        val state = Pair(OAuth2Constants.STATE, UUID.randomUUID().toString())
        return listOf(claimPair, nonce, state)
    }

}