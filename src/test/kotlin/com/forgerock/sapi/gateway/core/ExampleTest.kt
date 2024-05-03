package com.forgerock.sapi.gateway.core

import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.isNotNull
import assertk.assertions.isTrue
import com.forgerock.sapi.gateway.common.constants.OAuth2AuthorizeRequestJwtClaims
import com.forgerock.sapi.gateway.common.constants.OAuth2Constants
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager
import com.forgerock.sapi.gateway.framework.data.RequestParameters
import com.forgerock.sapi.gateway.framework.utils.GsonUtils
import com.forgerock.sapi.gateway.framework.utils.MultipleApiClientTest
import com.forgerock.sapi.gateway.ob.uk.framework.constants.PLAIN_FAPI_ACR_CLAIM
import com.github.kittinunf.fuel.core.Headers
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.util.JSONObjectUtils
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.UUID

class ExampleTest : MultipleApiClientTest() {

    @BeforeEach
    fun beforeEach() {
    }

    @ParameterizedTest
    @MethodSource("getApiClients")
    fun successApiClientsDoPlainFapi(apiClient: ApiClient) {
        // Given
        val apiUnderTest = ConfigurationManager.apiUnderTest
        val registrationResponse = apiClient.doDynamicClientRegistration(apiUnderTest)
        assertThat(registrationResponse).isNotNull()

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

        // When
        val (_, response, result) = apiClient.fuelManager.get(apiUnderTest.getEndpointUrl("plainFapiEndpoint"))
            .header(Headers.AUTHORIZATION, "Bearer ${accessToken.access_token}").responseString()
        assertThat(response.isSuccessful).isTrue()
        assertThat(result.get()).contains("user")
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