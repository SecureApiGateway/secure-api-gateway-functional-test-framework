package com.forgerock.sapi.gateway.core

import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.trustedDirectory
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.oauth.OAuth2ErrorResponse
import com.forgerock.sapi.gateway.framework.oauth.register.RegisterApiClient
import org.junit.jupiter.api.Test

class RegisterApiClientTest {


    private fun apiClientConfig() = trustedDirectory.productionTrustedDirectoryConfig.apiClientConfig.first()

    // Sanity test of the config
    @Test
    fun apiClientRegistersSuccessfully() {
        val apiClientConfig = apiClientConfig()
        val apiClient = RegisterApiClient(trustedDirectory).register(
            trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
        )
        assertThat(apiClient.clientId).isNotEmpty()
        assertThat(apiClient.tokenEndpointAuthMethod).isNotNull()
    }

    @Test
    fun failsToRegisterIfMtlsTransportCertNotProvider() {
        val apiClientConfig = apiClientConfig()

        val registerApiClient = RegisterApiClient(trustedDirectory)
        // Supply a fuelManager that does not have the client's certificates loaded
        registerApiClient.fuelManagerSupplier = { _ -> getFuelManager() }


        val registerResponse = registerApiClient.invokeRegisterEndpoint(
            trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
        )
        val responseJson = registerResponse.second.body().asString("application/json")
        val errorResponse = ObjectMapper().registerModule(
            KotlinModule.Builder().build()
        ).readValue(responseJson, OAuth2ErrorResponse::class.java)

        assertThat(registerResponse.second.statusCode).isEqualTo(400)
        assertThat(errorResponse.errorDescription).isEqualTo("Client mTLS certificate not provided")
    }

}