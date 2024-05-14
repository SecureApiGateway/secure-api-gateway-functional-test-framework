package com.forgerock.sapi.gateway.core

import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.forgerock.sapi.gateway.framework.apiclient.ApiClientRegistrationConfig
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.apiUnderTest
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.trustedDirectory
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import com.forgerock.sapi.gateway.framework.oauth.OAuth2ErrorResponse
import com.forgerock.sapi.gateway.framework.oauth.register.RegisterApiClient
import com.github.kittinunf.fuel.core.Response
import com.nimbusds.jose.JWSAlgorithm
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey

class RegisterApiClientTest {

    private val apiClientConfig = trustedDirectory.productionTrustedDirectoryConfig.apiClientConfig.first()

    private val objectMapper = ObjectMapper().registerModule(
        KotlinModule.Builder().build()
    )

    // Sanity test of the config
    @Test
    fun apiClientRegistersSuccessfully() {
        val apiClient = RegisterApiClient(trustedDirectory).register(
            trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
        )
        assertThat(apiClient.clientId).isNotEmpty()
        assertThat(apiClient.tokenEndpointAuthMethod).isNotNull()
    }

    @Nested
    inner class MtlsTests {
        @Test
        fun failsToRegisterIfMtlsTransportCertNotProvider() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            // Supply a fuelManager that does not have the client's certificates loaded
            registerApiClient.fuelManagerSupplier = { _ -> getFuelManager() }

            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.errorDescription).isEqualTo("Client mTLS certificate not provided")
        }

        @Test
        fun failsToRegisterIfMtlsCertNotFoundInJwks() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            // Supply a fuelManager that has a different client's mTLS cert
            registerApiClient.fuelManagerSupplier =
                { _ -> getFuelManager(socketFactory = apiUnderTest.devTrustedDirectory.apiClients.values.first().socketFactory) }

            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.errorDescription).isEqualTo("tls transport cert does not match any certs registered in jwks for software statement")
        }
    }

    @Nested
    inner class RequestJwtSigningTests {

        @Test
        fun failsToRegisterIfRequestJwtSignedWithRS256() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            // Override the JWT signer to use RS256
            registerApiClient.registrationRequestJwtSigner = { signingKeys, _, jwtClaimsSet ->
                registerApiClient.signedRegistrationRequestJwt(
                    signingKeys, JWSAlgorithm.RS256, jwtClaimsSet
                )
            }

            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.error).isEqualTo("invalid_client_metadata")
            assertThat(errorResponse.errorDescription).isEqualTo("Registration Request signature is invalid: 'jwt signed using unsupported algorithm: RS256'")
        }

        @Test
        fun failsToRegisterIfRequestJwtSignedWithWrongKey() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            // Override the JWT signer to use RS256
            registerApiClient.registrationRequestJwtSigner = { validKeyPair, signingAlgorithm, jwtClaimsSet ->
                val signingKeyPairWithInvalidPrivateKey =
                    KeyPairHolder(
                        generateRsaPrivateKey(),
                        validKeyPair.publicCert,
                        validKeyPair.keyID,
                        validKeyPair.type
                    )
                registerApiClient.signedRegistrationRequestJwt(
                    signingKeyPairWithInvalidPrivateKey, signingAlgorithm, jwtClaimsSet
                )
            }

            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.error).isEqualTo("invalid_client_metadata")
            assertThat(errorResponse.errorDescription).isEqualTo("Registration Request signature is invalid: 'jwt signature verification failed'")
        }

        @Test
        fun failsToRegisterIfRequestJwtSignedWithUnknownKid() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            // Override the JWT signer to use RS256
            registerApiClient.registrationRequestJwtSigner = { validKeyPair, signingAlgorithm, jwtClaimsSet ->
                registerApiClient.signedRegistrationRequestJwt(
                    KeyPairHolder(validKeyPair.privateKey, validKeyPair.publicCert, "unknown-kid", validKeyPair.type),
                    signingAlgorithm,
                    jwtClaimsSet
                )
            }

            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.error).isEqualTo("invalid_client_metadata")
            assertThat(errorResponse.errorDescription).isEqualTo("Registration Request signature is invalid: 'jwk not found in supplied jwkSet for kid: unknown-kid'")
        }

        private fun generateRsaPrivateKey(): PrivateKey {
            try {
                val generator = KeyPairGenerator.getInstance("RSA")
                generator.initialize(2048)
                val pair = generator.generateKeyPair()

                return pair.private
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException(e)
            }
        }
    }

    private fun invokeRegisterEndpointExpectingErrorResponse(
        registerApiClient: RegisterApiClient, clientConfig: ApiClientRegistrationConfig
    ): Pair<Response, OAuth2ErrorResponse> {
        val registerResponse = registerApiClient.invokeRegisterEndpoint(
            clientConfig
        )
        val response = registerResponse.second
        val responseJson = response.body().asString("application/json")
        val errorResponse = objectMapper.readValue(responseJson, OAuth2ErrorResponse::class.java)
        return Pair(response, errorResponse)
    }

}