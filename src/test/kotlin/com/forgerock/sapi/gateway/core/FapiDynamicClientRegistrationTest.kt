package com.forgerock.sapi.gateway.core

import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.REDIRECT_URIS
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.RESPONSE_TYPES
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.SOFTWARE_STATEMENT_CLAIM
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.TOKEN_ENDPOINT_AUTH_METHOD
import com.forgerock.sapi.gateway.framework.apiclient.ApiClientRegistrationConfig
import com.forgerock.sapi.gateway.framework.configuration.ApiClientConfig
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.apiUnderTest
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.trustedDirectory
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import com.forgerock.sapi.gateway.framework.oauth.OAuth2ErrorResponse
import com.forgerock.sapi.gateway.framework.oauth.TokenEndpointAuthMethod
import com.forgerock.sapi.gateway.framework.oauth.register.RegisterApiClient
import com.github.kittinunf.fuel.core.Response
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.util.Date
import java.util.concurrent.TimeUnit

class FapiDynamicClientRegistrationTest {

    private lateinit var apiClientConfig:ApiClientConfig

    private val objectMapper = ObjectMapper().registerModule(
        KotlinModule.Builder().build()
    )

    @BeforeEach
    fun beforeEach() {
        // Take a fresh copy of the config before each test
        apiClientConfig = trustedDirectory.productionTrustedDirectoryConfig.apiClientConfig.first().copy()
    }

    @ParameterizedTest
    @ValueSource(strings = ["tls_client_auth", "private_key_jwt"])
    fun apiClientRegistersWithSupportedAuthMethod(tokenEndpointAuthMethodString: String) {
        val tokenEndpointAuthMethod = TokenEndpointAuthMethod.valueOf(tokenEndpointAuthMethodString)
        apiClientConfig.preferredTokenEndpointAuthMethod = tokenEndpointAuthMethod
        val apiClient = RegisterApiClient(trustedDirectory).register(
            trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
        )
        assertThat(apiClient.clientId).isNotEmpty()
        assertThat(apiClient.tokenEndpointAuthMethod).isEqualTo(tokenEndpointAuthMethod)

        // Verify that we can get a client_credentials access_token for this OAuth2.0 client
        assertThat(apiUnderTest.oauth2Server.getClientCredentialsAccessToken(apiClient, "openid accounts")).isNotNull()
    }

    @Nested
    inner class MtlsTests {
        @Test
        fun failsIfMtlsTransportCertNotProvider() {
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
        fun failsIfMtlsCertNotFoundInJwks() {
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
        fun failsIfRequestJwtSignedWithRS256() {
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
        fun failsIfRequestJwtSignatureInvalid() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            // Override the JWT signer to supply a newly generated key, sig will therefore not validate against the
            // key in the JWKS for the configured keyId.
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
        fun failsIfRequestJwtSignedWithUnknownKid() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            // Override the JWT signer to use a kid not in the client's JWKS
            registerApiClient.registrationRequestJwtSigner = { validKeyPair, signingAlgorithm, jwtClaimsSet ->
                registerApiClient.signedRegistrationRequestJwt(
                    KeyPairHolder(generateRsaPrivateKey(), validKeyPair.publicCert, "unknown-kid", validKeyPair.type),
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

        @Test
        fun failsIfRequestJwtSignedByKeyWithIncorrectUse() {
            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val registerApiClient = RegisterApiClient(trustedDirectory)
            // Override the JWT signer to use the transport key, this will not have the sig use in the JWKS
            registerApiClient.registrationRequestJwtSigner = { validKeyPair, signingAlgorithm, jwtClaimsSet ->
                registerApiClient.signedRegistrationRequestJwt(
                    clientConfig.transportKeys,
                    signingAlgorithm,
                    jwtClaimsSet
                )
            }

            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.error).isEqualTo("invalid_client_metadata")
            assertThat(errorResponse.errorDescription).isEqualTo(
                "Registration Request JWT is invalid: Expected JWT to have a valid signature")
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

    @Nested
    inner class ClientMetadataTests {

        @Test
        fun failsIfTokenEndpointAuthMethodNotSupported() {
            testRegisteringWithInvalidRequestClaims(
                { builder -> builder.claim(TOKEN_ENDPOINT_AUTH_METHOD, "client_secret_basic") },
                "invalid_client_metadata",
                "token_endpoint_auth_method not supported, must be one of: [private_key_jwt, tls_client_auth]"
            )
        }

        @Test
        fun failsIfRedirectUriIsNotInSoftwareStatement() {
            testRegisteringWithInvalidRequestClaims(
                { builder -> builder.claim(REDIRECT_URIS, listOf("https://uri-not-in-ssa.com")) },
                "invalid_redirect_uri",
                "invalid registration request redirect_uris value, must match or be a subset of the software_redirect_uris"
            )
        }

        @Test
        fun failsIfRedirectUriIsNotHttps() {
            val invalidRedirectUri = "http://google.com"
            val expectedErrorMessage = "redirect_uris must use https scheme"
            testInvalidRedirectUriInSoftwareStatement(invalidRedirectUri, expectedErrorMessage)
        }
        @Test
        fun failsIfRedirectUriIsLocalhost() {
            val invalidRedirectUri = "https://localhost:8080/callback"
            val expectedErrorMessage = "redirect_uris must not contain localhost"
            testInvalidRedirectUriInSoftwareStatement(invalidRedirectUri, expectedErrorMessage)
        }

        @ParameterizedTest
        @ValueSource(
            strings = ["token_endpoint_auth_signing_alg", "id_token_signed_response_alg", "request_object_signing_alg"]
        )
        fun failsIfSigningClaimConfiguredWithUnsupportedSigningAlg(signingClaimName: String) {
            testRegisteringWithInvalidRequestClaims(
                { builder -> builder.claim(signingClaimName, "RS256") },
                "invalid_client_metadata",
                "request object field: ${signingClaimName}, must be one of: [PS256]"
            )
        }

        @ParameterizedTest
        @ValueSource(strings = ["code id_token token", "code token", "token", "id_token"])
        fun failsIfResponseTypeNotSupported(invalidResponseType: String) {
            // Override response_types with a list containing a valid value and an invalid value
            testRegisteringWithInvalidRequestClaims(
                { builder ->
                    builder.claim(RESPONSE_TYPES, listOf("code", invalidResponseType).shuffled())
                },
                "invalid_client_metadata",
                "Invalid response_types value: $invalidResponseType, must be one of: \"code\" or \"code id_token\""
            )
        }

        @Test
        fun failsIfRequestJwtHasExpired() {
            // Set JWT exp to 5 mins in the past
            testRegisteringWithInvalidRequestClaims(
                { builder ->
                    builder.expirationTime(Date(System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(5)))
                },
                "invalid_client_metadata",
                "Registration Request JWT is invalid: Expected timestamp 'exp' to be after the given datetime"
            )
        }

        private fun testRegisteringWithInvalidRequestClaims(
            claimOverrider: (JWTClaimsSet.Builder) -> Unit,
            expectedError: String,
            expectedErrorDescription: String
        ) {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            registerApiClient.applyRequestJwtClaimOverrides = claimOverrider

            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.error).isEqualTo(expectedError)
            assertThat(errorResponse.errorDescription).isEqualTo(expectedErrorDescription)
        }

        private fun testInvalidRedirectUriInSoftwareStatement(invalidRedirectUri: String, expectedErrorMessage: String) {
            // Use the dev directory in order to generate SSAs with invalid redirect_uris
            val devTrustedDirectory = apiUnderTest.devTrustedDirectory
            val devApiClientConfig = devTrustedDirectory.createApiClientRegistrationConfig()
            val registerApiClient = RegisterApiClient(devTrustedDirectory)

            // Override the SSA claim
            registerApiClient.softwareStatementSupplier = { a ->
                val ssaClaims = devTrustedDirectory.getSoftwareStatementClaims(a.softwareId)
                ssaClaims.software_redirect_uris = listOf(invalidRedirectUri)
                devTrustedDirectory.getSSA(a, ssaClaims)
            }
            registerApiClient.redirectUriSelector = { _ -> listOf(invalidRedirectUri) }

            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                devApiClientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.error).isEqualTo("invalid_redirect_uri")
            assertThat(errorResponse.errorDescription).isEqualTo(expectedErrorMessage)
        }

    }

    @Nested
    inner class SoftwareStatementTests {

        @Test
        fun failsIfSoftwareStatementSigIsInvalid() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val ssaJwt = SignedJWT.parse(trustedDirectory.getSSA(clientConfig))

            registerApiClient.applyRequestJwtClaimOverrides = { builder ->
                // Re-sign the SSA using the client's key (SSA must be signed by the Trusted Directory)
                val invalidSsaJwt = SignedJWT(ssaJwt.header, ssaJwt.jwtClaimsSet)
                invalidSsaJwt.sign(RSASSASigner(clientConfig.signingKeys.privateKey))
                builder.claim(
                    SOFTWARE_STATEMENT_CLAIM,
                    invalidSsaJwt.serialize()
                )
            }

            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.error).isEqualTo("invalid_software_statement")
            assertThat(errorResponse.errorDescription).isEqualTo(
                "Failed to validate SSA against jwks_uri 'https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks'")
        }

        @Test
        fun failsIfSoftwareStatementNotFromSupportedTrustedDirectory() {
            val registerApiClient = RegisterApiClient(trustedDirectory)
            val clientConfig = trustedDirectory.createApiClientRegistrationConfig(apiClientConfig)
            val ssaJwt = SignedJWT.parse(trustedDirectory.getSSA(clientConfig))

            registerApiClient.applyRequestJwtClaimOverrides = { builder ->

                val ssaIssuedByUnsupportedDirectory =
                    SignedJWT(
                        ssaJwt.header, JWTClaimsSet.Builder(ssaJwt.jwtClaimsSet)
                            .claim("iss", "Unknown Trusted Directory").build()
                    )
                ssaIssuedByUnsupportedDirectory.sign(RSASSASigner(clientConfig.signingKeys.privateKey))
                builder.claim(
                    SOFTWARE_STATEMENT_CLAIM,
                    ssaIssuedByUnsupportedDirectory.serialize()
                )
            }

            val (response, errorResponse) = invokeRegisterEndpointExpectingErrorResponse(
                registerApiClient,
                clientConfig
            )

            assertThat(response.statusCode).isEqualTo(400)
            assertThat(errorResponse.error).isEqualTo("unapproved_software_statement")
            assertThat(errorResponse.errorDescription).isEqualTo(
                "The issuer of the software statement is unrecognised")
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