package com.forgerock.sapi.gateway.framework.oauth.register

import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.GRANT_TYPES_CLAIM
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.REDIRECT_URIS
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.RESPONSE_TYPES
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.SCOPE
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.SOFTWARE_STATEMENT_CLAIM
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.TLS_CLIENT_AUTH_SUBJECT_DN
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.TOKEN_ENDPOINT_AUTH_METHOD
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.TOKEN_ENDPOINT_AUTH_SIGNING_ALG
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.apiclient.ApiClientRegistrationConfig
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.apiUnderTest
import com.forgerock.sapi.gateway.framework.fapi.FapiCompliantValues
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import com.forgerock.sapi.gateway.framework.oauth.TokenEndpointAuthMethod
import com.forgerock.sapi.gateway.framework.trusteddirectory.TrustedDirectory
import com.forgerock.sapi.gateway.framework.utils.KeyUtils
import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.fuel.core.Headers
import com.github.kittinunf.fuel.core.ResponseResultOf
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.shaded.json.JSONArray
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import javax.net.ssl.SSLSocketFactory

/**
 * Dynamic Client Registration implementation, takes ApiClientRegistrationConfig and completes the registration
 * process to produce ApiClient objects which can be used to access APIs.
 * The default values for properties are aimed to create valid registration tests, these values can be changed to
 * allow behaviour to be customised in order to trigger error responses.
 */
class RegisterApiClient(private val trustedDirectory: TrustedDirectory) {

    /**
     * Function which supplies the FuelManager to use for this client.
     * Defaults to: com.forgerock.sapi.gateway.framework.http.fuel.FuelInitialiserKt.getFuelManager
     */
    var fuelManagerSupplier: (SSLSocketFactory) -> FuelManager = { socketFactory -> getFuelManager(socketFactory) }

    /**
     * Function which produces a SignedJWT that is used as the request param in the registration call.
     * Defaults to calling: signedRegistrationRequestJwt method
     */
    var registrationRequestJwtSigner: (KeyPairHolder, JWSAlgorithm, JWTClaimsSet) -> SignedJWT = this::signedRegistrationRequestJwt

    /**
     * Consumer that allows the JWTClaimsSet values to be overridden / customised.
     * Defaults to no overrides being applied.
     */
    var applyRequestJwtClaimOverrides: (JWTClaimsSet.Builder) -> Unit = {}

    /**
     * Supplies the software statement to use for the ApiClientRegistrationConfig
     * Defaults to calling the trusted directory getSSA method.
     */
    var softwareStatementSupplier: (ApiClientRegistrationConfig) -> String = trustedDirectory::getSSA

    /**
     * Selects the redirect_uri to use for the registration from the values available in the Software Statement.
     * Defaults to calling method: getRedirectUriFromSoftwareStatementClaims
     */
    var redirectUriSelector: (JWTClaimsSet) -> List<Any> = this::getRedirectUriFromSoftwareStatementClaims

    fun register(clientConfig: ApiClientRegistrationConfig): ApiClient {
        val responseObject = invokeRegisterEndpoint(clientConfig)

        val response = responseObject.second
        val result = responseObject.third
        if (response.isSuccessful) {
            val dcrResponse = result.get()
            println("Dynamic Client Registration response is $dcrResponse")
            return ApiClient(
                signingKeys = clientConfig.signingKeys,
                socketFactory = clientConfig.socketFactory,
                trustedDirectory = clientConfig.trustedDirectory,
                softwareId = clientConfig.softwareId,
                orgId = clientConfig.orgId,
                registrationResponse = dcrResponse
            )
        } else {
            throw Exception("Dynamic Client Registration of ${clientConfig.orgId}/${clientConfig.softwareId} with ${apiUnderTest.name} failed. ${response.statusCode}, $result")
        }
    }

    fun invokeRegisterEndpoint(clientConfig: ApiClientRegistrationConfig): ResponseResultOf<RegistrationResponse> {
        val softwareStatementAssertion = softwareStatementSupplier.invoke(clientConfig)
        val jwtClaimsSet: JWTClaimsSet =
            getRegistrationJWTClaims(softwareStatementAssertion, apiUnderTest, clientConfig)

        val signedJWT = registrationRequestJwtSigner.invoke(clientConfig.signingKeys, JWSAlgorithm.PS256, jwtClaimsSet)
        println("Signed registration jwt is ${signedJWT.serialize()}")

        val fuelManager = fuelManagerSupplier.invoke(clientConfig.socketFactory)
        val responseObject = fuelManager.post(apiUnderTest.oauth2Server.oidcWellKnown.registrationEndpoint ?: "")
            .body(signedJWT.serialize())
            .header(Headers.CONTENT_TYPE, "application/jwt")
            .responseObject<RegistrationResponse>()
        return responseObject
    }

    fun signedRegistrationRequestJwt(
        signingKeyPair: KeyPairHolder,
        signingAlgorithm: JWSAlgorithm,
        jwtClaimsSet: JWTClaimsSet
    ): SignedJWT {
        val jwsHeader = JWSHeader.Builder(signingAlgorithm)
            .keyID(signingKeyPair.keyID)
            .type(JOSEObjectType.JWT)
            .build()
        val signedJWT = SignedJWT(jwsHeader, jwtClaimsSet)
        signedJWT.sign(
            RSASSASigner(signingKeyPair.privateKey)
        )
        return signedJWT
    }

    private fun getRegistrationJWTClaims(softwareStatementAssertion: String, apiUnderTest: ApiUnderTest, apiClientConfig: ApiClientRegistrationConfig): JWTClaimsSet {
        val softwareStatement = SignedJWT.parse(softwareStatementAssertion)
        val softwareStatementClaims = softwareStatement.jwtClaimsSet
        val redirectUris = redirectUriSelector.invoke(softwareStatementClaims)

        val tokenEndpointAuthMethod = getTokenEndpointAuthMethod(apiUnderTest, apiClientConfig)
        val claimsBuilder = JWTClaimsSet.Builder()
            .issuer(apiClientConfig.softwareId)
            .expirationTime(KeyUtils.getExpirationDateMinsInFuture(3))
            .claim(SOFTWARE_STATEMENT_CLAIM, softwareStatementAssertion)
            .claim(GRANT_TYPES_CLAIM, listOf("authorization_code", "refresh_token", "client_credentials"))
            .claim(ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM, idTokenResponseAlgs(apiUnderTest))
            .claim(REDIRECT_URIS, redirectUris)
            .claim(RESPONSE_TYPES, responseTypesFromApiUnderTest(apiUnderTest))
            .claim(TOKEN_ENDPOINT_AUTH_METHOD, tokenEndpointAuthMethod)
            .claim(TOKEN_ENDPOINT_AUTH_SIGNING_ALG, getTokenEndpointAuthSigningAlg(apiUnderTest))
            .claim(SCOPE, getScopesSupported(apiUnderTest))

        if (tokenEndpointAuthMethod == TokenEndpointAuthMethod.tls_client_auth) {
            claimsBuilder.claim(TLS_CLIENT_AUTH_SUBJECT_DN, getTransportCertSubjectDN(apiClientConfig))
        }
        applyRequestJwtClaimOverrides.invoke(claimsBuilder)

        return claimsBuilder.build()
    }

    private fun getTokenEndpointAuthSigningAlg(apiUnderTest: ApiUnderTest): String {
        return apiUnderTest.oauth2Server.oidcWellKnown.tokenEndpointAuthSigningAlgValuesSupported[0]
    }

    private fun getScopesSupported(apiUnderTest: ApiUnderTest): String {
        return apiUnderTest.oauth2Server.oidcWellKnown.scopesSupported.joinToString(separator = " ")
    }

    private fun getTokenEndpointAuthMethod(apiUnderTest: ApiUnderTest, apiClientConfig: ApiClientRegistrationConfig): TokenEndpointAuthMethod {
        val supportedAuthMethods = getTokenEndpointAuthMethodsSupported(apiUnderTest)
        val preferredTokenEndpointAuthMethod = apiClientConfig.preferredTokenEndpointAuthMethod
        if (supportedAuthMethods.contains(preferredTokenEndpointAuthMethod)) {
            return preferredTokenEndpointAuthMethod
        }
        val authMethod = supportedAuthMethods[0]
        println("PreferredTokenEndpointAuthMethod: $preferredTokenEndpointAuthMethod is not supported " +
                "- falling back to: $authMethod" )
        return authMethod
    }

    private fun getTokenEndpointAuthMethodsSupported(apiUnderTest: ApiUnderTest): List<TokenEndpointAuthMethod> {
        return apiUnderTest.oauth2Server.oidcWellKnown.tokenEndpointAuthMethodsSupported
    }

    private fun idTokenResponseAlgs(apiUnderTest: ApiUnderTest): String {
        val idTokenResponseAlgs = FapiCompliantValues.getFapiCompliantListOfValues(
            ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM,
            apiUnderTest.fapiSecurityProfile
        ).intersect(apiUnderTest.oauth2Server.oidcWellKnown.idTokenSigningAlgValuesSupported.toSet())

        if (idTokenResponseAlgs.isEmpty()) {
            throw Exception(
                "api '${apiUnderTest.name} does not support any ${apiUnderTest.fapiSecurityProfile} " +
                        "compliant $ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM claims"
            )
        }
        return idTokenResponseAlgs.elementAt(0)
    }

    private fun responseTypesFromApiUnderTest(apiUnderTest: ApiUnderTest) =
        apiUnderTest.oauth2Server.oidcWellKnown.responseTypesSupported.intersect(listOf("code", "code id_token"))

    private fun getRedirectUriFromSoftwareStatementClaims(softwareStatementClaims: JWTClaimsSet): List<Any> {
        val redirectUris: JSONArray =
            softwareStatementClaims.getClaim(trustedDirectory.ssaClaimNames.redirectUris) as JSONArray
        val filteredRedirectUris = redirectUris.toArray().filter {
            if (it is String) {
                !it.contains("localhost")
            } else {
                false
            }
        }
        return listOf(filteredRedirectUris[0])
    }

    private fun getTransportCertSubjectDN(apiClientConfig: ApiClientRegistrationConfig): String {
        return apiClientConfig.transportKeys.publicCert.subjectX500Principal.name
    }

}

data class RegistrationResponse(
    val application_type: String,
    val client_id: String,
    val client_secret: String? = null,
    val client_secret_expires_at: String? = null,
    val default_max_age: String,
    val grant_types: List<String>,
    val id_token_encrypted_response_alg: String,
    val id_token_encrypted_response_enc: String,
    val id_token_signed_response_alg: String,
    val jwks_uri: String? = "",
    val redirect_uris: List<String>,
    val registration_access_token: String,
    val registration_client_uri: String,
    val request_object_encryption_alg: String,
    val request_object_encryption_enc: String?,
    val request_object_signing_alg: String,
    val response_types: List<String>,
    val scope: String,
    val scopes: List<String>,
    val subject_type: String,
    val token_endpoint_auth_method: TokenEndpointAuthMethod,
    val token_endpoint_auth_signing_alg: String,
    val userinfo_encrypted_response_alg: String,
    val userinfo_encrypted_response_enc: String,
    val userinfo_signed_response_alg: String,
    val introspection_encrypted_response_alg: String,
    val introspection_encrypted_response_enc: String,
    val introspection_signed_response_alg: String,
    val client_type: String,
    val public_key_selector: String,
    val authorization_code_lifetime: Long,
    val user_info_response_format_selector: String,
    val tls_client_certificate_bound_access_tokens: Boolean,
    val backchannel_logout_session_required: Boolean,
    val default_max_age_enabled: Boolean,
    val token_intro_response_format_selector: String,
    val jwt_token_lifetime: Long,
    val id_token_encryption_enabled: Boolean,
    val access_token_lifetime: Long,
    val refresh_token_lifetime: Long,
    val software_statement: String? = null
)