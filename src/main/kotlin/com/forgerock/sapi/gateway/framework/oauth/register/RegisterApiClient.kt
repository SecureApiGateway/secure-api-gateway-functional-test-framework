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
import com.forgerock.sapi.gateway.framework.apiclient.RegistrationResponse
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.apiUnderTest
import com.forgerock.sapi.gateway.framework.fapi.FapiCompliantValues
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
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
 */
class RegisterApiClient(private val trustedDirectory: TrustedDirectory) {

    var fuelManagerSupplier: (SSLSocketFactory) -> FuelManager = { socketFactory -> getFuelManager(socketFactory) }

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
        val softwareStatementAssertion = trustedDirectory.getSSA(clientConfig)
        val jwtClaimsSet: JWTClaimsSet =
            getRegistrationJWTClaims(softwareStatementAssertion, apiUnderTest, clientConfig)

        val jwsHeader = JWSHeader.Builder(JWSAlgorithm.PS256)
            .keyID(clientConfig.signingKeys.keyID)
            .type(JOSEObjectType.JWT)
            .build()
        val signedJWT = SignedJWT(jwsHeader, jwtClaimsSet)
        signedJWT.sign(
            RSASSASigner(clientConfig.signingKeys.privateKey)
        )
        println("Signed registration jwt is ${signedJWT.serialize()}")

        val fuelManager = fuelManagerSupplier.invoke(clientConfig.socketFactory)
        val responseObject = fuelManager.post(apiUnderTest.oauth2Server.oidcWellKnown.registrationEndpoint ?: "")
            .body(signedJWT.serialize())
            .header(Headers.CONTENT_TYPE, "application/jwt")
            .responseObject<RegistrationResponse>()
        return responseObject
    }

    private fun getRegistrationJWTClaims(softwareStatementAssertion: String, apiUnderTest: ApiUnderTest, apiClientConfig: ApiClientRegistrationConfig): JWTClaimsSet {
        val softwareStatement = SignedJWT.parse(softwareStatementAssertion)
        val softwareStatementClaims = softwareStatement.jwtClaimsSet
        val redirectUris = getRedirectUriFromSoftwareStatementClaims(softwareStatementClaims)

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

    fun getRedirectUriFromSoftwareStatementClaims(softwareStatementClaims: JWTClaimsSet): List<Any> {
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

    fun getTransportCertSubjectDN(apiClientConfig: ApiClientRegistrationConfig): String {
        return apiClientConfig.transportKeys.publicCert.subjectX500Principal.name
    }

}