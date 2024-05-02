package com.forgerock.sapi.gateway.framework.apiclient

import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.GRANT_TYPES_CLAIM
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.REDIRECT_URIS
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.RESPONSE_TYPES
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.SCOPE
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.SOFTWARE_STATEMENT_CLAIM
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.TOKEN_ENDPOINT_AUTH_METHOD
import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.TOKEN_ENDPOINT_AUTH_SIGNING_ALG
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.fapi.FapiCompliantValues
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import com.forgerock.sapi.gateway.framework.trusteddirectory.TrustedDirectory
import com.forgerock.sapi.gateway.framework.utils.KeyUtils
import com.github.kittinunf.fuel.core.Headers
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.shaded.json.JSONArray
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.http.HttpMethod
import java.util.*
import javax.net.ssl.SSLSocketFactory

class ApiClient(
    val signingKeys: KeyPairHolder,
    val transportKeys: KeyPairHolder,
    val socketFactory: SSLSocketFactory,
    val trustedDirectory: TrustedDirectory,
    val softwareId: String = UUID.randomUUID().toString(),
    val orgId: String = UUID.randomUUID().toString()
) {
    var name: String = "${orgId}/${softwareId}"
    val fuelManager = getFuelManager(socketFactory)
    lateinit var registrationResponse: RegistrationResponse

    fun registered(): Boolean {
        return ::registrationResponse.isInitialized
    }

    fun getClientAssertionJwt(aud: String, jwsSigningAlgorithm: JWSAlgorithm): SignedJWT {
        val expTime = KeyUtils.getExpirationDateMinsInFuture(3L)
        val jwtClaimsBuilder = JWTClaimsSet.Builder()
            .audience(aud)
            .expirationTime(expTime)
            .issueTime(Date())
            .jwtID(UUID.randomUUID().toString())
        if (::registrationResponse.isInitialized) {
            jwtClaimsBuilder.issuer(registrationResponse.client_id)
                .subject(registrationResponse.client_id)
        } else {
            jwtClaimsBuilder.issuer(softwareId).subject(softwareId)
        }
        val jwtClaims = jwtClaimsBuilder.build()
        return signJwt(jwtClaims, jwsSigningAlgorithm)
    }

    fun getClientAssertionJwtBuilder(aud: String, scopes: String): JWTClaimsSet.Builder {
        val expTime = KeyUtils.getExpirationDateMinsInFuture(3L)
        val nbf = KeyUtils.getExpirationDateMinsInFuture(0L)
        val jwtClaimsBuilder = JWTClaimsSet.Builder()
            .audience(aud)
            .claim(SCOPE, scopes)
            .expirationTime(expTime)
            .issueTime(Date())
            .jwtID(UUID.randomUUID().toString())
            .notBeforeTime(nbf)
            .issueTime(nbf)

        if (::registrationResponse.isInitialized) {
            jwtClaimsBuilder.issuer(registrationResponse.client_id)
                .subject(registrationResponse.client_id)
        } else {
            jwtClaimsBuilder.issuer(softwareId).subject(softwareId)
        }
        return jwtClaimsBuilder
    }

    fun signJwt(jwtClaims: JWTClaimsSet, jwsSigningAlgorithm: JWSAlgorithm): SignedJWT {
        val jwsHeader = JWSHeader.Builder(jwsSigningAlgorithm)
            .keyID(signingKeys.keyID)
            .type(JOSEObjectType.JWT)
            .build()
        val signedJWT = SignedJWT(jwsHeader, jwtClaims)
        signedJWT.sign(
            RSASSASigner(signingKeys.privateKey)
        )
        return signedJWT
    }

    fun doDynamicClientRegistration(apiUnderTest: ApiUnderTest): RegistrationResponse {
        if (!::registrationResponse.isInitialized) {
            forceDynamicClientRegistration(apiUnderTest)
        } else {
            println("Client already registered")
        }
        return registrationResponse
    }

    fun forceDynamicClientRegistration(apiUnderTest: ApiUnderTest): RegistrationResponse {
        println(
            "Registering apiClient $name with Api under test's OAuth Server at" +
                    " ${apiUnderTest.oauth2Server.oidcWellKnown.issuer}"
        )

        val softwareStatementAssertion = trustedDirectory.getSSA(this)
        val jwtClaimsSet: JWTClaimsSet = getRegistrationJWTClaims(softwareStatementAssertion, apiUnderTest)
        val signedJWT = signJwt(jwtClaimsSet, JWSAlgorithm.PS256)
        println("Signed registration jwt is ${signedJWT.serialize()}")

        val (_, response, result) = fuelManager.post(apiUnderTest.oauth2Server.oidcWellKnown.registrationEndpoint ?: "")
            .body(signedJWT.serialize())
            .header(Headers.CONTENT_TYPE, "application/jwt")
            .responseObject<RegistrationResponse>()

        if (response.isSuccessful) {
            val dcrResponse = result.get()
            println("Dynamic Client Registration response is $dcrResponse")
            registrationResponse = dcrResponse
            return registrationResponse
        } else {
            throw Exception("Dynamic Client Registration of $name with ${apiUnderTest.name} failed. ${response.statusCode}, $result")
        }

    }

    private fun getRegistrationJWTClaims(softwareStatementAssertion: String, apiUnderTest: ApiUnderTest): JWTClaimsSet {
        val softwareStatement = SignedJWT.parse(softwareStatementAssertion)
        val softwareStatementClaims = softwareStatement.jwtClaimsSet
        val redirectUris = getRedirectUriFromSoftwareStatementClaims(softwareStatementClaims)

        return JWTClaimsSet.Builder()
            .issuer(softwareId)
            .expirationTime(KeyUtils.getExpirationDateMinsInFuture(3))
            .claim(SOFTWARE_STATEMENT_CLAIM, softwareStatementAssertion)
            .claim(GRANT_TYPES_CLAIM, listOf("authorization_code", "refresh_token", "client_credentials"))
            .claim(ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM, idTokenResponseAlgs(apiUnderTest))
            .claim(REDIRECT_URIS, redirectUris)
            .claim(RESPONSE_TYPES, responseTypesFromApiUnderTest(apiUnderTest))
            .claim(TOKEN_ENDPOINT_AUTH_METHOD, getTokenEndpointAuthMethodsSupported(apiUnderTest))
            .claim(TOKEN_ENDPOINT_AUTH_SIGNING_ALG, getTokenEndpointAuthSigningAlg(apiUnderTest))
            .claim(SCOPE, getScopesSupported(apiUnderTest))
            .build()
    }

    private fun getTokenEndpointAuthSigningAlg(apiUnderTest: ApiUnderTest): String {
        return apiUnderTest.oauth2Server.oidcWellKnown.tokenEndpointAuthSigningAlgValuesSupported[0]
    }

    private fun getScopesSupported(apiUnderTest: ApiUnderTest): String {
        return apiUnderTest.oauth2Server.oidcWellKnown.scopesSupported.joinToString(separator = " ")
    }

    private fun getTokenEndpointAuthMethodsSupported(apiUnderTest: ApiUnderTest): String {
        return apiUnderTest.oauth2Server.oidcWellKnown.tokenEndpointAuthMethodsSupported[0].toString()
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


    fun getTransportCertSubjectDN(): String {
        return transportKeys.publicCert.subjectX500Principal.name
    }
}
