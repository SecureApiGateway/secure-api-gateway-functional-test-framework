package com.forgerock.sapi.gateway.framework.apiclient

import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants.Companion.SCOPE
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import com.forgerock.sapi.gateway.framework.trusteddirectory.TrustedDirectory
import com.forgerock.sapi.gateway.framework.utils.KeyUtils
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID
import javax.net.ssl.SSLSocketFactory

/**
 * Represents an OAuth2.0 client registered using DCR.
 *
 * Includes the signing and transport keys to allow the client to interact with an API, allowing requests to be sent
 * that include JWTs signed by the client and/or using the client's certificates for mTLS flows.
 */
class ApiClient(
    val signingKeys: KeyPairHolder,
    val socketFactory: SSLSocketFactory,
    val trustedDirectory: TrustedDirectory,
    val softwareId: String = UUID.randomUUID().toString(),
    val orgId: String = UUID.randomUUID().toString(),
    registrationResponse: RegistrationResponse
) {
    var name: String = "${orgId}/${softwareId}"
    val fuelManager = getFuelManager(socketFactory)
    val clientId = registrationResponse.client_id
    val tokenEndpointAuthMethod = registrationResponse.token_endpoint_auth_method
    val redirectUris = registrationResponse.redirect_uris

    fun getClientAssertionJwt(aud: String, jwsSigningAlgorithm: JWSAlgorithm): SignedJWT {
        val expTime = KeyUtils.getExpirationDateMinsInFuture(3L)
        val jwtClaimsBuilder = JWTClaimsSet.Builder().audience(aud).expirationTime(expTime).issueTime(Date())
            .jwtID(UUID.randomUUID().toString()).issuer(clientId).subject(clientId)
        return signJwt(jwtClaimsBuilder.build(), jwsSigningAlgorithm)
    }

    fun getClientAssertionJwtBuilder(aud: String, scopes: String): JWTClaimsSet.Builder {
        val expTime = KeyUtils.getExpirationDateMinsInFuture(3L)
        val nbf = KeyUtils.getExpirationDateMinsInFuture(0L)
        return JWTClaimsSet.Builder().audience(aud).claim(SCOPE, scopes).expirationTime(expTime).issueTime(Date())
            .jwtID(UUID.randomUUID().toString()).notBeforeTime(nbf).issueTime(nbf).issuer(clientId).subject(clientId)
    }

    fun signJwt(jwtClaims: JWTClaimsSet, jwsSigningAlgorithm: JWSAlgorithm): SignedJWT {
        val jwsHeader = JWSHeader.Builder(jwsSigningAlgorithm).keyID(signingKeys.keyID).type(JOSEObjectType.JWT).build()
        val signedJWT = SignedJWT(jwsHeader, jwtClaims)
        signedJWT.sign(
            RSASSASigner(signingKeys.privateKey)
        )
        return signedJWT
    }

    override fun toString(): String {
        return "ApiClient[clientId: ${clientId}, name: ${name}]"
    }

}
