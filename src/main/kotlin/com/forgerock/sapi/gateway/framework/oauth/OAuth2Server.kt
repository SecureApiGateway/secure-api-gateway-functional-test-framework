package com.forgerock.sapi.gateway.framework.oauth

import com.forgerock.sapi.gateway.common.constants.OAuth2TokenClientAssertionTypes.Companion.CLIENT_ASSERTION_TYPE_JWT_BEARER
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenGrantTypes.Companion.CLIENT_CREDENTIALS
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.CLIENT_ASSERTION
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.CLIENT_ASSERTION_TYPE
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.GRANT_TYPE
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.SCOPE
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.consents.ConsentHandlerFactory
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.http.fuel.initFuel
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.forgerock.sapi.gateway.framework.oidc.OBDirectoryOidcWellKnownResponse
import com.forgerock.sapi.gateway.framework.oidc.OidcWellKnown
import com.forgerock.sapi.gateway.ob.uk.framework.accesstoken.model.AccessTokenResponse
import com.forgerock.sapi.gateway.ob.uk.support.resourceowner.ResourceOwner
import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.Headers
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT

class OAuth2Server(private val oidcWellKnownUrl: String) {
    var oidcWellKnown: OidcWellKnown
    var grantTypesSupported: List<String>

    data class AuthorizeRequestComponents(val url: String, val parameters: List<Pair<String, String>>)

    init {
        // Hack to handle non-standard response from Open Banking Sandbox Directory. Issue raise to have them
        // fix it. https://directory.openbanking.org.uk/obieservicedesk/s/case/500Px000007m9EkIAI/the-sandbox-directory-oidc-well-known-response-does-not-conform-to-oidc-connect-well-known-10-specification
        oidcWellKnown = if (oidcWellKnownUrl.contains("openbankingtest.org.uk")) {
            initFuel() // FIXME - hack to init fuel with client certs as .well-known endpoint requires mTLS
            val (_, response, result) = Fuel.get(oidcWellKnownUrl)
                .header(Headers.CONTENT_TYPE, "application/jwt")
                .responseObject<OBDirectoryOidcWellKnownResponse>()

            if (response.isSuccessful) {
                result.get().getOidcWellKnown()
            } else {
                throw Exception("Failed to obtain OpenId Connect Well Known endpoint from $oidcWellKnownUrl. Error was ${response.statusCode}, $result.get()")
            }
        } else {
            val (_, response, result) = Fuel.get(oidcWellKnownUrl)
                .header(Headers.CONTENT_TYPE, "application/jwt")
                .responseObject<OidcWellKnown>()

            if (response.isSuccessful) {
                result.get()
            } else {
                throw Exception("Failed to obtain OpenId Connect Well Known endpoint from $oidcWellKnownUrl. Error was ${response.statusCode}, $result.get()")
            }
        }
        grantTypesSupported = oidcWellKnown.grantTypesSupported
    }

    fun getAccessToken(apiClient: ApiClient, scopes: String): AccessTokenResponse {
        if (oidcWellKnown.tokenEndpointAuthMethodsSupported.contains(TokenEndpointAuthMethod.private_key_jwt)) {

            val jwt: SignedJWT = apiClient.getClientAssertionJwt(
                aud = oidcWellKnown.tokenEndpoint,
                jwsSigningAlgorithm = JWSAlgorithm.PS256 //ToDO: Get supported alg from oidc well known response
            )
            println("signed jwt is ${jwt.serialize()}")

            val parameters = mutableListOf(
                CLIENT_ASSERTION_TYPE to CLIENT_ASSERTION_TYPE_JWT_BEARER,
                GRANT_TYPE to CLIENT_CREDENTIALS,
                CLIENT_ASSERTION to jwt.serialize(),
                SCOPE to scopes
            )

            val (_, certResult, r) = apiClient.fuelManager.post(
                oidcWellKnown.tokenEndpoint, parameters
            ).responseObject<AccessTokenResponse>()


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

    fun getAuthorizationCodeAccessToken(
        apiClient: ApiClient,
        apiUnderTest: ApiUnderTest,
        scopes: String,
        resourceOwner: ResourceOwner,
        responseType: String,
        domainSpecificClaims: List<Pair<String, Any>>
    ): AccessToken {
        val consentHandler = ConsentHandlerFactory.getConsentHandler(apiUnderTest)
        return consentHandler.getAccessToken(apiClient, apiUnderTest, scopes, resourceOwner, responseType, domainSpecificClaims)
    }
}


