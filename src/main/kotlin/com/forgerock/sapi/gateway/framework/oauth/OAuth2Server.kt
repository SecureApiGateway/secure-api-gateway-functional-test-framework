package com.forgerock.sapi.gateway.framework.oauth

import com.forgerock.sapi.gateway.common.constants.OAuth2Constants.Companion.CLIENT_ID
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenClientAssertionTypes.Companion.CLIENT_ASSERTION_TYPE_JWT_BEARER
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenGrantTypes.Companion.CLIENT_CREDENTIALS
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.CLIENT_ASSERTION
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.CLIENT_ASSERTION_TYPE
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.GRANT_TYPE
import com.forgerock.sapi.gateway.common.constants.OAuth2TokenRequestConstants.Companion.SCOPE
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager.Loader.apiUnderTest
import com.forgerock.sapi.gateway.framework.configuration.ResourceOwner
import com.forgerock.sapi.gateway.framework.consents.ConsentHandlerFactory
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.http.fuel.initFuel
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.forgerock.sapi.gateway.framework.oidc.OBDirectoryOidcWellKnownResponse
import com.forgerock.sapi.gateway.framework.oidc.OidcWellKnown
import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.Headers
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.JWSAlgorithm

class OAuth2Server(oidcWellKnownUrl: String) {
    // Hack to handle non-standard response from Open Banking Sandbox Directory. Issue raise to have them
    // fix it. https://directory.openbanking.org.uk/obieservicedesk/s/case/500Px000007m9EkIAI/the-sandbox-directory-oidc-well-known-response-does-not-conform-to-oidc-connect-well-known-10-specification
    var oidcWellKnown: OidcWellKnown = if (oidcWellKnownUrl.contains("openbankingtest.org.uk")) {
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
    var grantTypesSupported: List<String> = oidcWellKnown.grantTypesSupported

    data class AuthorizeRequestComponents(val url: String, val parameters: List<Pair<String, String>>)

    fun getClientCredentialsAccessToken(
        apiClient: ApiClient,
        scopes: String
    ): AccessToken {
        val authMethod = TokenEndpointAuthMethod.valueOf(apiClient.tokenEndpointAuthMethod)
        val body = mutableListOf(
            GRANT_TYPE to CLIENT_CREDENTIALS,
            SCOPE to scopes
        )
        if (authMethod == TokenEndpointAuthMethod.private_key_jwt) {
            val clientAssertion =
                apiClient.getClientAssertionJwt(apiUnderTest.oauth2Server.oidcWellKnown.issuer, JWSAlgorithm.PS256)
            body.addAll(
                listOf(
                    CLIENT_ASSERTION_TYPE to CLIENT_ASSERTION_TYPE_JWT_BEARER,
                    CLIENT_ASSERTION to clientAssertion.serialize()
                )
            )
        } else if (authMethod == TokenEndpointAuthMethod.tls_client_auth) {
            body.add(CLIENT_ID to apiClient.clientId)
        }

        val (_, response, result) = apiClient.fuelManager.post(
            apiUnderTest.oauth2Server.oidcWellKnown.tokenEndpoint,
            body
        )
            .header("Content-Type", "application/x-www-form-urlencoded")
            .responseObject<AccessToken>()
        if (!response.isSuccessful) {
            throw AssertionError("Failed to exchange auth code for access token. $response")
        }
        return result.get()
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


