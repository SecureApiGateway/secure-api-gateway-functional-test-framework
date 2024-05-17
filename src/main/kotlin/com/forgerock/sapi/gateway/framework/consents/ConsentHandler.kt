package com.forgerock.sapi.gateway.framework.consents

import com.forgerock.sapi.gateway.common.constants.*
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.data.AuthenticationResponse
import com.forgerock.sapi.gateway.framework.http.fuel.getLocationHeader
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.oauth.TokenEndpointAuthMethod
import com.forgerock.sapi.gateway.framework.configuration.ResourceOwner
import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.JWSAlgorithm
import org.apache.http.HttpStatus

abstract class ConsentHandler {
    abstract fun getAccessToken(apiClient: ApiClient,
                                apiUnderTest: ApiUnderTest,
                                scopes: String,
                                resourceOwner: ResourceOwner,
                                responseType: String,
                                domainSpecificClaims: List<Pair<String, Any>>): AccessToken

    open fun getAuthorizeRequestComponents(
        apiClient: ApiClient,
        apiUnderTest: ApiUnderTest,
        scopes: String,
        resourceOwner: ResourceOwner,
        responseType: String,
        domainSpecificClaims: List<Pair<String, Any>>
    ): OAuth2Server.AuthorizeRequestComponents {
        val requestJwtClaimsBuilder = apiClient.getClientAssertionJwtBuilder(
            aud = apiUnderTest.oauth2Server.oidcWellKnown.issuer, scopes = scopes
        )

        for (domainSpecificClaim in domainSpecificClaims) {
            requestJwtClaimsBuilder.claim(domainSpecificClaim.first, domainSpecificClaim.second)
        }
        requestJwtClaimsBuilder.claim(OAuth2AuthorizeRequestJwtClaims.RESPONSE_TYPE, responseType)
        requestJwtClaimsBuilder.claim(OAuth2Constants.REDIRECT_URI, apiClient.redirectUris[0])
        requestJwtClaimsBuilder.claim(OAuth2Constants.CLIENT_ID, apiClient.clientId)

        val requestObjectSigningAlgo =
            apiUnderTest.oauth2Server.oidcWellKnown.requestObjectSigningAlgValuesSupported.firstOrNull()
                ?: JWSAlgorithm.PS256.toString()

        val requestJwt = apiClient.signJwt(
            requestJwtClaimsBuilder.build(),
            JWSAlgorithm.parse(requestObjectSigningAlgo)
        )

        val requestJwtString = requestJwt.serialize()

        val parameters = mutableListOf(
            OAuth2Constants.CLIENT_ID to apiClient.clientId,
            OAuth2AuthorizeRequestJwtClaims.REQUEST to requestJwtString,
            OAuth2AuthorizeRequestJwtClaims.USERNAME to resourceOwner.userName,
            OAuth2AuthorizeRequestJwtClaims.PASSWORD to resourceOwner.userPassword,
            OAuth2TokenRequestConstants.SCOPE to scopes,
            OAuth2AuthorizeRequestJwtClaims.RESPONSE_TYPE to responseType
        )

        val authUrl = apiUnderTest.oauth2Server.oidcWellKnown.authorizationEndpoint
        return OAuth2Server.AuthorizeRequestComponents(authUrl, parameters)
    }

    open fun makeAuthorizeRequest(apiClient: ApiClient, authRequestComponents: OAuth2Server.AuthorizeRequestComponents,
                                  extraParams: List<Pair<String, String>>): Response {

        val augmentedParameters : MutableList<Pair<String, String>> = authRequestComponents.parameters.toMutableList()
        for (param in extraParams) {
            augmentedParameters.add(param)
        }

        val authRequest = apiClient.fuelManager.get(
            authRequestComponents.url,
            parameters = augmentedParameters
        ).header("Content-Type", "application/x-www-form-urlencoded")
            .allowRedirects(false)

        val (_, response, _) = authRequest.responseString()
        if (response.statusCode != HttpStatus.SC_MOVED_TEMPORARILY) {
            throw AssertionError(
                "Could not get authentication URL. Request to ${authRequestComponents.url} " +
                        "produced response $response"
            )
        }
        return response
    }

    open fun getLoginUrlFromAuthResponse(apiUnderTest: ApiUnderTest, authResponse: Response): String {
        try {
            val location = authResponse.getLocationHeader()
            val parameters = location.substring(location.indexOf("?"))
            return "https://sapig." + apiUnderTest.serverDomain + apiUnderTest.authenticatePath + parameters
        } catch (e: Exception) {
            throw AssertionError("Could not obtain location header from Authorization endpoint response")
        }

    }

    open fun performResourceOwnerLogin(
        resourceOwnerLoginUrl: String,
        resourceOwner: ResourceOwner
    ): AuthenticationResponse {
        val (_, response, result) = FuelManager.instance.post(resourceOwnerLoginUrl)
            .header(Pair("X-OpenAM-Username", resourceOwner.userName))
            .header(Pair("X-OpenAM-Password", resourceOwner.userPassword))
            .header("Accept-API-Version", "resource=2.1, protocol=1.0")
            .responseObject<AuthenticationResponse>()
        if (!response.isSuccessful) {
            throw AssertionError("Authorization of Resource Owner ${resourceOwner.userName} failed. $response")
        }
        return result.get()
    }


    open fun getAuthCodeFromRedirectURL(redirectWithAuthCode: String): String {
        return redirectWithAuthCode.substring(
            redirectWithAuthCode.indexOf("code=") + 5,
            redirectWithAuthCode.indexOf("&")
        )
    }

    open fun exchangeCodeForAccessToken(
        authCode: String,
        apiClient: ApiClient,
        apiUnderTest: ApiUnderTest
    ): AccessToken {
        val clientAssertion =
            apiClient.getClientAssertionJwt(apiUnderTest.oauth2Server.oidcWellKnown.issuer, JWSAlgorithm.PS256)
        val body = mutableListOf(
            OAuth2Constants.CLIENT_ID to apiClient.clientId,
            OAuth2TokenRequestConstants.GRANT_TYPE to OAuth2TokenGrantTypes.AUTHORIZATION_CODE,
            OAuth2TokenRequestConstants.CODE to authCode,
            OAuth2Constants.REDIRECT_URI to apiClient.redirectUris[0]
        )
        if (apiClient.tokenEndpointAuthMethod == TokenEndpointAuthMethod.private_key_jwt) {
            body.addAll(
                listOf(
                    OAuth2TokenRequestConstants.CLIENT_ASSERTION_TYPE to OAuth2TokenClientAssertionTypes.CLIENT_ASSERTION_TYPE_JWT_BEARER,
                    OAuth2TokenRequestConstants.CLIENT_ASSERTION to clientAssertion.serialize()
                )
            )
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

}