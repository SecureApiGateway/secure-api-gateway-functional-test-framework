package com.forgerock.sapi.gateway.framework.consents

import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.fapi.FapiSecurityProfile
import com.forgerock.sapi.gateway.framework.http.fuel.getLocationHeader
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.ob.uk.support.resourceowner.ResourceOwner
import org.apache.http.HttpStatus
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class AMPlainFAPIConsentHandler private constructor() : ConsentHandler() {

    companion object {

        @Volatile
        private var instance: AMPlainFAPIConsentHandler? = null

        fun getInstance() = instance ?: synchronized(this) {
            instance ?: AMPlainFAPIConsentHandler().also {
                instance = it
                ConsentHandlerFactory.addConsentHandler(FapiSecurityProfile.FAPI_1_0_ADVANCED,
                    AMPlainFAPIConsentHandler())
            }
        }
    }

    override fun getAccessToken(
        apiClient: ApiClient,
        apiUnderTest: ApiUnderTest,
        scopes: String,
        resourceOwner: ResourceOwner,
        responseType: String,
        domainSpecificClaims: List<Pair<String, Any>>
    ): AccessToken {
        val authRequestComponents: OAuth2Server.AuthorizeRequestComponents = getAuthorizeRequestComponents(
            apiClient = apiClient,
            apiUnderTest = apiUnderTest,
            scopes = scopes,
            resourceOwner = resourceOwner,
            responseType = responseType,
            domainSpecificClaims = domainSpecificClaims
        )
        val firstAuthResponse = makeAuthorizeRequest(apiClient, authRequestComponents, listOf())
        val resourceOwnerLoginUrl = getLoginUrlFromAuthResponse(apiUnderTest, firstAuthResponse)
        val authenticationResponse = performResourceOwnerLogin(resourceOwnerLoginUrl, resourceOwner)
        // Cookie will be used to show resource owner is authenticated
        val cookie = "${apiUnderTest.cookieName}=${authenticationResponse.tokenId}"

        // Construct the URI and include the params used in the initial auth request as query params
        // This is required as the Fuel lib will encode the params for a POST as form params, for this
        // request we need a mixture of query and form params in order to submit the request in the same fashion as the
        // AM UI.
        val authUri = URI.create(
            authRequestComponents.url + "?" + authRequestComponents.parameters.map { (key, value) ->
                URLEncoder.encode(
                    key,
                    StandardCharsets.UTF_8
                ) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)
            }.joinToString("&")
        )

        // decision and csrf params are required in the POST body
        // See guide: https://backstage.forgerock.com/docs/am/7.5/oauth2-guide/oauth2-authz-grant.html#proc-auth-code-no-browser
        val formParams = mutableListOf(
            "decision" to "allow",
            "redirect_uri" to apiClient.registrationResponse.redirect_uris[0],
            "csrf" to authenticationResponse.tokenId
        )

        // Note: Post request - this is an AM API to communicate the consent decision
        val (_, response, result) = apiClient.fuelManager.post(authUri.toString(), formParams)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Cookie", cookie)
            .allowRedirects(false)
            .responseString()

        if (response.statusCode != HttpStatus.SC_MOVED_TEMPORARILY) {
            throw AssertionError("Failed to get authorize with cookie")
        }

        val redirectWithAuthCode = response.getLocationHeader()
        val authCode = getAuthCodeFromRedirectURL(redirectWithAuthCode)

        return exchangeCodeForAccessToken(authCode, apiClient, apiUnderTest)
    }
}