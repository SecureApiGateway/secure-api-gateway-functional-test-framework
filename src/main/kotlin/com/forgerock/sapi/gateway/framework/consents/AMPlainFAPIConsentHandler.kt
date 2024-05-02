package com.forgerock.sapi.gateway.framework.consents

import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.fapi.FapiSecurityProfile
import com.forgerock.sapi.gateway.framework.http.fuel.getLocationHeader
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.ob.uk.support.resourceowner.ResourceOwner
import org.apache.http.HttpStatus

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
        var authRequestComponents: OAuth2Server.AuthorizeRequestComponents = getAuthorizeRequestComponents(
            apiClient = apiClient,
            apiUnderTest = apiUnderTest,
            scopes = scopes,
            resourceOwner = resourceOwner,
            responseType = responseType,
            domainSpecificClaims = domainSpecificClaims
        )
        val firstAuthResponse = makeAuthorizeRequest(apiClient, authRequestComponents, listOf())
        val resourceOwnerLoginUrl = getLoginUrlFromAuthResponse(apiUnderTest, firstAuthResponse)
        val (cookieValue, successUrl, _) = performResourceOwnerLogin(resourceOwnerLoginUrl, resourceOwner)
        // Cookie will be used to show resource owner is authenticated
        val cookie = "${apiUnderTest.cookieName}=${cookieValue}"

        val extraParams: MutableList<Pair<String, Any>> = mutableListOf("Cookie" to cookie, "decision" to "allow", "redirect_uri" to apiClient.registrationResponse.redirect_uris[0])
        extraParams.addAll(authRequestComponents.parameters)

        val (_, response, result) = apiClient.fuelManager.post(
            authRequestComponents.url,
            extraParams
        ).header("Content-Type", "application/x-www-form-urlencoded")
            .header("Cookie", cookie)
            .allowRedirects(false)
            .responseString()

       // val successAuthResponse = makeAuthorizeRequest(apiClient, authRequestComponents, extraParams)

        if (response.statusCode != HttpStatus.SC_MOVED_TEMPORARILY) {
            throw AssertionError("Failed to get authorize with cookie")
        }

        val redirectWithAuthCode = response.getLocationHeader()
        val authCode = getAuthCodeFromRedirectURL(redirectWithAuthCode)

        return exchangeCodeForAccessToken(authCode, apiClient, apiUnderTest)
    }
}