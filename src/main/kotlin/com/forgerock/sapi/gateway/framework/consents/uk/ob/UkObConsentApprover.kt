package com.forgerock.sapi.gateway.framework.consents.uk.ob

import com.github.kittinunf.fuel.core.Response

interface UkObConsentApprover {

    data class SendConsentDecisionRequestBody(
        val consentJwt: String, val decision: String, val accountIds: List<String>
    )

    data class SendConsentDecisionResponseBody(val consentJwt: String, val redirectUri: String)

    fun approveConsent(response: Response, cookie: String): SendConsentDecisionResponseBody
}