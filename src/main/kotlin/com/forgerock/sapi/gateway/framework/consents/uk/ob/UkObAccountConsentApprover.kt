package com.forgerock.sapi.gateway.framework.consents.uk.ob

import com.forgerock.sapi.gateway.framework.configuration.IG_SERVER
import com.forgerock.sapi.gateway.framework.configuration.RCS_DECISION_API_URI
import com.forgerock.sapi.gateway.framework.consents.uk.ob.UkObConsentApprover.SendConsentDecisionRequestBody
import com.forgerock.sapi.gateway.framework.consents.uk.ob.UkObConsentApprover.SendConsentDecisionResponseBody
import com.forgerock.sapi.gateway.framework.http.fuel.getLocationHeader
import com.forgerock.sapi.gateway.framework.http.fuel.jsonBody
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.core.isSuccessful
import com.google.gson.JsonParser

class UkObAccountConsentApprover: UkObConsentApprover {

    override fun approveConsent(response: Response, cookie: String): SendConsentDecisionResponseBody {
        // Location Header will contain the Consent URL which will contain the consent_request_jwt signed by P1AIC
        val consentURL = response.getLocationHeader()
        val consentRequestJwt = consentURL.substring(consentURL.indexOf("=") + 1)
        val consentDetails = getConsentDetails(consentRequestJwt, cookie)
        val accountIds = getAccountIdsFromConsentDetails(consentDetails)
        return sendConsentDecision(consentRequestJwt, accountIds, cookie)
    }

    private fun sendConsentDecision(consentRequestJwt: String, consentedAccount: List<String>, cookie: String):
            SendConsentDecisionResponseBody {
        val body = SendConsentDecisionRequestBody(consentRequestJwt, "Authorised", consentedAccount)
        val (_, response, result) = Fuel.post(RCS_DECISION_API_URI)
            .header("Cookie", cookie)
            .jsonBody(body)
            .responseObject<SendConsentDecisionResponseBody>()
        if (!response.isSuccessful) throw AssertionError(
            "Could not send consent decision",
            result.component2()
        )
        return result.get()
    }

    private fun getAccountIdsFromConsentDetails(consentDetails: String): List<String> {
        try {
            val str = JsonParser().parse(consentDetails).asJsonObject
            val accountsIds = ArrayList<String>()
            val accounts = str.getAsJsonArray("accounts")
            for (account in accounts) {
                val id = account.asJsonObject.get("id").asString
                accountsIds.add(id)
            }
            return accountsIds
        } catch (e: Exception) {
            throw AssertionError(
                "The response body doesn't have the expected format"
            )
        }
    }

    fun getConsentDetails(consentRequest: String, cookie: String): String {
        val requestUrl = "$IG_SERVER/rcs/api/consent/details"
        val (_, response, result) = Fuel.post(requestUrl)
            .header("Cookie", cookie)
            .body(consentRequest)
            .header("Content-Type", "application/jwt")
            .responseString()
        if (!response.isSuccessful) throw AssertionError(
            "Could not get the consent details",
            result.component2()
        )
        return result.get()
    }
}