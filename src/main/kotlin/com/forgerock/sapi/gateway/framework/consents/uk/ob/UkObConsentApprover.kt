package com.forgerock.sapi.gateway.framework.consents.uk.ob

import com.forgerock.sapi.gateway.ob.uk.support.general.GeneralAS
import com.github.kittinunf.fuel.core.Response

interface UkObConsentApprover {
    fun approveConsent(response: Response, cookie: String): GeneralAS.SendConsentDecisionResponseBody
}