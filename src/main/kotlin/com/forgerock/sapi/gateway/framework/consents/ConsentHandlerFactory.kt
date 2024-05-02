package com.forgerock.sapi.gateway.framework.consents

import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.fapi.FapiSecurityProfile

class ConsentHandlerFactory (){

    companion object{
        private val consentHandlers: MutableMap<FapiSecurityProfile, ConsentHandler> = mutableMapOf()

        fun getConsentHandler(apiUnderTest: ApiUnderTest): ConsentHandler {
            val handler: ConsentHandler = when (apiUnderTest.fapiSecurityProfile){
                FapiSecurityProfile.FAPI_RW -> consentHandlers[FapiSecurityProfile.FAPI_RW]


                FapiSecurityProfile.FAPI_1_0_ADVANCED -> consentHandlers[FapiSecurityProfile.FAPI_1_0_ADVANCED]
                FapiSecurityProfile.FAPI_2_0 -> TODO()
            } ?: throw Exception("No handler for api with fapiSecurityProfile of ${apiUnderTest.fapiSecurityProfile}")

            return handler
        }

        fun addConsentHandler(fapiProfile: FapiSecurityProfile, consentHandler: ConsentHandler) {
            consentHandlers[fapiProfile] = consentHandler
        }
    }
}