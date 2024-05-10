package com.forgerock.sapi.gateway.framework.fapi

import com.forgerock.sapi.gateway.common.constants.DynamicRegistrationConstants

enum class FapiSecurityProfile {
    FAPI_RW, FAPI_1_0_ADVANCED, FAPI_2_0
}

const val PLAIN_FAPI_ACR_CLAIM = "urn:mace:incommon:iap:silver"

class FapiCompliantValues {

    companion object {

        val fapiRWCompliantListValues: Map<String, List<String>> =
            mapOf(DynamicRegistrationConstants.ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM to listOf("ES256", "PS256"))

        val fapi1_0AdvancedValues: Map<String, List<String>> =
            mapOf(DynamicRegistrationConstants.ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM to listOf("ES256", "PS256"))

        fun getFapiCompliantListOfValues(claimName: String, fapiSecurityProfile: FapiSecurityProfile): List<String> {
            when (fapiSecurityProfile) {
                FapiSecurityProfile.FAPI_RW -> {
                    return getFapiRWCompliantValues(claimName)
                }

                FapiSecurityProfile.FAPI_1_0_ADVANCED -> return fapi1_0AdvancedValues[claimName] ?: listOf()

                FapiSecurityProfile.FAPI_2_0 -> TODO()
            }
        }

        fun getFapiRWCompliantValues(claimName: String): List<String> {
            var values = fapiRWCompliantListValues[claimName]
            return values ?: listOf()
        }
    }

}