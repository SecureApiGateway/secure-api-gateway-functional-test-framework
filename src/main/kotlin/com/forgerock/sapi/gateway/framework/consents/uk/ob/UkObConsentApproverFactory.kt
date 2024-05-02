package com.forgerock.sapi.gateway.framework.consents.uk.ob

class UkObConsentApproverFactory {
    companion object {
        fun getApprover(consentType: UkObConsentType): UkObConsentApprover {
            when (consentType) {
                UkObConsentType.ACCOUNT -> {
                    return UkObAccountConsentApprover()
                }
            }
        }
    }
}