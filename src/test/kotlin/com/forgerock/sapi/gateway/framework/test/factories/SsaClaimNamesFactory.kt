package com.forgerock.sapi.gateway.framework.test.factories

import com.forgerock.sapi.gateway.framework.configuration.SsaClaimNames

/**
 * Factory to create a configured object that may be used in unit tests of the framework itself
 */
class SsaClaimNamesFactory {
    companion object {
        fun getSsaClaimsNames(): SsaClaimNames {
            return SsaClaimNames(redirectUris = "redirect_uris")
        }
    }
}