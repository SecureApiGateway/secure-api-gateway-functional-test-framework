package com.forgerock.sapi.gateway.framework.trusteddirectory

import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.apiclient.ApiClientRegistrationConfig
import com.forgerock.sapi.gateway.framework.configuration.SsaClaimNames

abstract class TrustedDirectory {

    abstract val ssaClaimNames: SsaClaimNames
    var apiClients: MutableMap<String, ApiClient> = mutableMapOf()

    abstract fun getSSA(apiClientRegistrationConfig: ApiClientRegistrationConfig): String
}