package com.forgerock.sapi.gateway.framework.test.factories

import com.forgerock.sapi.gateway.framework.configuration.ApiClientConfig
import java.util.*

/**
 * Factory to create a configured object that may be used in unit tests of the framework itself
 */
class ApiClientConfigFactory {
    companion object {
        fun getApiClientConfigs(noOfClients: Int): List<ApiClientConfig> {
            val apiClientConfigs : MutableList<ApiClientConfig> = mutableListOf()
            for(i in 0..noOfClients) {
                apiClientConfigs.add(ApiClientConfig(
                    orgId = UUID.randomUUID().toString(),
                    softwareId = UUID.randomUUID().toString(),
                    publicTransportKeyID = UUID.randomUUID().toString(),
                    publicTransportPemPath = "/tmp/obwac.pem",
                    privateTransportPemPath = "/tmp/obwac.key",
                    publicSigningKeyID = UUID.randomUUID().toString(),
                    publicSigningPemPath = "/tmp/obsign.pem",
                    privateSigningPemPath = "/tmp/obsign.key"
                )
                )
            }
            return apiClientConfigs
        }
    }
}