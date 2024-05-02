package com.forgerock.sapi.gateway.framework.utils

import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager

abstract class MultipleApiClientTest {
    companion object {
        @JvmStatic
        fun getApiClients(): List<ApiClient> {
            return ConfigurationManager.getApiClients()
        }
    }
}