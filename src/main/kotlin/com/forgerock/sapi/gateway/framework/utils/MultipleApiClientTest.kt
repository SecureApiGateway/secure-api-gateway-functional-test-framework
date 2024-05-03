package com.forgerock.sapi.gateway.framework.utils

import assertk.assertThat
import assertk.assertions.isGreaterThanOrEqualTo
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager
import org.junit.jupiter.api.BeforeAll

abstract class MultipleApiClientTest {

    companion object {
        @JvmStatic
        fun getApiClients(): List<ApiClient> {
            return ConfigurationManager.getApiClients()
        }

        @JvmStatic
        @BeforeAll
        fun validateConfig() {
            assertThat(getApiClients().size).isGreaterThanOrEqualTo(2)
        }
    }
}