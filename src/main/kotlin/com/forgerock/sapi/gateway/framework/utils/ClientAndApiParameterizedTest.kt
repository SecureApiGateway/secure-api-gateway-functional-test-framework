package com.forgerock.sapi.gateway.framework.utils

import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.configuration.ConfigurationManager
import org.junit.jupiter.api.Named
import org.junit.jupiter.params.provider.Arguments

abstract class ClientAndApiParameterizedTest {
    companion object {

        val parameterizedTestArguments: Map<ApiClient, ApiUnderTest>

        @JvmStatic
        fun getParameterizedTestArgs(): List<Arguments> {
            val args: MutableList<Arguments> = mutableListOf()
            parameterizedTestArguments.forEach { (apiClient, apiUnderTest) ->
                args.add(
                    Arguments.of(
                        Named.of(apiClient.name, apiClient),
                        Named.of(apiUnderTest.name, apiUnderTest)
                    )
                )
            }
            return args
        }

        init {
            parameterizedTestArguments = ConfigurationManager.getApiClientsAndApisUnderTestArguments(
                apiClientsToUse = listOf("all"),
                testWithApiClientFromDevelopmentTrustedDirectory = true
            )
        }
    }
}