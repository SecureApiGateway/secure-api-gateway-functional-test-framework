package com.forgerock.sapi.gateway.framework.configuration

import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.consents.AMPlainFAPIConsentHandler
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.trusteddirectory.ProductionTrustedDirectory
import com.forgerock.sapi.gateway.framework.trusteddirectory.SoftwareStatementProviders.OAuth2SoftwareStatementProvider
import com.forgerock.sapi.gateway.framework.trusteddirectory.certificateproviders.FileCertificateProvider
import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.addResourceSource
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.extension.BeforeAllCallback
import org.junit.jupiter.api.extension.ExtensionContext
import java.security.Security


@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class WithApiClient(
    val apiClients: Array<String> = []
)

@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class ApisUnderTest(
    val apisUnderTest: Array<String> = []
)

class ConfigurationManager(private val filePath: String = EXTERNAL_SYSTEM_DEPENDENCIES_CONFIG_FILE_PATH) :
    BeforeAllCallback {

    companion object Loader {

        fun createConsentHandlers() {
            AMPlainFAPIConsentHandler.getInstance()
        }

        init {
            createConsentHandlers()
        }

        val configFilePath = EXTERNAL_SYSTEM_DEPENDENCIES_CONFIG_FILE_PATH
        lateinit var trustedDirectory: ProductionTrustedDirectory
        lateinit var apiUnderTest: ApiUnderTest

        fun loadConfig(): ExternalSystemDependenciesConfig {
            val config = ConfigLoaderBuilder.default()
                .addResourceSource(configFilePath)
                .build()
                .loadConfigOrThrow<ExternalSystemDependenciesConfig>()

            println("Found config for Trusted Directory called '${config.trustedDirectory.name}'")
            return config
        }

        fun getApiClientsAndApisUnderTestArguments(
            apiClientsToUse: List<String>,
            testWithApiClientFromDevelopmentTrustedDirectory: Boolean
        ): Map<ApiClient, ApiUnderTest> {
            val apiClientsAndApisToTest: MutableMap<ApiClient, ApiUnderTest> = mutableMapOf()

            if (testWithApiClientFromDevelopmentTrustedDirectory) {
                apiUnderTest.devTrustedDirectory.apiClients.forEach { (_, devApiClient) ->
                    apiClientsAndApisToTest[devApiClient] = apiUnderTest
                }
            }

            trustedDirectory.apiClients.forEach { (_, prodApiClient) ->
                if (apiClientsToUse.contains("all") || apiClientsToUse.contains(prodApiClient.name)) {
                    apiClientsAndApisToTest[prodApiClient] = apiUnderTest
                }
            }


            return apiClientsAndApisToTest
        }

        fun getApiClients(): List<ApiClient> {
            var apiClients: MutableList<ApiClient> = mutableListOf()
            apiUnderTest.devTrustedDirectory.apiClients.forEach { (_, devApiClient) ->
                apiClients.add(devApiClient)
            }
            trustedDirectory.apiClients.forEach { (_, apiClient) ->
                apiClients.add(apiClient)
            }
            return apiClients
        }
    }

    override fun beforeAll(context: ExtensionContext?) {
        Security.addProvider(BouncyCastleProvider())
        val config = loadConfig()
        val variables = getVariableValues(config.variables)
        doVariableSubstitution(config, variables)

        println("Creating TPP using ${config.trustedDirectory.name}")
        for (apiClientConfig in config.trustedDirectory.apiClients) {
            val certificateProvider = FileCertificateProvider(apiClientConfig)
            val softwareStatementProvider = OAuth2SoftwareStatementProvider()
            val oauth2Server = OAuth2Server(config.trustedDirectory.openidWellKnown)
            trustedDirectory = ProductionTrustedDirectory(
                config.trustedDirectory,
                oauth2Server,
                softwareStatementProvider, certificateProvider, certificateProvider
            )
        }
        apiUnderTest = ApiUnderTest(config.apiUnderTest)
    }

    private fun getVariableValues(variables: List<String>): Map<String, String> {
        val variableVals: MutableMap<String, String> = mutableMapOf()
        for (variable in variables) {
            val envVar = System.getenv(variable)
            if (envVar == null) {
                throw Exception("Variable $variable defined in config file does not have an environment variable $variable set")
            } else {
                variableVals[variable] = envVar
            }
        }
        return variableVals
    }
}