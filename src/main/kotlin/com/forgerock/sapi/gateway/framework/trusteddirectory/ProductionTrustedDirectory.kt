package com.forgerock.sapi.gateway.framework.trusteddirectory

import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.apiclient.ApiClientRegistrationConfig
import com.forgerock.sapi.gateway.framework.configuration.ApiClientConfig
import com.forgerock.sapi.gateway.framework.configuration.ProductionTrustedDirectoryConfig
import com.forgerock.sapi.gateway.framework.configuration.SsaClaimNames
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.oauth.register.RegisterApiClient

/**
 * Represents an external trusted directory, such as the UK Open Banking Directory. Such a directory acts as the
 * gatekeeper to the API Ecosystem. It signs public certificates that must be used by the client and the API for TLS
 * connections and for message signing. It issues Software Statement Assertions that can be used by a client to register
 * with an Api Provider.
 */
class ProductionTrustedDirectory(
    val productionTrustedDirectoryConfig: ProductionTrustedDirectoryConfig,
    val oauth2Server: OAuth2Server,
    val softwareStatementProvider: SoftwareStatementProvider,
    val transportCertProvider: CertificateProvider,
    val signingKeyCertProvider: CertificateProvider

) : TrustedDirectory() {

    private val registerApiClient = RegisterApiClient(this)
    
    init {
        for (apiClientConfig in productionTrustedDirectoryConfig.apiClientConfig) {
            val apiClient = createApiClient(apiClientConfig)
            apiClients[apiClient.name] = apiClient
        }
    }

    private fun createApiClient(apiClientConfig: ApiClientConfig): ApiClient {
        return registerApiClient.register(
            createApiClientRegistrationConfig(apiClientConfig)
        )
    }

    fun createApiClientRegistrationConfig(
        apiClientConfig: ApiClientConfig
    ): ApiClientRegistrationConfig {
        val signingKeys = signingKeyCertProvider.getSigningKeys()
        val transportKeys = transportCertProvider.getTransportKeys()
        val socketFactory = transportCertProvider.getSocketFactory()
        return ApiClientRegistrationConfig(
            signingKeys = signingKeys,
            transportKeys = transportKeys,
            socketFactory = socketFactory,
            trustedDirectory = this,
            softwareId = apiClientConfig.softwareId,
            orgId = apiClientConfig.orgId,
            preferredTokenEndpointAuthMethod = apiClientConfig.preferredTokenEndpointAuthMethod)
    }

    override val ssaClaimNames: SsaClaimNames
        get() = productionTrustedDirectoryConfig.ssaClaimNames


    override fun getSSA(apiClientRegistrationConfig: ApiClientRegistrationConfig): String {
        val ssaUrl = this.productionTrustedDirectoryConfig.ssaUrl.replace("{org_id}", apiClientRegistrationConfig.orgId)
            .replace("{software_id}", apiClientRegistrationConfig.softwareId)
        val ssa = softwareStatementProvider.getSoftwareStatementAssertion(
            apiClientRegistrationConfig = apiClientRegistrationConfig,
            oauth2Server = oauth2Server,
            directorySsaUrl = ssaUrl,
            scopesToAccessSsa = productionTrustedDirectoryConfig.scopesToAccessSsa
        )

        return ssa
    }

}