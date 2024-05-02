package com.forgerock.sapi.gateway.framework.trusteddirectory

import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.configuration.ApiClientConfig
import com.forgerock.sapi.gateway.framework.configuration.ProductionTrustedDirectoryConfig
import com.forgerock.sapi.gateway.framework.configuration.SsaClaimNames
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server

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

    // ToDo: OAuth2Server needs to be pass in via constructor to make this class testable
    // val oauth2Server: OAuth2Server = OAuth2Server(productionTrustedDirectoryConfig.openidWellKnown)

    init {
        for (apiClientConfig in productionTrustedDirectoryConfig.ApiClients) {
            val apiClient = createApiClient(apiClientConfig)
            apiClients[apiClient.name] = apiClient
        }
    }

    fun createApiClient(apiClientConfig: ApiClientConfig): ApiClient {
        val signingKeys = signingKeyCertProvider.getSigningKeys()
        val transportKeys = transportCertProvider.getTransportKeys()
        val socketFactory = transportCertProvider.getSocketFactory()
        return ApiClient(
            signingKeys = signingKeys,
            transportKeys = transportKeys,
            socketFactory = socketFactory,
            this,
            softwareId = apiClientConfig.softwareId,
            orgId = apiClientConfig.orgId,
        )
    }

    override val ssaClaimNames: SsaClaimNames
        get() = productionTrustedDirectoryConfig.ssaClaimNames

    override fun getSSA(apiClient: ApiClient): String {
        val ssaUrl = this.productionTrustedDirectoryConfig.ssaUrl.replace("{org_id}", apiClient.orgId)
            .replace("{software_id}", apiClient.softwareId)
        val ssa = softwareStatementProvider.getSoftwareStatementAssertion(
            apiClient = apiClient,
            oauth2Server = oauth2Server,
            directorySsaUrl = ssaUrl,
            scopesToAccessSsa = productionTrustedDirectoryConfig.scopesToAccessSsa
        )

        return ssa
    }

    private fun getSsaUrl(apiClient: ApiClient): String {
        return productionTrustedDirectoryConfig.ssaUrl
            .replace("{org_id}", apiClient.orgId, true)
            .replace("{software_id}", apiClient.softwareId, true)
    }

}