package com.forgerock.sapi.gateway.framework.api

import com.forgerock.sapi.gateway.framework.configuration.ApiConfig
import com.forgerock.sapi.gateway.framework.fapi.FapiSecurityProfile
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.oidc.OidcWellKnown
import com.forgerock.sapi.gateway.framework.trusteddirectory.DevelopmentTrustedDirectory
import com.forgerock.sapi.gateway.framework.trusteddirectory.SoftwareStatementProviders.OAuth2SoftwareStatementProvider
import com.forgerock.sapi.gateway.framework.trusteddirectory.certificateproviders.ApiCertificateProvider
import com.forgerock.sapi.gateway.framework.configuration.ResourceOwner

/**
 * Represents the API Under test
 */
class ApiUnderTest(val apiConfig: ApiConfig) {
    val name: String
    val serverDomain: String
    val oauth2Server: OAuth2Server
    val fapiSecurityProfile: FapiSecurityProfile = FapiSecurityProfile.valueOf(apiConfig.fapiSecurityProfile)
    val devTrustedDirectory: DevelopmentTrustedDirectory
    val authenticatePath: String = apiConfig.authenticatePath
    val resourceOwners: MutableList<ResourceOwner> = mutableListOf()
    val cookieName = apiConfig.cookieName

    fun getOidcWellKnown(): OidcWellKnown {
        return oauth2Server.oidcWellKnown
    }

    fun getEndpointUrl(endpointName: String): String{
        // TODO: Get URL from Discovery Endpoint
        return "https://mtls.sapig.${apiConfig.serverDomain}/rs/fapi/api"
    }


    init {
        oauth2Server = OAuth2Server(oidcWellKnownUrl = apiConfig.oidcWellKnownUrl)
        name = apiConfig.name
        serverDomain = apiConfig.serverDomain
        val devDirectoryConfig = apiConfig.devTrustedDirectory
        println("Creating DevelopmentTrustedDirectory $devDirectoryConfig.name")
        val apiCertificateProvider = ApiCertificateProvider(devDirectoryConfig)
        val softwareStatementProvider = OAuth2SoftwareStatementProvider()
        devTrustedDirectory = DevelopmentTrustedDirectory(
            devDirectoryConfig,
            apiCertificateProvider, softwareStatementProvider
        )

        apiConfig.resourceOwners.forEach {
            resourceOwners.add(ResourceOwner(it))
        }
    }

}