package com.forgerock.sapi.gateway.framework.trusteddirectory

import com.forgerock.sapi.gateway.framework.apiclient.ApiClientRegistrationConfig
import com.forgerock.sapi.gateway.framework.configuration.DevelopmentTrustedDirectoryConfig
import com.forgerock.sapi.gateway.framework.configuration.SsaClaimNames
import com.forgerock.sapi.gateway.framework.http.fuel.getFuelManager
import com.forgerock.sapi.gateway.framework.http.fuel.jsonBody
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.oauth.TokenEndpointAuthMethod
import com.forgerock.sapi.gateway.framework.oauth.register.RegisterApiClient
import com.forgerock.sapi.gateway.framework.platform.register.SoftwareStatementRequest
import com.forgerock.sapi.gateway.framework.trusteddirectory.certificateproviders.ApiCertificateProvider
import com.github.kittinunf.fuel.core.Headers
import com.github.kittinunf.fuel.core.isSuccessful
import java.util.UUID

class DevelopmentTrustedDirectory(
    val developerTrustedDirectoryConfig: DevelopmentTrustedDirectoryConfig,
    val certificateProvider: ApiCertificateProvider,
) : TrustedDirectory() {

    val oauth2Server: OAuth2Server = OAuth2Server(developerTrustedDirectoryConfig.oidcWellKnownUrl)
    init {
        val apiClient = RegisterApiClient(this).register(
            ApiClientRegistrationConfig(
                signingKeys = certificateProvider.getSigningKeys(),
                transportKeys = certificateProvider.getTransportKeys(),
                socketFactory = certificateProvider.getSocketFactory(),
                trustedDirectory = this,
                softwareId = UUID.randomUUID().toString(),
                orgId = UUID.randomUUID().toString(),
                preferredTokenEndpointAuthMethod = TokenEndpointAuthMethod.private_key_jwt
            )
        )
        apiClients[apiClient.name] = apiClient
    }

    override val ssaClaimNames: SsaClaimNames
        get() = developerTrustedDirectoryConfig.ssaClaimNames


    override fun getSSA(apiClientRegistrationConfig: ApiClientRegistrationConfig): String {
        val ssaUrl = developerTrustedDirectoryConfig.getSsaUrl

        val fuelManager = getFuelManager(apiClientRegistrationConfig.socketFactory)
        val (_, response, result) = fuelManager.post(ssaUrl)
            .jsonBody(getSoftwareStatementClaims(apiClientRegistrationConfig.softwareId))
            .header(Headers.CONTENT_TYPE, "application/json")
            .response()

        if (response.isSuccessful) {
            val softwareStatementAssertion = result.get()
            println("Software Statement is ${softwareStatementAssertion}")
            return softwareStatementAssertion.decodeToString()
        } else {
            throw Exception("Failed to obtain SSA from development trusted directory at $ssaUrl")
        }
    }

    private fun getSoftwareStatementClaims(softwareId: String): SoftwareStatementRequest {
        val softwareStatementRequest = SoftwareStatementRequest(
            software_id = softwareId,
            software_client_name = "FAPI Functional Test Suite",
            software_client_id = softwareId,
            software_tos_uri = "https://github.com/SecureApiGateway",
            software_client_description = "FAPI Functional Test Suite",
            software_redirect_uris = listOf("https://www.google.com", "https://postman-echo.com/get"),
            software_policy_uri = "https://github.com/SecureApiGateway",
            software_logo_uri = "https://avatars.githubusercontent.com/u/74596995?s=96&v=4",
            software_roles = getSupportedRoles(),
            software_jwks = certificateProvider.jwkSet
        )
        return softwareStatementRequest
    }

    private fun getSupportedRoles(): List<String> {
        var roles: List<String> = mutableListOf()
        developerTrustedDirectoryConfig.roles?.let {
            roles = developerTrustedDirectoryConfig.roles
        }
        return roles
    }
}