package com.forgerock.sapi.gateway.framework.apiclient

import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import com.forgerock.sapi.gateway.framework.oauth.TokenEndpointAuthMethod
import com.forgerock.sapi.gateway.framework.trusteddirectory.TrustedDirectory
import javax.net.ssl.SSLSocketFactory

/**
 * Configuration capturing the data required to register an ApiClient
 */
data class ApiClientRegistrationConfig(
    val signingKeys: KeyPairHolder,
    val transportKeys: KeyPairHolder,
    val socketFactory: SSLSocketFactory,
    val trustedDirectory: TrustedDirectory,
    val softwareId: String,
    val orgId: String,
    // Preferred, the registration may use a different method if the server does not support this one
    val preferredTokenEndpointAuthMethod: TokenEndpointAuthMethod
)