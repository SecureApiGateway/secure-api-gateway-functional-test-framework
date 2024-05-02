package com.forgerock.sapi.gateway.framework.configuration

data class ApiConfig(
    var name: String,
    var serverDomain: String,
    val cookieName: String,
    var oidcWellKnownUrl: String,
    var rsDiscoveryUrl: String,
    val fapiSecurityProfile: String,
    val authenticatePath: String,
    val resourceOwners: List<ResourceOwnerConfig>,
    val devTrustedDirectory: DevelopmentTrustedDirectoryConfig
)