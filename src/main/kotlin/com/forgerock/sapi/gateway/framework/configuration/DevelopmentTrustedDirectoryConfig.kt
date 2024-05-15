package com.forgerock.sapi.gateway.framework.configuration

data class DevelopmentTrustedDirectoryConfig(
    val name: String,
    var getKeysUrl: String,
    var getTransportPemsUrl: String,
    var getSigningPemsUrl: String,
    var getSsaUrl: String,
    val ssaClaimNames: SsaClaimNames,
    var oidcWellKnownUrl: String,
    val roles: List<String>?
)