package com.forgerock.sapi.gateway.framework.configuration

/**
 * This class is initialized by Jackson from the config file specified in Config.kt
 */
data class ExternalSystemDependenciesConfig(
    val variables: List<String>,
    val trustedDirectory: ProductionTrustedDirectoryConfig,
    val apiUnderTest: ApiConfig
)

fun doVariableSubstitution(systemDependenciesConfig: ExternalSystemDependenciesConfig, variables: Map<String, String>){
    systemDependenciesConfig.trustedDirectory.name =
        substituteVariables(systemDependenciesConfig.trustedDirectory.name, variables)
    systemDependenciesConfig.trustedDirectory.jwks_uri =
        substituteVariables(systemDependenciesConfig.trustedDirectory.jwks_uri, variables)
    systemDependenciesConfig.trustedDirectory.openidWellKnown =
        substituteVariables(systemDependenciesConfig.trustedDirectory.openidWellKnown, variables)
    systemDependenciesConfig.trustedDirectory.ssaUrl =
        substituteVariables(systemDependenciesConfig.trustedDirectory.ssaUrl, variables)
    systemDependenciesConfig.trustedDirectory.scopesToAccessSsa =
        substituteVariables(systemDependenciesConfig.trustedDirectory.scopesToAccessSsa, variables)

    systemDependenciesConfig.apiUnderTest.name =
        substituteVariables(systemDependenciesConfig.apiUnderTest.name, variables)
    systemDependenciesConfig.apiUnderTest.serverDomain =
        substituteVariables(systemDependenciesConfig.apiUnderTest.serverDomain, variables)
    systemDependenciesConfig.apiUnderTest.oidcWellKnownUrl =
        substituteVariables(systemDependenciesConfig.apiUnderTest.oidcWellKnownUrl, variables)
    systemDependenciesConfig.apiUnderTest.rsDiscoveryUrl =
        substituteVariables(systemDependenciesConfig.apiUnderTest.rsDiscoveryUrl, variables)

    systemDependenciesConfig.apiUnderTest.devTrustedDirectory.oidcWellKnownUrl =
        substituteVariables(systemDependenciesConfig.apiUnderTest.devTrustedDirectory.oidcWellKnownUrl, variables)

    systemDependenciesConfig.apiUnderTest.devTrustedDirectory.getKeysUrl =
        substituteVariables(systemDependenciesConfig.apiUnderTest.devTrustedDirectory.getKeysUrl, variables)
    systemDependenciesConfig.apiUnderTest.devTrustedDirectory.getTransportPemsUrl =
        substituteVariables(systemDependenciesConfig.apiUnderTest.devTrustedDirectory.getTransportPemsUrl, variables)
    systemDependenciesConfig.apiUnderTest.devTrustedDirectory.getSigningPemsUrl =
        substituteVariables(systemDependenciesConfig.apiUnderTest.devTrustedDirectory.getSigningPemsUrl, variables)
    systemDependenciesConfig.apiUnderTest.devTrustedDirectory.getSsaUrl =
        substituteVariables(systemDependenciesConfig.apiUnderTest.devTrustedDirectory.getSsaUrl, variables)
}

fun substituteVariables(templateValue: String, variables: Map<String, String>): String{
    var substitutedString = templateValue
    for(variable in variables){
        substitutedString = substituteVariable(substitutedString, "{{${variable.key}}}", variable.value)
    }
    return substitutedString
}

fun substituteVariable(templateValue: String, variableName: String, variableValue: String): String{
    return templateValue.replace(variableName, variableValue)
}