package com.forgerock.sapi.gateway.framework.configuration

data class ResourceOwner(private val resourceOwnerConfig: ResourceOwnerConfig) {
    val userName: String = resourceOwnerConfig.username
    val userPassword: String = resourceOwnerConfig.password
}