package com.forgerock.sapi.gateway.ob.uk.support.resourceowner

import com.forgerock.sapi.gateway.framework.configuration.ResourceOwnerConfig

data class ResourceOwner(private val resourceOwnerConfig: ResourceOwnerConfig) {
    val userName: String = resourceOwnerConfig.username
    val userPassword: String = resourceOwnerConfig.password
}