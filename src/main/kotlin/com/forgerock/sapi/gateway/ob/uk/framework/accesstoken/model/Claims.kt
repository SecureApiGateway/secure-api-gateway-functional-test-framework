package com.forgerock.sapi.gateway.ob.uk.framework.accesstoken.model

data class ClaimsTest(
        val iss: String = com.forgerock.sapi.gateway.ob.uk.framework.configuration.OB_SOFTWARE_ID,
        val sub: String = com.forgerock.sapi.gateway.ob.uk.framework.configuration.OB_SOFTWARE_ID,
        val scope: String = com.forgerock.sapi.gateway.ob.uk.framework.configuration.UK_OPEN_BANKING_DIRECTORY_TPP_SCOPES,
        val aud: String = com.forgerock.sapi.gateway.ob.uk.framework.configuration.AUDIENCE_SANDBOX,
        val exp: Long = (System.currentTimeMillis() / 1000) + 180,
)
