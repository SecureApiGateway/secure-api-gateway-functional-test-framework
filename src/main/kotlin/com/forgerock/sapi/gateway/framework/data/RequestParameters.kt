package com.forgerock.sapi.gateway.framework.data

import com.forgerock.sapi.gateway.framework.configuration.REDIRECT_URI
import java.util.UUID

data class RequestParameters(
    val aud: String,
    val claims: Claims,
    val client_id: String,
    val exp: Long = System.currentTimeMillis() / 1000 + 600,
    val iat: Long = System.currentTimeMillis() / 1000,
    val nbf: Long = System.currentTimeMillis() / 1000,
    val jti: UUID = UUID.randomUUID(),
    val iss: String,
    val nonce: String = UUID.randomUUID().toString(),
    val redirect_uri: String = REDIRECT_URI,
    val response_type: String = "code id_token",
    val scope: String
) {
    data class Claims(
            val id_token: IdToken,
            val userinfo: Userinfo?
    ) {
        data class IdToken(
                val acr: Acr,
                val openbanking_intent_id: OpenbankingIntentId?
        ) {
            data class OpenbankingIntentId(
                val essential: Boolean,
                val value: String
            )

            data class Acr(
                val essential: Boolean,
                val value: String
            )
        }

        data class Userinfo(
            val openbanking_intent_id: OpenbankingIntentId
        ) {
            data class OpenbankingIntentId(
                val essential: Boolean,
                val value: String
            )
        }
    }
}
