package com.forgerock.sapi.gateway.common.constants

class DynamicRegistrationConstants {
    companion object {
        const val SOFTWARE_STATEMENT_CLAIM: String = "software_statement"
        const val GRANT_TYPES_CLAIM: String = "grant_types"
        const val ID_TOKEN_SIGNED_RESPONSE_ALG_CLAIM: String = "id_token_signed_response_alg"
        const val REDIRECT_URIS: String = "redirect_uris"
        const val RESPONSE_TYPES: String = "response_types"
        const val TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method"
        const val TOKEN_ENDPOINT_AUTH_SIGNING_ALG = "token_endpoint_auth_signing_alg"
        const val TLS_CLIENT_AUTH_SUBJECT_DN = "tls_client_auth_subject_dn"
        const val SCOPE = "scope"
    }
}