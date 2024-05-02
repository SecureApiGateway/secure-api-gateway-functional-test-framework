package com.forgerock.sapi.gateway.common.constants

class OpenIDConnectWellKnownMetadataNames {
    companion object {
        const val TOKEN_ENDPOINT = "token_endpoint"
        const val TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = "token_endpoint_auth_methods_supported"
        const val TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = "token_endpoint_auth_signing_alg_values_supported"
        const val ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "id_token_signing_alg_values_supported"
        const val REQUEST_PARAMETER_SUPPORTED = "request_parameter_supported"
        const val REGISTRATION_ENDPOINT = "registration_endpoint"
        const val ISSUER = "issuer"
        const val GRANT_TYPES_SUPPORTED = "grant_types_supported"
        const val JWKS_URI = "jwks_uri"
        const val SCOPES_SUPPORTED = "scopes_supported"
        const val RESPONSE_TYPES_SUPPORTED = "response_types_supported"
        const val AUTHORIZATION_ENDPOINT = "authorization_endpoint"
        const val REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED = "request_object_signing_alg_values_supported"
    }
}