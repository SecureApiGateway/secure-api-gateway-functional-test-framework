package com.forgerock.sapi.gateway.framework.oauth

enum class TokenEndpointAuthMethod {
    client_secret_basic, client_secret_post, private_key_jwt, tls_client_auth
}