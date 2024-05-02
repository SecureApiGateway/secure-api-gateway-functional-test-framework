package com.forgerock.sapi.gateway.common.constants

class OAuth2Constants {
    companion object {
        const val REDIRECT_URI = "redirect_uri"
        const val SCOPE = "scope"
        const val CLIENT_ID = "client_id"
        const val NONCE = "nonce"
        const val STATE = "state"
    }
}

class OAuth2TokenRequestConstants {
    companion object {
        const val GRANT_TYPE = "grant_type"
        const val CODE = "code"
        const val REDIRECT_URI = "redirect_uri"

        const val CLIENT_ASSERTION_TYPE = "client_assertion_type"
        const val CLIENT_ASSERTION = "client_assertion"
        const val SCOPE = "scope"
    }
}

class OAuth2TokenClientAssertionTypes {
    companion object {
        const val CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    }
}

class OAuth2TokenGrantTypes {
    companion object {
        const val CLIENT_CREDENTIALS = "client_credentials"
        const val AUTHORIZATION_CODE = "authorization_code"
    }
}

class OAuth2AccessTokenResponse {
    companion object {
        const val ACCESS_TOKEN = "access_token"
        const val TOKEN_TYPE = "token_type"
        const val EXPIRES_IN = "expires_in"
        const val REFRESH_TOKEN = "refresh_token"
        const val SCOPE = "scope"
    }
}

class OAuth2AuthorizeRequestJwtClaims {
    companion object {

        const val CLAIMS = "claims"
        const val RESPONSE_TYPE = "response_type"
        const val REQUEST = "request"
        const val USERNAME = "username"
        const val PASSWORD = "password"
    }
}

class OAuth2AuthorizeResponseParams {
    companion object {
        const val ERROR_DESCRIPTION = "error_description"
    }
}

