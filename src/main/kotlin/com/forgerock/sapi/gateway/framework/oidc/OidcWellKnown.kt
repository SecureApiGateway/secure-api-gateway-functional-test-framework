package com.forgerock.sapi.gateway.framework.oidc

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.AUTHORIZATION_ENDPOINT
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.GRANT_TYPES_SUPPORTED
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.ISSUER
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.JWKS_URI
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.REGISTRATION_ENDPOINT
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.REQUEST_PARAMETER_SUPPORTED
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.RESPONSE_TYPES_SUPPORTED
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.SCOPES_SUPPORTED
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.TOKEN_ENDPOINT
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
import com.forgerock.sapi.gateway.common.constants.OpenIDConnectWellKnownMetadataNames.Companion.TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED
import com.forgerock.sapi.gateway.framework.oauth.TokenEndpointAuthMethod

@JsonInclude(JsonInclude.Include.NON_NULL)
data class OidcWellKnown(
    @JsonProperty(TOKEN_ENDPOINT) val tokenEndpoint: String,
    @JsonProperty(TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED) val tokenEndpointAuthMethodsSupported: List<TokenEndpointAuthMethod>,
    @JsonProperty(TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED) val tokenEndpointAuthSigningAlgValuesSupported: List<String>,
    @JsonProperty(JWKS_URI) val jwksUri: String,
    @JsonProperty(ISSUER) val issuer: String,
    @JsonProperty(GRANT_TYPES_SUPPORTED) val grantTypesSupported: List<String>,
    @JsonProperty(ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED) val idTokenSigningAlgValuesSupported: List<String>,
    @JsonProperty(REQUEST_PARAMETER_SUPPORTED) val requestParameterSupported: Boolean,
    @JsonProperty(REGISTRATION_ENDPOINT) val registrationEndpoint: String?,
    @JsonProperty(RESPONSE_TYPES_SUPPORTED) val responseTypesSupported: List<String>,
    @JsonProperty(SCOPES_SUPPORTED) val scopesSupported: List<String>,
    @JsonProperty(AUTHORIZATION_ENDPOINT) val authorizationEndpoint: String,
    @JsonProperty(REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED) val requestObjectSigningAlgValuesSupported: List<String>
)

class OBDirectoryOidcWellKnownResponse(
    @JsonProperty(TOKEN_ENDPOINT) val tokenEndpoint: String,
    @JsonProperty(TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED) val tokenEndpointAuthMethodsSupported: List<TokenEndpointAuthMethod>,
    @JsonProperty(TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED) val tokenEndpointAuthSigningAlgValuesSupported: List<String>,
    @JsonProperty(JWKS_URI) val jwksUri: String,
    @JsonProperty(ISSUER) val issuer: String,
    @JsonProperty(GRANT_TYPES_SUPPORTED) val grantTypesSupported: List<String>,
    @JsonProperty(ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED) val idTokenSigningAlgValuesSupported: List<String>,
    @JsonProperty(REQUEST_PARAMETER_SUPPORTED) val requestParameterSupported: Boolean,
    @JsonProperty(REGISTRATION_ENDPOINT) val registrationEndpoint: String?,
    @JsonProperty(RESPONSE_TYPES_SUPPORTED) val responseTypesSupported: List<String>,
    @JsonProperty(SCOPES_SUPPORTED) val scopesSupported: List<String>,
    @JsonProperty(AUTHORIZATION_ENDPOINT) val authorizationEndpoint: String,
    @JsonProperty(REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED) val requestObjectSigningAlgValuesSupported: List<List<String>>
) {
    fun getOidcWellKnown(): OidcWellKnown {
        return OidcWellKnown(
            tokenEndpoint = tokenEndpoint,
            tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported,
            tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported,
            jwksUri = jwksUri,
            issuer = issuer,
            grantTypesSupported = grantTypesSupported,
            idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported,
            requestParameterSupported = requestParameterSupported,
            registrationEndpoint = registrationEndpoint,
            responseTypesSupported = responseTypesSupported,
            scopesSupported = scopesSupported,
            authorizationEndpoint = authorizationEndpoint,
            requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported[0]
        )
    }
}
