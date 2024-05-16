# Secure API Gateway Function Test Framework
This framework aims to provide the tools needed to test APIs deployed using SAPI-G.

The framework comes with a set of tests that test the SAPI-G core (Plain FAPI) deployment.

## Framework configuration
Default configuration that is shipped with the framework can be found here: [src/main/resources/config.json](src/main/resources/config.json)

The config file supports placeholders, allowing config to be customised using environment variables.
Placeholders are of the form: `${VAR}` , or to supply a default value: `${VAR:-defaultValue}`

If an environment variable cannot be found, then the framework will fail to load the config file with an exception.

### Environment variables required by default config

| Name                      | Purpose                                                                                  | Example value                |
|---------------------------|------------------------------------------------------------------------------------------|------------------------------|
| API_UNDER_TEST_SERVER_TLD | The TLD of the environment to run the tests against                                      | dev-core.forgerock.financial |
| API_PROVIDER_ORG_ID       | The organisation id that the ApiClient belongs to as registered in the Trusted Directory | 0015800001041REAAY           |
| API_PROVIDER_SOFTWARE_ID  | The softwate_id of the ApiClient's software statement in the Trusted Directory           | Y6NjA9TOn3aMm9GaPtLwkp       |
| AM_REALM                  | The realm in AM being used for the OAuth2 provider for this deployment                   | alpha                        |
| AM_COOKIE_NAME            | The name of the AM cookie that needs to be set when doing end user authentication        | iPlanetDirectoryPro          |
| API_CLIENT_TRANSPORT_KID  | The kid (key id) of the ApiClient's transport key registered in their JWKS               |                              |
| API_CLIENT_SIGNING_KID    | The kid (key id) of the ApiClient's signing key registered in their JWKS                 |                              |


### Config implementation details
3rd Party library used: https://github.com/sksamuel/hoplite

Variables in config can be replaced using different methods, further details: https://github.com/sksamuel/hoplite?tab=readme-ov-file#built-in-preprocessors

## Set up the certificates for test purposes
The certificates are protected, and you can't find them in the repository, for that reason to run the functional tests in local environments is necessary set the OB certificates:
- Create the folder `certificates` in the root project folder

**ForgeRock code owners**
- Get the certificates from [sapig-ci-secrets](https://github.com/ForgeCloud/sapig-ci-secrets/tree/main/ob-directory-certs/tpp-SAPIG-automating-testing) and decrypt them:
  - OBWac.key
  - OBWac.pem
  - OBSeal.key
  - OBSeal.pem

**Customers**
- Obtain your TPP OB certificates for test purposes from OB directory:
  - OBWac.key
  - OBWac.pem
  - OBSeal.key
  - OBSeal.pem

- Copy the certificates to `certificates` folder created in the above step.

## Writing tests for an API

Example set of tests: [PlainFapiApiEndpointTest](src/test/kotlin/com/forgerock/sapi/gateway/core/PlainFapiApiEndpointTest.kt)
, these test the example API that is used to run the OIDF FAPI conformance suite. Only a single REST endpoint is exposed
which gets some test data, this endpoint is protected to FAPI standards.

Tests can extend from the `com.forgerock.sapi.gateway.framework.utils.MultipleApiClientTest` class. This bootstraps
the config and completes dynamic client registration for the ApiClients defined in the config file, these clients can
then be used to call the API under test.

```kotlin
class ExampleApiTest : MultipleApiClientTest() {
    
    @ParameterizedTest
    @MethodSource("getApiClients") // This is made available by 
    fun exampleTest(apiClient: ApiClient) {
        // Get an authorization_code access token
        val accessToken = getAuthorizationCodeAccessToken(apiClient)

        // Call the API_ENDPOINT_UNDER_TEST, supplying the access_token
        val (_, response, result) = apiClient.fuelManager.get(API_ENDPOINT_UNDER_TEST)
                                                         .header(Headers.AUTHORIZATION, 
                                                                 "Bearer ${accessToken.access_token}")
                                                         .responseString()

        // Assert behaviour is as expected
        assertThat(response.isSuccessful).isTrue()
    }

    // Helper function to get access_tokens to use with the API under test
    // Supply values or add parameters for SCOPES, RESPONSE_TYPES and ADDITIONAL_CLAIMS values
    private fun getAuthorizationCodeAccessToken(
      apiClient: ApiClient
    ): AccessToken {
        val scopes = SCOPES
        // The end user that approves the consent
        val resourceOwner = apiUnderTest.resourceOwners[0]
        val responseTypes = RESPONSE_TYPES
        val additionalClaims: List<Pair<String, Any>> = ADDITIONAL_CLAIMS
        val accessToken = apiUnderTest.oauth2Server.getAuthorizationCodeAccessToken(
            apiClient,
            apiUnderTest,
            scopes,
            resourceOwner,
            responseTypes,
            additionalClaims
        )
        return accessToken
    }
}
```
