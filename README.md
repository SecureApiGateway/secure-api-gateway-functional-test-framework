# Secure API Gateway Function Test Framework
This framework aims to provide the tools needed to test APIs deployed using SAPI-G.

The framework comes with a set of tests that test the SAPI-G core (Plain FAPI) deployment.

## Framework configuration
Default configuration that is shipped with the framework can be found here: [src/main/resources/config.json](src/main/resources/config.json)

The config file supports placeholders, allowing config to be customised using environment variables.
Placeholders are of the form: `{{ENV_VAR_NAME}}`.

If an environment variable cannot be found, then the framework will fail to load the config file with an exception.

### Environment variables required by default config

| Name                      | Purpose                                                                                  | Example value                |
|---------------------------|------------------------------------------------------------------------------------------|------------------------------|
| API_UNDER_TEST_SERVER_TLD | The TLD of the environment to run the tests against                                      | dev-core.forgerock.financial |
| API_PROVIDER_ORG_ID       | The organisation id that the ApiClient belongs to as registered in the Trusted Directory | 0015800001041REAAY           |
| API_PROVIDER_SOFTWARE_ID  | The softwate_id of the ApiClient's software statement in the Trusted Directory           | Y6NjA9TOn3aMm9GaPtLwkp       |


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
