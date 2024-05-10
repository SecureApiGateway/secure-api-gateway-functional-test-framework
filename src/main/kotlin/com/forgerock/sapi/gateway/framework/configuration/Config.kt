package com.forgerock.sapi.gateway.framework.configuration

val IG_SERVER = System.getenv("igServer") ?: "https://sapig.dev.forgerock.financial"
val RCS_DECISION_API_URI = "$IG_SERVER/rcs/api/consent/decision"

val TRUSTSTORE_PATH = System.getenv("truststorePath") ?: "/com/forgerock/sapi/gateway/ob/uk/truststore.jks"
val TRUSTSTORE_PASSWORD = System.getenv("truststorePassword") ?: "changeit"

// certificates
val OB_TPP_EIDAS_TRANSPORT_KEY_PATH = System.getenv("eidasOBWacKey") ?: "./certificates/OBWac.key"
val OB_TPP_EIDAS_TRANSPORT_PEM_PATH = System.getenv("eidasOBWacPem") ?: "./certificates/OBWac.pem"

val REDIRECT_URI = System.getenv("redirectUri") ?: "https://www.google.co.uk"

val EXTERNAL_SYSTEM_DEPENDENCIES_CONFIG_FILE_PATH =
    System.getenv("externalSystemDependenciesConfigFilePath") ?: "/config.json"
