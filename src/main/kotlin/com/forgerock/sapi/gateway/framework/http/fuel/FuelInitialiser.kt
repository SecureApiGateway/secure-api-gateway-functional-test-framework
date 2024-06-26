package com.forgerock.sapi.gateway.framework.http.fuel

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import com.fasterxml.jackson.datatype.joda.JodaModule
import com.fasterxml.jackson.datatype.joda.deser.LocalDateDeserializer
import com.fasterxml.jackson.datatype.joda.ser.LocalDateSerializer
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.forgerock.sapi.gateway.common.constants.OAuth2AuthorizeResponseParams
import com.forgerock.sapi.gateway.framework.configuration.OB_TPP_EIDAS_TRANSPORT_KEY_PATH
import com.forgerock.sapi.gateway.framework.configuration.OB_TPP_EIDAS_TRANSPORT_PEM_PATH
import com.forgerock.sapi.gateway.framework.configuration.TRUSTSTORE_PASSWORD
import com.forgerock.sapi.gateway.framework.configuration.TRUSTSTORE_PATH
import com.forgerock.sapi.gateway.framework.utils.FileUtils
import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.fuel.core.Request
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.core.ResponseResultOf
import com.github.kittinunf.fuel.core.extensions.jsonBody
import com.github.kittinunf.fuel.core.interceptors.LogRequestAsCurlInterceptor
import com.github.kittinunf.fuel.core.interceptors.LogResponseInterceptor
import com.github.kittinunf.fuel.core.response
import com.github.kittinunf.fuel.jackson.jacksonDeserializerOf
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonElement
import com.google.gson.JsonPrimitive
import com.google.gson.JsonSerializationContext
import io.r2.simplepemkeystore.MultiFileConcatSource
import io.r2.simplepemkeystore.SimplePemKeyStoreProvider
import org.apache.http.HttpHeaders
import org.apache.http.ssl.SSLContextBuilder
import org.joda.time.DateTime
import org.joda.time.DateTimeZone
import org.joda.time.LocalDate
import org.joda.time.format.ISODateTimeFormat
import java.io.InputStream
import java.lang.reflect.Type
import java.security.KeyStore
import java.security.Security
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSocketFactory
import kotlin.ranges.CharRange.Companion.EMPTY


fun Response.getLocationHeader(): String {
    val location = this.headers[HttpHeaders.LOCATION].firstOrNull()
    if (location == null) {
        throw AssertionError("No Location Header in response")
    } else {
        if (location.contains(OAuth2AuthorizeResponseParams.ERROR_DESCRIPTION)) {
            throw AssertionError("authorize request to $location failed: ")
        }
        return location
    }
}

class DateTimeDeserializer : StdDeserializer<DateTime>(DateTime::class.java) {
    override fun deserialize(jp: JsonParser, ctxt: DeserializationContext?): DateTime {
        val date = jp.text
        return DateTime.parse(date)
    }

    fun deserialize(
        je: JsonElement, type: Type?,
        jdc: JsonDeserializationContext?
    ): DateTime? {
        return if (je.asString.isEmpty()) null
        else
            ISODateTimeFormat.dateTimeParser().parseDateTime(je.asString).withZone(DateTimeZone.UTC)
    }
}

class DateTimeSerializer : StdSerializer<DateTime>(DateTime::class.java) {
    override fun serialize(value: DateTime?, gen: JsonGenerator?, provider: SerializerProvider?) {
        gen?.writeString(value?.toDateTimeISO()?.withZone(DateTimeZone.UTC).toString())
    }

    fun serialize(
        src: DateTime?, typeOfSrc: Type?,
        context: JsonSerializationContext?
    ): JsonElement {
        return JsonPrimitive(
            if (src == null) EMPTY.toString()
            else
                src.toDateTimeISO()?.withZone(DateTimeZone.UTC).toString()
        )
    }
}

val serializers: SimpleModule = SimpleModule("CustomSerializer")
    .addDeserializer(DateTime::class.java, DateTimeDeserializer())
    .addSerializer(DateTime::class.java, DateTimeSerializer())
    .addSerializer(LocalDate::class.java, LocalDateSerializer())
    .addDeserializer(LocalDate::class.java, LocalDateDeserializer())

val defaultMapper: ObjectMapper = ObjectMapper().registerKotlinModule()
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
    .registerModules(JodaModule())
    .registerModules(serializers)

fun initFuel(privatePem: InputStream, certificatePem: InputStream) {
    val ks = loadKeystore(privatePem, certificatePem)
    val truststore = object {}.javaClass.getResource(TRUSTSTORE_PATH)
    val sc = SSLContextBuilder()
        .loadKeyMaterial(
            ks,
            "".toCharArray()

        )
        // Force keystore to select hardcoded "server" alias in io.r2.simplepemkeystore.spi.SimplePemKeyStoreSpi see https://github.com/robymus/simple-pem-keystore/issues/2
        { _, _ -> "server" }
        .loadTrustMaterial(truststore.toURI().toURL(), TRUSTSTORE_PASSWORD.toCharArray())
    initFuel(sc)
}

/**
 * To support each ApiClient having it's own FuelManager
 */
fun getFuelManager(
    socketFactory: SSLSocketFactory = SSLContextBuilder().loadTrustMaterial(
        object {}.javaClass.getResource(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray()
    ).build().socketFactory
): FuelManager {
    val fuelManager = FuelManager()
    fuelManager.socketFactory = socketFactory
    fuelManager.apply {
        hostnameVerifier = HostnameVerifier { _, _ -> true }
        addRequestInterceptor(LogRequestAsCurlInterceptor)
        addResponseInterceptor(LogResponseInterceptor)
        timeoutInMillisecond = 30000
        timeoutReadInMillisecond = 30000
    }
    fuelManager.baseHeaders = mapOf("x-obri-analytics-enabled" to "false")
    return fuelManager
}

private fun initFuel(
    scb: SSLContextBuilder = SSLContextBuilder().loadTrustMaterial(
        object {}.javaClass.getResource(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray()
    )
) {
    FuelManager.instance.reset()
    FuelManager.instance.apply {
        socketFactory = scb.build().socketFactory
        hostnameVerifier = HostnameVerifier { _, _ -> true }
        addRequestInterceptor(LogRequestAsCurlInterceptor)
        addResponseInterceptor(LogResponseInterceptor)
        timeoutInMillisecond = 30000
        timeoutReadInMillisecond = 30000
    }
    FuelManager.instance.baseHeaders = mapOf("x-obri-analytics-enabled" to "false")
}

/**
 * Initialise HTTP client Fuel for MTLS
 * @param privatePem private pem resource
 * @param publicPem pem certificate
 */
fun initFuel(
    privatePem: String = OB_TPP_EIDAS_TRANSPORT_KEY_PATH,
    publicPem: String = OB_TPP_EIDAS_TRANSPORT_PEM_PATH
) {
    val privatePemStream = FileUtils().getInputStream(privatePem)
    val publicPemStream = FileUtils().getInputStream(publicPem)
    initFuel(privatePemStream, publicPemStream)
}

private fun loadKeystore(privatePem: InputStream, publicPem: InputStream): KeyStore {
    Security.addProvider(SimplePemKeyStoreProvider())
    val ks = KeyStore.getInstance("simplepem")
    ks.load(
        MultiFileConcatSource()
            .add(privatePem)
            .add(publicPem)
            .build(),
        CharArray(0)
    )
    return ks
}

/**
 * Extend Fuel DSL to use our custom (de)serializer
 */
inline fun <reified T : Any> Request.responseObject(): ResponseResultOf<T> =
    response(jacksonDeserializerOf(defaultMapper))

/**
 * Extend Fuel DSL to use our cus
 */
inline fun <reified T : Any> Request.body(): ResponseResultOf<T> = response(jacksonDeserializerOf(defaultMapper))

inline fun <reified T : Any> Request.jsonBody(src: T) = this.jsonBody(defaultMapper.writeValueAsString(src))

fun Request.jsonBody(src: String) = this.jsonBody(src)
