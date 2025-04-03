package com.forgerock.sapi.gateway.framework.utils

import com.forgerock.sapi.gateway.framework.configuration.TRUSTSTORE_PASSWORD
import com.forgerock.sapi.gateway.framework.configuration.TRUSTSTORE_PATH
import io.r2.simplepemkeystore.MultiFileConcatSource
import io.r2.simplepemkeystore.SimplePemKeyStoreProvider
import org.apache.http.ssl.SSLContextBuilder
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io.*
import java.security.KeyStore
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.util.*
import javax.net.ssl.SSLSocketFactory


class KeyUtils {
    companion object {

        val MILLISECONDS_PER_MINUTE = 60 * 1000

        fun readX509PublicCertificate(file: File): X509Certificate {
            println("Reading public key from file $file")
            return readX509PublicCertificateFromIS(FileInputStream(file))
        }

        fun readX509PublicCertificate(pemString: String): X509Certificate {
            return readX509PublicCertificateFromIS(pemString.byteInputStream())
        }

        private fun readX509PublicCertificateFromIS(istream: InputStream): X509Certificate {
            val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509", "BC")
            return certificateFactory.generateCertificate(istream) as X509Certificate
        }

        @Throws(IOException::class)
        fun readPKS8PrivateKey(file: File): RSAPrivateKey {
            return readPKS8PrivateKey(FileReader(file))
        }

        fun readPKS8PrivateKey(keyString: String): RSAPrivateKey {
            return readPKS8PrivateKey(keyString.reader())
        }

        private fun readPKS8PrivateKey(reader: Reader): RSAPrivateKey {
            val pemParser = PEMParser(reader)
            val pemObject = pemParser.readObject()
            val converter = JcaPEMKeyConverter()
            when {
                (pemObject is PrivateKeyInfo) -> return converter.getPrivateKey(pemObject) as RSAPrivateKey
                (pemObject is PEMKeyPair) -> return converter.getPrivateKey(pemObject.privateKeyInfo) as RSAPrivateKey
            }
            throw Exception("Unknown private key format")
        }


        fun getExpirationDateMinsInFuture(minsInFuture: Long): Date {
            val millisecondsInFuture = minsInFuture * MILLISECONDS_PER_MINUTE
            return Date(System.currentTimeMillis() + millisecondsInFuture)
        }

        fun getKeyStore(privatePem: InputStream, publicPem: InputStream): KeyStore {
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

        fun getKeystorePassword() = "as-sapig".toCharArray()

        fun getSocketFactory(ks: KeyStore): SSLSocketFactory {
            val truststore = object {}.javaClass.getResource(TRUSTSTORE_PATH)
            val sc = SSLContextBuilder()
                .loadKeyMaterial(
                    ks,
                    "as-sapig".toCharArray()
                )
                // Force keystore to select hardcoded "server" alias in io.r2.simplepemkeystore.spi.SimplePemKeyStoreSpi see https://github.com/robymus/simple-pem-keystore/issues/2
                { _, _ -> "server" }
                .loadTrustMaterial(truststore.toURI().toURL(), TRUSTSTORE_PASSWORD.toCharArray())
            return sc.build().socketFactory
        }
    }
}