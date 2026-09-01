package com.example.wallet

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import uniffi.agever.AgeVerHolderPublicKey
import uniffi.agever.holderPkFromBytes
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.math.BigInteger
import java.security.cert.Certificate

class HardwareKeyManager(private val context: Context) {
    private val keyAlias = "agever_demo_holder_key"
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun getOrGenerateKey(): Certificate {
        // deleteKey() // TODO for testing
        if (!keyStore.containsAlias(keyAlias)) {
            generateKey()
        }
        val hasAPILevel = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        val hasstrongbox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        Log.d("KeyManager", "has strongbox: $hasstrongbox, has apilevel: $hasAPILevel")
        1
        val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        return entry.certificate
    }

    fun getCertificateChain(): List<Certificate> {
        return keyStore.getCertificateChain(keyAlias)?.toList() ?: emptyList()
    }


        fun deleteKey() {
      if (keyStore.containsAlias(keyAlias)) {
          keyStore.deleteEntry(keyAlias)
          Log.d("KeyManager", "deleted key")
      }                  
    }

    private fun generateKey() {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        val hasstrongbox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        Log.d("KeyManager", "generating new key with strongbox: $hasstrongbox")
        val challenge = "agever_attestation_challenge".toByteArray()
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                    context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
                ) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    fun sign(data: ByteArray): ByteArray {
        val privateKey = (keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry).privateKey
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(privateKey)
            update(data)
        }
        return signature.sign()
    }

    fun isKeyHardwareBacked(): Boolean {
        if (!keyStore.containsAlias(keyAlias)) return false
        val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        val factory = java.security.KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = try {
            factory.getKeySpec(entry.privateKey, android.security.keystore.KeyInfo::class.java)
        } catch (e: Exception) {
            return false
        }
        return keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
    }



//    private fun derToRaw(der: ByteArray): ByteArray {
//        // Simple DER parser for ECDSA signature (seq of 2 integers)
//        // DER: 0x30 <len> 0x02 <len_r> <r> 0x02 <len_s> <s>
//        var offset = 0
//        if (der[offset++] != 0x30.toByte()) throw Exception("Invalid DER signature: expected 0x30")
//        offset++ // Skip sequence length
//
//        fun readInt(): ByteArray {
//            if (der[offset++] != 0x02.toByte()) throw Exception("Invalid DER signature: expected 0x02")
//            val len = der[offset++].toInt()
//            val value = der.sliceArray(offset until offset + len)
//            offset += len
//            // Remove leading zero if necessary (DER adds it to keep it positive)
//            return if (value.size > 32) {
//                value.sliceArray(value.size - 32 until value.size)
//            } else if (value.size < 32) {
//                ByteArray(32 - value.size) + value
//            } else {
//                value
//            }
//        }
//
//        val r = readInt()
//        val s = readInt()
//        return r + s
//    }
}
