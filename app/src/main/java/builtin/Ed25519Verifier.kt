package builtin

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

object Ed25519Verifier {

    fun verify(rawPublicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (rawPublicKey.size != 32) return false
        return try {
            verifySystem(rawPublicKey, message, signature)
        } catch (e: Exception) {
            verifyBouncyCastle(rawPublicKey, message, signature)
        }
    }

    private fun verifySystem(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val prefix = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
        )
        val der = prefix + pk
        val key: PublicKey = KeyFactory.getInstance("Ed25519")
            .generatePublic(X509EncodedKeySpec(der))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(key)
        verifier.update(msg)
        return verifier.verify(sig)
    }

    private fun verifyBouncyCastle(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val params = Ed25519PublicKeyParameters(pk, 0)
        val signer = Ed25519Signer()
        signer.init(false, params)
        signer.update(msg, 0, msg.size)
        return signer.verifySignature(sig)
    }
}
