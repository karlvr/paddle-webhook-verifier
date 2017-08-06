package com.xk72.paddle;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import de.ailis.pherialize.Pherialize;

/**
 * Verify Paddle webhook requests.
 */
public class PaddleWebhookVerifier {

	private PublicKey publicKey;
	
	/**
	 * Construct with a base64 encoded public key. Strip off the <code>-----BEGIN PUBLIC KEY-----</code>
	 * and <code>-----END PUBLIC KEY-----</code> to leave just the base64 encoded text.
	 * @param publicKey A base64 encoded public key
	 * @throws InvalidKeySpecException If the key is not in the correct format.
	 */
	public PaddleWebhookVerifier(String publicKey) throws InvalidKeySpecException {
		final KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(publicKey));
		this.publicKey = keyFactory.generatePublic(keySpec);
	}
	
	/**
	 * Verify a request. Pass in a map of the request parameters, such as from
	 * {@link javax.servlet.http.HttpServletRequest#getParameterMap()}.
	 * @param parameters A map of the request parameters.
	 * @return Whether or not the request signature was verified.
	 * @throws SignatureException If the signature in the request was invalid (means the request was not verified).
	 */
	public boolean verify(Map<String, String[]> parameters) throws SignatureException {
		final String[] signature = parameters.get("p_signature");
		if (signature == null) {
			return false;
		}
		
		final byte[] decodedSignature = Base64.getDecoder().decode(signature[0]);
		final byte[] serializedParameters = parametersForSigning(parameters);
		
		final Signature verifier;
		try {
			verifier = Signature.getInstance("SHA1withRSA");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		try {
			verifier.initVerify(publicKey);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException(e);
		}
		verifier.update(serializedParameters);
		return verifier.verify(decodedSignature);
	}

	private byte[] parametersForSigning(Map<String, String[]> parameters) {
		TreeMap<String, String> parametersForSigning = new TreeMap<String, String>();
		for (Entry<String, String[]> e : parameters.entrySet()) {
			parametersForSigning.put(e.getKey(), e.getValue()[0]);
		}
		parametersForSigning.remove("p_signature");
		
		/* Use Pherialize to serialize the Map as PHP would */
		final String serializedParametersForSigning = Pherialize.serialize(parametersForSigning);
		return serializedParametersForSigning.getBytes(StandardCharsets.UTF_8);
	}
	
}
