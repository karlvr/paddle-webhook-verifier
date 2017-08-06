package com.xk72.paddle;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.Assert;
import org.junit.Test;

public class PaddleWebhookVerifierTest {

	private static final String PUBLIC_KEY = "" +
			"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8RaF2liU+LK7OTSq61rF" +
			"EwCQVOuW2nAGRBBGhRI01Yq160n/GsPt8ydgGzaZSPC5Fg6SSDW7pHvrC/lL39+Z" +
			"ZWb0PvXWsPWE+bG7jPXrxm7XlMMULIjw67vmuZdDpcane4DZ91voIRKM6EHchHkW" +
			"WXOb5jCAA1v37718IDyrhNkFMr9eiT47gN0EIbrKuNdCNj4pxra/ZWrcnoRTysKE" +
			"P0cRD4c1qMJ6VMviYMSVkiBFlTQtw9eSDscsfIhxEcWASsXfzfKGKdyn7h6XcSjG" +
			"Lw2GVK21JdkK9GUmKV+PxBbLFVBD3pn2CsMfiB8+DGCkSnYr6Y8UL4WlAp5q5AB0" +
			"j7Ug6sFJ3p/tWWvEKD3Y40FRe+tTWsn6Mh3j1YoqR+Zv0OtFOzyMkhAFtuJ+N1c1" +
			"hukccDapiMx0NxQcHjZ/xHFuRc7z7lDab7JPLo0uqxvKMfwLobjAMXqWPYpJLKBN" +
			"hnZ/3I0bGbDo/cZ0tkT2jkntX07trymlnxK4iqWK6BgkCRi5FvkymeveIqLhrAAT" +
			"a0i6o71y5gZMVSEtlZ/6e/d8D231sTwSIOix3n1y+tU77YmD/2wa0zTbsLubJ9SO" +
			"udaGz7qBV/Ec8Lrdg0xOVeLasTiY5Yv8ggG5s6NiybU0wXEsYwNBcjTvUzLJekHO" +
			"/r7I2rxq10eUcPsThBK10xsCAwEAAQ==";

	private PaddleWebhookVerifier verifier() throws InvalidKeySpecException {
		return new PaddleWebhookVerifier(PUBLIC_KEY);
	}
	
	@Test
	public void testPublicKey() throws InvalidKeySpecException {
		verifier();
	}
	
	@Test
	public void testNoSignature() throws InvalidKeySpecException, SignatureException {
		final PaddleWebhookVerifier verifier = verifier();
		
		Map<String, String[]> parameters = new HashMap<String, String[]>();
		Assert.assertFalse(verifier.verify(parameters));
	}
	
	@Test
	public void testNoSignature2() throws InvalidKeySpecException, SignatureException {
		final PaddleWebhookVerifier verifier = verifier();
		
		Map<String, String[]> parameters = new HashMap<String, String[]>();
		parameters.put("foo", new String[] { "bae" });
		Assert.assertFalse(verifier.verify(parameters));
	}
	
	@Test
	public void testTestSignature() throws InvalidKeySpecException, SignatureException {
		final PaddleWebhookVerifier verifier = verifier();
		
		Map<String, String[]> parameters = parseParameters("p_country=US&p_coupon=&p_coupon_savings=0&p_currency=USD&p_earnings=%7B%22469%22%3A%2247.0000%22%7D&p_order_id=1680209&p_paddle_fee=3&p_price=50&p_product_id=515852&p_quantity=1&p_sale_gross=50&p_tax_amount=0&p_used_price_override=1&passthrough=Example+passthrough&quantity=1&p_signature=4ay%2Bk5obWsSKmuyv5mAsd3m%2FsxbIWB8aw3KfWnqNV1xjarPBB6CwQjLFKSsVuIiZA8%2FzQYpTFKmEnhhzDyYZs42Gj0liR9fIjsUopgGEwU%2B7SFtEmx%2BOg9m477T3DEwMs4H0v5hb2D5BolRg897BhI8DemVC2kmp5e3uSGiynxhQUlD%2F%2FvfTA7YhvXX6vrsRo12qRTPGhO1ddTesZrnzzXewI%2FpgpUSHdNlgFMBUFwL10F2THzgCxxbFEHD8JeyzseTybRRVKjWplrcnVNjta099GuIYqgshgVLk5CRoyP28BxOI0WV2z7gkGnNbHSvC%2FeeVf8zQpG4SsEhdIuUmaCTPyuxvsPCtiWXhY65ONb6PMEHeI2HuEehE7iaZ2WJfG%2B7in8BypLWkYUr%2FQg%2BkAY%2F%2BV4GLhT9Ka3Gree8JfhV1%2BFUZ2VqhAmbBwUwc1jN%2Bv%2FmwoPjHifleSmPXZD%2BjRzNCpdhz48GHXJXuEE0MoWe8Er0LIbLbgOe7ChUz6UhI5T9IWrcHAPPIP%2FVBLvw471PH9kCpKkniPeofXOIG1L%2F9k%2FFF3w7FbIe2nYqN8OyV4WE2B%2FqZHQyiTIq%2FXgNM%2BOwxPUREUIx9n%2ButKu1SbYcKZd%2Bi94rov2TAkKPAV1VXTqc3tuXW1XbDe6KMVYQmMBnlR4clsIXCVAQELKOacwU%3D");
		
		Assert.assertTrue(verifier.verify(parameters));
	}

	private Map<String, String[]> parseParameters(String request) {
		Map<String, String> map = parseURLEncodedString(request);
		
		Map<String, String[]> parameters = new HashMap<String, String[]>();
		for (Entry<String, String> e : map.entrySet()) {
			parameters.put(e.getKey(), new String[] { e.getValue() });
		}
		return parameters;
	}
	
	private static Map<String, String> parseURLEncodedString(String string) {
		Map<String, String> response = new HashMap<String, String>();

		String[] params = string.split("&");
		for (String param : params) {
			String[] comp = param.split("=");

			String name, value;
			if (comp.length > 0) {
				try {
					name = URLDecoder.decode(comp[0], "UTF-8");
				} catch (UnsupportedEncodingException e) {
					throw new IllegalStateException(e);
				}
				if (comp.length > 1) {
					try {
						value = URLDecoder.decode(comp[1], "UTF-8");
					} catch (UnsupportedEncodingException e) {
						throw new IllegalStateException(e);
					}
				} else {
					/* Empty parameters are represented as empty strings */
					value = "";
				}
				
				if (name.length() > 0) {
					if (!response.containsKey(name)) {
						response.put(name, value);
					}
				}
			}
		}

		return response;
	}
	
}
