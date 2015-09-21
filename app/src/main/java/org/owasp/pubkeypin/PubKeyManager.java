package org.owasp.pubkeypin;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

// Many thanks to Nikolay Elenkov for feedback.
// Shamelessly based upon Moxie's example code (AOSP/Google did not offer code)
// http://www.thoughtcrime.org/blog/authenticity-is-broken-in-ssl-but-your-app-ha/
public final class PubKeyManager implements X509TrustManager {

	// DER encoded public key
	private static String PUB_KEY = "30820222300d06092a864886f70d01010105000382020f003082020a0282020100c747619aaef86d077beed55e66caf4cd8ae46d760d49ae662ebd5ba6b56868746dd711d1533ca0ae18bd9651ecc1b0961751a5fd8b342f2cb58f06df8ebb24b11f25067a9fdbb82d2bb60228bb5b6754d15562396c2e1f20cde9244c2de0b7f12650ba722ca724306f7dc5220d9bc64b1f6d7b9d081e9baf22b03cfce30ebb323724d6128d425f99e4a81fd83881144fb80a947f2383b4ec322764d6d03694a4c9ce05e1ebcd1a7ba2871d8efb9214a8c15ccef6fa789354f19bdb96c216442af9e9a0e7fad5f9eecf8a173781ab1c10979d1534452e5f5288b15a7ba72fe27a5959570c8d69e245d0ce73204b46a67debd13e30c641e9ede8f5db75f5d992c70b66b02aae832cacdd60d575d61f3aaffda509fb2e0198da1cc8c7a071a91816d7a3b16098474b2283701653f33751025a6dd5845af2cc8a0284493513649db04c7d79db1873e90e8b8f75b8d2b249b1dff1e994b1e7f17d32eb5bad6c2818050e0a0da2ee4edb68d26ccfcff950fa47334b676e4d6ded98f6b1b7432730bee9a0ed94078427458270fde975b65d83a3b6395c788df80aecd3e4c4fe9d2c4cc44940850283931779ffacf93a9fbaf2223c9d7c4818d44eaa4232aadc4af7d8b1a5a4fa32c816a0c7959204a74564b115060c15224a6362456a563f30f6ae66172a18cb8e8f68361f368d81a1dccf6270b3b99da7b02da9f07359fab4652cf4530203010001";

	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {

		assert (chain != null);
		if (chain == null) {
			throw new IllegalArgumentException(
					"checkServerTrusted: X509Certificate array is null");
		}

		assert (chain.length > 0);
		if (!(chain.length > 0)) {
			throw new IllegalArgumentException(
					"checkServerTrusted: X509Certificate is empty");
		}

		assert (null != authType && authType.equalsIgnoreCase("ECDHE_RSA"));
		if (!(null != authType && authType.equalsIgnoreCase("ECDHE_RSA"))) {
			throw new CertificateException(
					"checkServerTrusted: AuthType is not RSA");
		}

		// Perform customary SSL/TLS checks
		TrustManagerFactory tmf;
		try {
			tmf = TrustManagerFactory.getInstance("X509");
			tmf.init((KeyStore) null);

			for (TrustManager trustManager : tmf.getTrustManagers()) {
				((X509TrustManager) trustManager).checkServerTrusted(
						chain, authType);
			}

		} catch (Exception e) {
			throw new CertificateException(e);
		}

		// Hack ahead: BigInteger and toString(). We know a DER encoded Public
		// Key starts with 0x30 (ASN.1 SEQUENCE and CONSTRUCTED), so there is
		// no leading 0x00 to drop.
		RSAPublicKey pubkey = (RSAPublicKey) chain[0].getPublicKey();
		String encoded = new BigInteger(1 /* positive */, pubkey.getEncoded())
				.toString(16);

		// Pin it!
		final boolean expected = PUB_KEY.equalsIgnoreCase(encoded);
		assert(expected);
		if (!expected) {
			throw new CertificateException(
					"checkServerTrusted: Wrong public key!");
		}
	}

	public void checkClientTrusted(X509Certificate[] xcs, String string) {
		// throw new
		// UnsupportedOperationException("checkClientTrusted: Not supported yet.");
	}

	public X509Certificate[] getAcceptedIssuers() {
		// throw new
		// UnsupportedOperationException("getAcceptedIssuers: Not supported yet.");
		return null;
	}
}
