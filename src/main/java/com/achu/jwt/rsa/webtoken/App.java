package com.achu.jwt.rsa.webtoken;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;

import io.javalin.Javalin;

public class App {

	private RSAPrivateKey generatePrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		String privateKey = Files
				.readString(Path.of("./rsa/private-key.pem"))
				.replace("-----BEGIN PRIVATE KEY-----", "")
				.replaceAll(System.lineSeparator(), "")
				.replace("-----END PRIVATE KEY-----", "");
		PKCS8EncodedKeySpec  spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
		return (RSAPrivateKey) keyFactory.generatePrivate(spec);
	}

	private RSAPublicKey generatePublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		String publicKey = Files
				.readString(Path.of("./rsa/public-key.pem"))
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replaceAll(System.lineSeparator(), "")
				.replace("-----END PUBLIC KEY-----", "");
		X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
		return (RSAPublicKey) keyFactory.generatePublic(spec);
	}

	App() throws IllegalArgumentException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {

		System.out.println(
				createToken(new User("Superman", 99), Algorithm.RSA256(generatePublicKey(), generatePrivateKey())));

		//Javalin web = Javalin.create();
		// web.start(80);
	}

	private String createToken(User user, Algorithm alg) {
		Builder token = JWT.create().withClaim("name", user.getName()).withClaim("level", user.getLevel());
		return token.sign(alg);
	}

	public static void main(String[] args) {
		try {
			new App();
		} catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
	}

}
