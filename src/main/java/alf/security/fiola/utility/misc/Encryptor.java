package alf.security.fiola.utility.misc;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Component;

import com.lambdaworks.crypto.SCryptUtil;

import alf.security.fiola.utility.properties.PropertiesConstants;

@Component
public class Encryptor {
	private SecretKey desKey;
	private final static String HEX_DIGITS = "0123456789ABCDEF";

	static final String SOURCE = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+=-~{}[]:;<>,./?";
	static SecureRandom secureRnd = new SecureRandom();

	public Encryptor() {
		createCipher(PropertiesConstants.appSecretKeyHash.getBytes());
	}

	public Encryptor(byte[] key) {
		createCipher(key);
	}

	public void createCipher(byte[] desKeyData) {
		try {
			if (!(desKeyData.length == 16 || desKeyData.length == 24)) {
				return;
			}
			byte[] key = new byte[24];
			if (desKeyData.length == 16) {
				for (int za = 0; za < 16; za++) {
					key[za] = desKeyData[za];
				}
				for (int za = 0; za < 8; za++) {
					key[za + 16] = desKeyData[za];
				}
			}
			if (desKeyData.length == 24) {
				for (int za = 0; za < 24; za++) {
					key[za] = desKeyData[za];
				}
			}

			DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
			SecretKeyFactory keyFactory = null;
			keyFactory = SecretKeyFactory.getInstance("DESede");
			desKey = keyFactory.generateSecret(desKeySpec);
		} catch (NoSuchAlgorithmException ex1) {
		} catch (InvalidKeyException ex2) {
		} catch (InvalidKeySpecException ex3) {
		}
	}

	public byte[] encryptECB(byte[] cleartext) {
		byte[] ciphertext = null;
		try {
			Cipher desCipher;
			desCipher = Cipher.getInstance("DESede/ECB/NoPadding");
			desCipher.init(Cipher.ENCRYPT_MODE, desKey);
			ciphertext = desCipher.doFinal(cleartext);
		} catch (NoSuchAlgorithmException ex1) {
		} catch (InvalidKeyException ex2) {
		} catch (NoSuchPaddingException ex3) {
		} catch (BadPaddingException ex4) {
		} catch (IllegalBlockSizeException ex5) {
		} catch (IllegalStateException ex6) {
		}
		return ciphertext;
	}

	public byte[] decryptECB(byte[] ciphertext) {
		byte[] cleartext = null;
		try {
			Cipher desCipher;
			desCipher = Cipher.getInstance("DESede/ECB/NoPadding");
			desCipher.init(Cipher.DECRYPT_MODE, desKey);
			cleartext = desCipher.doFinal(ciphertext);
		} catch (NoSuchAlgorithmException ex1) {
		} catch (InvalidKeyException ex2) {
		} catch (NoSuchPaddingException ex3) {
		} catch (BadPaddingException ex4) {
		} catch (IllegalBlockSizeException ex5) {
		} catch (IllegalStateException ex6) {
		}
		return cleartext;
	}

	public byte[] encryptCBC(byte[] cleartext) {
		byte[] ciphertext = null;
		byte[] iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);

		try {
			Cipher desCipher;
			desCipher = Cipher.getInstance("DESede/CBC/NoPadding");
			desCipher.init(Cipher.ENCRYPT_MODE, desKey, paramSpec);
			ciphertext = desCipher.doFinal(cleartext);
			iv = desCipher.getIV();

		} catch (NoSuchAlgorithmException ex1) {
		} catch (InvalidKeyException ex2) {
		} catch (NoSuchPaddingException ex3) {
		} catch (BadPaddingException ex4) {
		} catch (IllegalBlockSizeException ex5) {
		} catch (IllegalStateException ex6) {
		} catch (InvalidAlgorithmParameterException ex7) {
		}
		return ciphertext;
	}

	public byte[] decryptCBC(byte[] ciphertext) {
		byte[] cleartext = null;
		byte[] iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '\0' };
		IvParameterSpec paramSpec = new IvParameterSpec(iv);

		try {
			Cipher desCipher;
			desCipher = Cipher.getInstance("DESede/CBC/NoPadding");
			desCipher.init(Cipher.DECRYPT_MODE, desKey, paramSpec);
			cleartext = desCipher.doFinal(ciphertext);
			iv = paramSpec.getIV();
		} catch (NoSuchAlgorithmException ex1) {
		} catch (InvalidKeyException ex2) {
		} catch (NoSuchPaddingException ex3) {
		} catch (BadPaddingException ex4) {
		} catch (IllegalBlockSizeException ex5) {
		} catch (IllegalStateException ex6) {
		} catch (InvalidAlgorithmParameterException ex7) {
			ex7.printStackTrace();
		}
		return cleartext;
	}

	public byte[] fromHexString(String s) {
		byte bytes[] = new byte[s.length() / 2];
		for (int i = 0; i < s.length() / 2; i++) {
			bytes[i] = (byte) (Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16));
		}
		return bytes;
	}

	public String toHexString(byte b[]) {
		if ((b == null) || (b.length == 0)) {
			return "";
		} else {
			return toHexString(b, 0, b.length);
		}
	}

	/** Convert bytes to HEX string */
	private String toHexString(byte b[], int off, int len) {
		StringBuffer s = new StringBuffer();
		for (int i = off; i < off + len; i++) {
			s.append(HEX_DIGITS.charAt((b[i] & 0xff) >> 4));
			s.append(HEX_DIGITS.charAt(b[i] & 0xf));
		}
		return s.toString();
	}

	public String cleanData(String orig) {
		StringBuffer buff = new StringBuffer();
		char[] chars = orig.toCharArray();
		for (int za = 0; za < chars.length; za++) {
			char tmp = chars[za];
			if (!(tmp == 0x00)) {
				buff.append(tmp);
			}
		}
		return buff.toString();
	}

	public String paddData(String orig) {
		StringBuffer buff = new StringBuffer();
		buff.append(orig);
		int paddSize = 0;
		if (orig.length() % 8 != 0) {
			paddSize = 8 - (orig.length() % 8);
		}
		for (int za = 0; za < paddSize; za++) {
			buff.append((char) 0x00);
		}
		return buff.toString();
	}

	public String encrypt(String data) {
		String retval = "";
		byte[] encrypted = encryptECB(paddData(data).getBytes());
		retval = toHexString(encrypted);
		return retval;
	}

	public String decrypt(String data) {
		String retval = "";
		byte[] decrypted = decryptECB(fromHexString(data));
		retval = cleanData(new String(decrypted));
		return retval;
	}

	/**
	 * @notes encryption method for AES256
	 */

	public static String encryptAES(String key, String initVector, String value) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

			byte[] encrypted = cipher.doFinal(value.getBytes());
			// System.out.println("encrypted string: " +
			// Base64.encodeBase64String(encrypted));

			return Base64.encodeBase64String(encrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public static String decryptAES(String key, String initVector, String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

			byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

			return new String(original);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}
	
	/**
	 * @note Generate Random Key String and use it to encrypt
	 * --not safe enough!
	 */
	public static String random16CharString() {
		StringBuilder sb = new StringBuilder(16);
		for (int i = 0; i < 16; i++)
			sb.append(SOURCE.charAt(secureRnd.nextInt(SOURCE.length())));
		return sb.toString();
	}
	
	/**
	 * @note SCRYPT Algorithm
	 */
	public static String generateScryptSecuredString(String text) {
		return SCryptUtil.scrypt(text, 16, 16, 16);
	}
	
	public static boolean checkScryptSecuredString(String text, String generatedScryptSecuredString) {
		return SCryptUtil.check(text, generatedScryptSecuredString);
	}
	
	/**
	 * @note PBKDF2WithHmacSHA1 Algorithm
	 * 
	 * -- start
	 */
	@SuppressWarnings("unused")
	private static String generateStorngPasswordHash(String text)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		int iterations = 1000;
		char[] chars = text.toCharArray();
		byte[] salt = getSalt();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] hash = skf.generateSecret(spec).getEncoded();
		return iterations + ":" + toHex(salt) + ":" + toHex(hash);
	}

	private static byte[] getSalt() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt;
	}

	private static String toHex(byte[] array) throws NoSuchAlgorithmException {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0) {
			return String.format("%0" + paddingLength + "d", 0) + hex;
		} else {
			return hex;
		}
	}
	
	@SuppressWarnings("unused")
	private static boolean validatePassword(String originalPassword, String storedPassword)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		String[] parts = storedPassword.split(":");
		int iterations = Integer.parseInt(parts[0]);
		byte[] salt = fromHex(parts[1]);
		byte[] hash = fromHex(parts[2]);

		PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] testHash = skf.generateSecret(spec).getEncoded();

		int diff = hash.length ^ testHash.length;
		for (int i = 0; i < hash.length && i < testHash.length; i++) {
			diff |= hash[i] ^ testHash[i];
		}
		return diff == 0;
	}

	private static byte[] fromHex(String hex) throws NoSuchAlgorithmException {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}
	/**
	 * PBKDF2WithHmacSHA1 Algorithm
	 * -- end
	 */
	

	public static void main(String args[]) throws Exception {

//		String generatedKey = random16CharString();
//		String generatedIV = random16CharString();
//		
//		System.out.println("Generated Credentials (Key)(IV) : " + generatedKey + " " + generatedIV);
//		
//		String encypted = encryptAES(generatedKey, generatedIV, "ERROR");
//
//		System.out.println(encypted);
//		System.out.println(decryptAES(generatedKey, generatedIV, encypted));
		
		
		String generatedScryptSecuredString = generateScryptSecuredString("SUCCESS");
		System.out.println(generatedScryptSecuredString);
		System.out.println(checkScryptSecuredString("SUCCESSA", "$s0$41010$Lst3ooPZ/fBqPUXlfydPWg==$SvQL8jqj+Ilr3aS+amRtq0OuNSg2lCdM23z9vb05Yvc="));

	}
}
