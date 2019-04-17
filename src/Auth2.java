import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Auth2 {
	public static void main(String[] args) {
		try {
			printAuthCode("XXXXXXXXXXXXXXXX");
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	private static void printAuthCode(String secretKey) throws InvalidKeyException, NoSuchAlgorithmException {
		final int timeUnit = 30;
		System.out.println("      30--------20--------10--------0");
		while (true) {
			long currentTime = System.currentTimeMillis() / 1000;
			long timeIndex = currentTime / timeUnit;
			long elapsedTime = currentTime % timeUnit;
			System.out.printf("%06d ", getCode(secretKey, timeIndex));
			for (int i = 0; i < timeUnit; i++) {
				System.out.print('>');
				System.out.flush();
				if (i >= elapsedTime) {
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						; // Do nothing
					}
				}
			}
			System.out.println();
		}
	}

	private static long getCode(String secretKey, long timeIndex) throws InvalidKeyException, NoSuchAlgorithmException {
		final String algorithm = "HmacSHA1";
		Mac mac = Mac.getInstance(algorithm);
		mac.init(new SecretKeySpec(base32decode(secretKey), algorithm));
		byte[] hash = mac.doFinal(toByteArray(timeIndex));
		int offset = hash[19] & 0xF;
		long truncatedHash = hash[offset] & 0x7F;
		for (int i = 1; i < 4; i++) {
			truncatedHash <<= 8;
			truncatedHash |= hash[offset + i] & 0xFF;
		}
		return truncatedHash %= 1000000;
	}

	private static byte[] base32decode(String secretKey) {
		final String b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
		ByteBuffer buff = ByteBuffer.allocate(secretKey.length() * 5 / 8);
		for (int i = 0; i < buff.capacity(); i++) {
			int k = i * 8 / 5;
			int b1 = b32.indexOf(secretKey.charAt(k)) << (8 - 5);
			int b2 = b32.indexOf(secretKey.charAt(k + 1)) << (8 - 5);
			int b3 = (i < buff.capacity() - 1) ? b32.indexOf(secretKey.charAt(k + 2)) << (8 - 5) : 0;
			int sft1 = i * 8 % 5;
			int sft2 = sft1 - 5; 
			int sft3 = sft2 - 5;
			buff.put((byte)(shift(b1, sft1) | shift(b2, sft2) | shift(b3, sft3)));
		}
		return buff.array();
	}

	private static int shift(int b, int shift) {
		return (shift > 0) ? b << shift : (shift < 0) ? b >>> -shift : b;
	}

	private static byte[] toByteArray(long x) {
		ByteBuffer buff = ByteBuffer.allocate(8);
		buff.putLong(x);
		return buff.array();
	}
}