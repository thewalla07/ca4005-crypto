import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.BitSet;
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.MessageDigest;

public class Assignment1 {

    private static int nBits = 1023;

    private static String primeModulus = "b59dd795 68817b4b 9f678982 2d22594f 376e6a9a bc024184 6de426e5 dd8f6edd ef00b465 f38f509b 2b183510 64704fe7 5f012fa3 46c5e2c4 42d7c99e ac79b2bc 8a202c98 327b9681 6cb80426 98ed3734 643c4c05 164e739c b72fba24 f6156b6f 47a7300e f778c378 ea301e11 41a6b25d 48f19242 68c62ee8 dd313474 5cdf7323";
    private static String generator = "44ec9d52 c8f9189e 49cd7c70 253c2eb3 154dd4f0 8467a64a 0267c9de fe4119f2 e373388c fa350a4e 66e432d6 38ccdc58 eb703e31 d4c84e50 398f9f91 677e8864 1a2d2f61 57e2f4ec 538088dc f5940b05 3c622e53 bab0b4e8 4b1465f5 738f5496 64bd7430 961d3e5a 2e7bceb6 2418db74 7386a58f f267a993 9833beef b7a6fd68";
    private static String geoffKey = "5af3e806 e0fa466d c75de601 86760516 792b70fd cd72a5b6 238e6f6b 76ece1f1 b38ba4e2 10f61a2b 84ef1b5d c4151e79 9485b217 1fcf318f 86d42616 b8fd8111 d59552e4 b5f228ee 838d535b 4b987f1e af3e5de3 ea0c403a 6c38002b 49eade15 171cb861 b3677324 60e3a984 2b532761 c16218c4 fea51be8 ea024838 5f6bac0d";

    public static void main(String[] args) {

        IOHandler ioh = new IOHandler();
        CryptoHandler crh = new CryptoHandler();

        BigInteger p = toBigInt(new String(ioh.readFile("prime_modulus")));
        BigInteger g = toBigInt(new String(ioh.readFile("generator")));
        // gpk == A
        BigInteger gpk = toBigInt(new String(ioh.readFile("geoff_public_key")));

        // b, my private key
        BigInteger b = createNBitKey(nBits);
        System.out.println("privateKey: " + b.toString(16) );

        // B = g ^ b (mod p)
        BigInteger mpk = crh.modExp(g, b, p);
        System.out.println("publicKey:  " + mpk.toString(16) );

        // s = A ^ b (mod p), where A = gpk
        BigInteger s = crh.modExp(gpk, b, p);
        System.out.println("sharedAesKey: " + s.toString(16) );

        // s is too large (1024 bit), and so must be reduced to 256 bit
        // k, sha256(s)
        BigInteger k = crh.sha256(s);
        System.out.println("reduced digest s: " + k.toString(16) );

        // iv random
        BigInteger iv = createNBitKey(128);
        System.out.println("initialization vector: " + iv.toString(16) );

        String filename = "testfile";

        System.out.println("Encrypting "+ filename);
        crh.encryptFile(filename, k, iv);

        // try {
        //     Thread.sleep(4000);
        // } catch (Exception e) {
        //     e.printStackTrace();
        // }
        //
        // System.out.println("Decrypting " + filename + ".enc");
        // crh.decryptFile(filename+".enc", k, iv);
        //
        // System.out.println("Success.");
        //

    }

    public static BigInteger createNBitKey(int nBits) {

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
            keyGen.init(nBits);
            SecretKey key = keyGen.generateKey();

            return new BigInteger(key.getEncoded());

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String toHex(BigInteger value) {

        return value.toString(16);
    }

    public static BigInteger toBigInt(String keyHexString) {

        // TODO: write function to convert from hex string to a big int
        return new BigInteger(keyHexString.replaceAll("\\s+",""), 16);
    }


}

class IOHandler {

    // read a file in as a byte array
    public byte[] readFile(String filename) {

        File fileIn = new File(filename);
        byte[] fileBytes = new byte[(int) fileIn.length()];

        try {

            FileInputStream fileInStream = new FileInputStream(fileIn);
            fileInStream.read(fileBytes);
            fileInStream.close();

        } catch (IOException e) {

            System.out.println("There was an error reading in file: " + filename);
            e.printStackTrace();
        }

        return fileBytes;
    }

    // write a byte array to a file
    public void writeFile(byte[] fileBytes, String filename) {

        File fileOut = new File(filename);

        try {

            FileOutputStream fileOutStream = new FileOutputStream(fileOut);
            fileOutStream.write(fileBytes);
            fileOutStream.close();

        } catch (IOException e) {

            System.out.println("There was an error writing to file: " + filename);
            e.printStackTrace();
        }
    }
}

class CryptoHandler {

    private void printBits(BitSet bits, int blockSize) {

        System.out.println();
        for (int i = 0; i < bits.length(); i++) {
            if (i %blockSize == 0)
                System.out.println();
            if (bits.get(i)) {
                System.out.print(1);
            } else {
                System.out.print(0);
            }
        }

        for(int j = blockSize; j > bits.length()%blockSize; j--)
            System.out.print(".");

        System.out.println();
    }

    public byte[] padBytes(byte[] bytes, int blockSize) {

        BitSet bits = BitSet.valueOf(bytes);

        //System.out.println(bytes.toString(16));
        printBits(bits, blockSize);

        int i = 0;

        int len = bits.length();

        System.out.println(bits.length());


        int padPosition = (len % 8 == 0) ? len + 7 : len + (len % 8) + 7;
        bits.set(padPosition, true);


        System.out.println(bits.length());

        len = bits.length();
        int arrSize = (len % blockSize == 0) ? 16*(len/blockSize) : (16*(len/blockSize)) + 16;

        byte[] newBytes = Arrays.copyOf(bits.toByteArray(), arrSize);
        System.out.println(arrSize + " and "+newBytes.length);


        // byte[] newBytes = byte[arrSize];
        // newBytes

        // bits.set(0, true);
        // int i = 0;
        // while (bits.length() % blockSize != 0) {
        //     bits.set(bits.length(), true);
        //     printBits(bits, blockSize);
        //     System.out.println(bits.length());
        //     i++;
        // }
        //
        // while (i>1) {
        //     bits.set(bits.length()-i, false);
        //     printBits(bits, blockSize);
        //     System.out.println(bits.length());
        //     System.out.println(bytes.length);
        //
        //     i--;
        // }
        //
        // printBits(bits, blockSize);

        return newBytes;
    }

    public void encryptFile(String filename, BigInteger k, BigInteger iv) {

        // reference cipher transformations found at:
        // https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        // this transformation has a 128 bit keysize by default
        String cipherType = "AES/CBC/NoPadding";

        IOHandler ioh = new IOHandler();
        byte[] fileBytes = ioh.readFile(filename);

        fileBytes = padBytes(fileBytes, 128);

        ioh.writeFile(fileBytes, filename+"test");

        SecretKeySpec keySpec = new SecretKeySpec(k.toByteArray(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.toByteArray());

        try {

            Cipher c = Cipher.getInstance(cipherType);
            c.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            fileBytes = c.doFinal(fileBytes);

            System.out.println("Enc done");
        } catch (Exception e) {

            e.printStackTrace();
        }

        ioh.writeFile(fileBytes, filename+".enc");
    }

    public void decryptFile(String filename, BigInteger k, BigInteger iv) {

        // reference cipher transformations found at:
        // https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        // this transformation has a 128 bit keysize by default
        String cipherType = "AES/CBC/NoPadding";

        IOHandler ioh = new IOHandler();
        byte[] fileBytes = ioh.readFile(filename);

        SecretKeySpec keySpec = new SecretKeySpec(k.toByteArray(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.toByteArray());

        try {

            Cipher c = Cipher.getInstance(cipherType);
            c.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            c.doFinal(fileBytes);

        } catch (Exception e) {

            e.printStackTrace();
        }

        ioh.writeFile(fileBytes, filename);
    }

    // perform modular exponentiation
    public BigInteger modExp(BigInteger b, BigInteger g, BigInteger p) {

        // calculate result = b ^ g mod p
        //                y = a ^ x mod p

        /*
            y = 1
            for i = 0 to n-1 do
                if x(i) = 1 then y = (y*a) mod p
                a = (a*a) mod p
            end
        */
        BigInteger result = BigInteger.ONE;
        BigInteger two = new BigInteger("2");

        b = b.mod(p);
        while (g.compareTo(BigInteger.ZERO) > 0) {
            if (g.mod(two).compareTo(BigInteger.ONE) == 0) {
                result = result.multiply(b).mod(p);
            }
            g = g.shiftRight(1);
            b = b.multiply(b).mod(p);
        }
        return result;
    }

    public BigInteger sha256(BigInteger num) {

        // 32B == 256b
        byte[] digestBytes = new byte[32];
        String algorithm = "SHA-256";

        try {

            MessageDigest md = MessageDigest.getInstance(algorithm);
            digestBytes = md.digest(num.toByteArray());

        } catch (Exception e) {

            System.out.println("No algorithm " + algorithm + " exists.");
            e.printStackTrace();
        }

        return new BigInteger(digestBytes);
    }
}
