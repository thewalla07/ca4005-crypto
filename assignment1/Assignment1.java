// Michael Wall 13522003
// This project is solely my own work except where otherwise noted

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
import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;
import java.security.MessageDigest;

public class Assignment1 {

    private static int nBits = 1023;

    private static String primeModulus = "b59dd795 68817b4b 9f678982 2d22594f 376e6a9a bc024184 6de426e5 dd8f6edd ef00b465 f38f509b 2b183510 64704fe7 5f012fa3 46c5e2c4 42d7c99e ac79b2bc 8a202c98 327b9681 6cb80426 98ed3734 643c4c05 164e739c b72fba24 f6156b6f 47a7300e f778c378 ea301e11 41a6b25d 48f19242 68c62ee8 dd313474 5cdf7323";
    private static String generator = "44ec9d52 c8f9189e 49cd7c70 253c2eb3 154dd4f0 8467a64a 0267c9de fe4119f2 e373388c fa350a4e 66e432d6 38ccdc58 eb703e31 d4c84e50 398f9f91 677e8864 1a2d2f61 57e2f4ec 538088dc f5940b05 3c622e53 bab0b4e8 4b1465f5 738f5496 64bd7430 961d3e5a 2e7bceb6 2418db74 7386a58f f267a993 9833beef b7a6fd68";
    private static String geoffKey = "5af3e806 e0fa466d c75de601 86760516 792b70fd cd72a5b6 238e6f6b 76ece1f1 b38ba4e2 10f61a2b 84ef1b5d c4151e79 9485b217 1fcf318f 86d42616 b8fd8111 d59552e4 b5f228ee 838d535b 4b987f1e af3e5de3 ea0c403a 6c38002b 49eade15 171cb861 b3677324 60e3a984 2b532761 c16218c4 fea51be8 ea024838 5f6bac0d";

    public static void main(String[] args) {

        String filename = "";

        if(args.length != 1){

            System.out.println("No file to encrypt!");
            return;

        } else {

            filename = args[0];
        }

        IOHandler ioh = new IOHandler();
        CryptoHandler crh = new CryptoHandler();

        BigInteger p = ioh.toBigInt(primeModulus);
        BigInteger g = ioh.toBigInt(generator);
        // gpk == A
        BigInteger gpk = ioh.toBigInt(geoffKey);

        // b, my private key
        BigInteger b = crh.createNBitKey(nBits);
        System.out.println("privateKey: " + b.toString(16) );
        ioh.writeAsHex(b, "myPrivateKey");

        // B = g ^ b (mod p)
        BigInteger mpk = crh.modExp(g, b, p);
        System.out.println("publicKey:  " + mpk.toString(16) );
        ioh.writeAsHex(mpk, "myPublicKey");

        // s = A ^ b (mod p), where A = gpk
        BigInteger s = crh.modExp(gpk, b, p);
        System.out.println("sharedAesKey: " + s.toString(16) );
        ioh.writeAsHex(s, "sharedAesKey");

        // s is too large (1024 bit), and so must be reduced to 256 bit
        // k, sha256(s)
        BigInteger k = crh.sha256(s);
        System.out.println("reduced digest s: " + k.toString(16) );
        ioh.writeAsHex(k, "aes256key");

        // iv random
        BigInteger iv = crh.createNBitKey(128);
        System.out.println("initialization vector: " + iv.toString(16) );
        ioh.writeAsHex(iv, "initializationVector");

        System.out.println("Encrypting "+ filename);
        crh.encryptFile(filename, k, iv);
        System.out.println("Done");
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

    public void writeAsHex(BigInteger value, String filename) {

        try {

            PrintWriter out = new PrintWriter(filename);
            out.println(toHex(value));
            out.close();

        } catch (FileNotFoundException e) {

            e.printStackTrace();
        }
    }

    public void writeHex(byte[] value, String filename) {

        try {

            PrintWriter out = new PrintWriter(filename);
            out.println(DatatypeConverter.printHexBinary(value));
            out.close();

        } catch (FileNotFoundException e) {

            e.printStackTrace();
        }
    }

    public String toHex(BigInteger value) {

        return value.toString(16);
    }

    public BigInteger toBigInt(String keyHexString) {

        return new BigInteger(keyHexString.replaceAll("\\s+",""), 16);
    }
}

class CryptoHandler {

    public byte[] padBytes(byte[] bytes, int blockSize) {

        BitSet bits = BitSet.valueOf(bytes);

        /*
            Because of the way BitSet handles a byte array, you can't directly
            pad the bits with 0s to the required length. Instead, I appended
            the 1 bit in the required position first. This position is
            determined by first getting the length of the bitset.

            If the bitset is a multiple of 8, then the pad position is set to
            the length + 7. Eg if the following bitset exists:
            10101111 01011111 - length is 16, so we pad at position 23
            0123.... 8....... .......23
            10101111 01011111 00000001

            The reason we pad at what appears to be a byte is because bitset
            reverses the bytes individually. I think this may be to do with
            endianness, but I could not figure this out from the api. When this
            is converted back to a byte[] the bits will actuall be as follows:
            11110101 11111010 10000000

            I verified this behaviour using the following linux command:
            $ cat file | xxd -b

            This way I could see the arrangement of bits and verify the padding
            position.
        */
        int len = bits.length();
        int padPosition = (bytes.length * 8) + 7;

        bits.set(padPosition, true);

        /*
            the length of the new array will be a multiple of the blockSize.
            If the current length ends at a full block, then that means the
            padded 1 bit was added at the 128th bit of the block, and so we add
            an extra 16 bytes for the padding of 0s. In any other case, we add
            the extra 16 bytes to fill out the rest of the block. Ex:
            len = 220,

                the last bit will be around here,
                so we want to pad to the end of
                block_2, total size = 32Bytes
                          |
                          |
                          *
            [ block_1 | block_2 ]

            (16*(220/128)) + 16
            (16*(1)) + 16
            16 + 16
            32 Bytes

            In the case of a just filled block:

            (16*(256/128)) + 16
            (16*(2)) + 16
            32 + 16
            48 Bytes

            So we can use the same calculation in both cases
        */

        len = bits.length();
        int arrSize = (16*(len/blockSize)) + 16;

        // Create a new array with the above bits that have been padded with
        // a single 1 bit. The new array will be arrSize bytes size in total,
        // meaning the remaining bytes will be padded with 0s
        byte[] newBytes = Arrays.copyOf(bits.toByteArray(), arrSize);

        return newBytes;
    }

    public void encryptFile(String filename, BigInteger k, BigInteger iv) {

        // reference cipher transformations found at:
        // https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html

        String cipherType = "AES/CBC/NoPadding";

        // use an iohandler to get the file data to encrypt
        IOHandler ioh = new IOHandler();
        byte[] fileBytes = ioh.readFile(filename);

        // pad the file to the required multiple of 128 bits
        fileBytes = padBytes(fileBytes, 128);

        // write file to test padding correctly applied
        ioh.writeFile(fileBytes, filename+"test");

        SecretKeySpec keySpec = new SecretKeySpec(k.toByteArray(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.toByteArray());

        try {

            Cipher c = Cipher.getInstance(cipherType);
            c.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            fileBytes = c.doFinal(fileBytes);

        } catch (Exception e) {

            e.printStackTrace();
        }

        // write the encrypted file out
        ioh.writeFile(fileBytes, filename+".enc");
    }

    public BigInteger modExp(BigInteger b, BigInteger g, BigInteger p) {

        // calculate result = b ^ g mod p
        //                y = a ^ x mod p


        // I used the right to left method from the lecture notes to
        // perform the modular exponentiation

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
            b = b.multiply(b).mod(p);
            g = g.shiftRight(1);
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

    public BigInteger createNBitKey(int nBits) {

        IOHandler ioh = new IOHandler();
        try {
            BigInteger newkey = BigInteger.ONE;

            // ensure the generated key is of the correct length
            while (newkey.toByteArray().length%(nBits/8) != 0) {

                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
                keyGen.init(nBits);
                SecretKey key = keyGen.generateKey();

                newkey = new BigInteger(DatatypeConverter.printHexBinary(key.getEncoded()), 16);
            }

            return newkey;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
