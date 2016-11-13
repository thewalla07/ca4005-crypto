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

public class Assignment2 {
    public static void main(String [] args) {
        System.out.println("Assignment 2");
    }
}


class CryptoHandler {

    public byte[] geterateNbitProbablePrime(int nbits) {

        byte[] result = new byte[nbits/8];

        //TODO: implement generation of probable prime

        return result;
    }

    public byte[] productOfPrimes(byte[] p, byte[] q) {

        byte[] result = new byte[0];

        //TODO: product of two prime numbers

        return result;
    }

    public byte[] eulerTotientPhi(byte[] n) {

        byte[] result = new byte[0];

        //TODO: look at notes on euler totient
        // phi(n) = n - 1 iff n is prime??

        return result;
    }

    public boolean isRelativelyPrime(byte[] e, byte[] phiN) {

        boolean result = true;

        //TODO: build test for relative primeness

        return result;
    }

    public byte[] getDecryptionExponent(byte[] e, byte[] phiN) {

        byte[] d = new byte[0];

        //TODO: d = multiplicativeInverse of e (mod phi(N))
        // use own umpl of extended  EGCD algorithm to calculate
        // the inverse, not a lib method.

        return d;
    }

    public byte[] getDecryption(byte[] c, byte[] d, byte[] n) {

        byte[] message = new byte[0];

        //TODO: implement c^d (mod n)
        // use impl of CRT to calculate this more efficiantly
        // can also make use of mult inv algo here

        return message;
    }

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
