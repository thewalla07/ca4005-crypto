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



        CryptoHandler crh = new CryptoHandler();
        IOHandler ioh = new IOHandler();



        if(args.length > 0){

            BigInteger e = new BigInteger(args[0]);
            BigInteger mod = new BigInteger(args[1]);

            BigInteger multinv = crh.multiplicativeInverse(e, mod);
            System.out.println(multinv);

            multinv = e.modInverse(mod);
            System.out.println(multinv);


            multinv = crh.euclidianGCD(e, mod);
            System.out.println(multinv);

            return;
        }

        BigInteger e = new BigInteger("65537");

        BigInteger phiN = e;

        BigInteger p = BigInteger.ZERO;
        BigInteger q = BigInteger.ZERO;
        BigInteger n = BigInteger.ZERO;

        System.out.println("Assignment 2");

        // 1. generate two distinct 512-bit probable primes p and q
        p = crh.getProbablePrime(512);
        System.out.println(ioh.toHex(p) + "\n");

        q = crh.getProbablePrime(512);
        System.out.println(ioh.toHex(q) + "\n");

        // 2. calculate the product of these two primes N = pq
        n = crh.productOfPrimes(p, q);
        System.out.println(ioh.toHex(n) + "\n");

        // 3. calculate the euler totient function phi(N)
        phiN = crh.eulerTotientPhi(p, q);
        System.out.println(ioh.toHex(phiN) + "\n");

        // 4. you will be using an encryption exponent e = 65537, so you will
        // need to ensure it is relatively prime to phi(N). If it is not, go
        // back to step 1 and generate new values for p and q.
        int i = 0;
        while(!crh.areRelativelyPrime(e, phiN)) {

            // 1. generate two distinct 512-bit probable primes p and q
            p = crh.getProbablePrime(512);
            System.out.println(ioh.toHex(p) + "\n");

            q = crh.getProbablePrime(512);
            System.out.println(ioh.toHex(q) + "\n");

            // 2. calculate the product of these two primes N = pq
            n = crh.productOfPrimes(p, q);
            System.out.println(ioh.toHex(n) + "\n");

            // 3. calculate the euler totient function phi(N)
            phiN = crh.eulerTotientPhi(p, q);
            System.out.println(ioh.toHex(phiN) + "\n");

            i++;
        }

        System.out.println(i + " iterations" + "\n");

        // 5. calculate the decryption exponent d, which is the multiplicative
        // inverse of e (mod phi(N)). This should be your own implementation
        // of the extended euclidian gcd algorithm.
        BigInteger gcd = crh.euclidianGCD(e, phiN);
        System.out.println("EGCD: " + ioh.toHex(gcd) + "\n");

        BigInteger d = crh.multiplicativeInverse(e, phiN);
        System.out.println("Decryption exponent: " + ioh.toHex(d) + "\n");

        BigInteger multinv = e.modInverse(phiN);
        System.out.println("Correct decryption exponent: " + ioh.toHex(multinv) + "\n");


        String str = "13522003";

        BigInteger c = new BigInteger(str);
        System.out.println("File: " + ioh.toHex(c) + "\n");
        //TODO: get input file for decryption signature

        BigInteger digest = crh.sha256(c);
        System.out.println("Digest: " + ioh.toHex(digest) + "\n");

        //TODO: modular exponentiation using Chinese Remainder Theor
        BigInteger signedDigest = crh.modExp(c, d, n);
        System.out.println("Signed digest: " + ioh.toHex(signedDigest) + "\n");

        c = new BigInteger(str.getBytes());
        System.out.println("File: " + ioh.toHex(c) + "\n");
        //TODO: get input file for decryption signature

        digest = crh.sha256(c);
        System.out.println("Digest: " + ioh.toHex(digest) + "\n");

        //TODO: modular exponentiation using Chinese Remainder Theor
        signedDigest = crh.modExp(c, d, n);
        System.out.println("Signed digest: " + ioh.toHex(signedDigest) + "\n");
    }
}


class CryptoHandler {

    public BigInteger getProbablePrime(int nbits) {

        return new BigInteger(nbits, 1000000000, new SecureRandom());
    }

    public BigInteger productOfPrimes(BigInteger p, BigInteger q) {

        return p.multiply(q);
    }

    public BigInteger eulerTotientPhi(BigInteger p, BigInteger q) {

        // from notes: if p and q are both prime and p != q, then
        // phi(pq) = (p - 1)(q - 1)

        if (p.compareTo(q) == 0) {
            return BigInteger.ZERO;
        }

        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public boolean areRelativelyPrime(BigInteger e, BigInteger phiN) {

        return euclidianGCD(e, phiN).compareTo(BigInteger.ONE) == 0;
    }

    public BigInteger euclidianGCD(BigInteger e, BigInteger phiN) {

        /*
            r0 = q1r1 + r2
            r1 = q2r2 + r3
                where rk = rk-2 (mod rk-1), and q is some quotient

            these steps can be used progressively to find the gcd of
            r0 and r1.
         */

        while (e.compareTo(BigInteger.ZERO) != 0 && phiN.compareTo(BigInteger.ZERO) != 0) {
            if (e.compareTo(phiN) > 0) {
                e = e.mod(phiN);
            } else {
                phiN = phiN.mod(e);
            }
        }

        return e.max(phiN);
    }

    public BigInteger multiplicativeInverse(BigInteger e, BigInteger phiN) {

        /*
            from the lecture notes, we can determine when some 'a'
            has an inverse (mod N) by using our EGCD algorithm ie
            iff egcd(a, N) == 1.

            we can use an extended version of the EGCD algorithm
            to calculate our inverse.

            given a,N we can compute d,x,y using xgcd such that:
                d = gcd(a,N) = xa + yN

            NOTE: unicode for congruent symbol ≡ is u2261
            considering the above modulo N we get
                d ≡ xa + yN (mod N) ≡ xa (mod N)

            therefor if d = 1, then a has a multiplicative inverse
            giben by:
                a^-1 ≡ x (mod N)

            also: the general equation ax ≡ b (mod N) has precisely
            d = gcd(a, N) solutions iff d divides b.

        */

        // here we are going to use the quotients instead of
        // getting rid of them


        // using the explanations and examples at:
        // https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
        // in addition to the lecture notes in order to
        // figure out the extended EGCD

        // start at values of x = 0, old_x = 1, y = 1, old_y = 1
        // d = phiN, old_d = e

        BigInteger t = BigInteger.ZERO;
        BigInteger r = phiN;

        BigInteger new_t = BigInteger.ONE;
        BigInteger new_r = e;

        BigInteger tmp = BigInteger.ZERO;

        while (new_r.compareTo(BigInteger.ZERO) != 0) {
            BigInteger q = r.divide(new_r);

            tmp = t;
            t = new_t;
            new_t = tmp.subtract(q.multiply(new_t));

            tmp = r;
            r = new_r;
            new_r = tmp.subtract(q.multiply(new_r));
        }
        if (r.compareTo(BigInteger.ONE) > 0) {
            return new BigInteger("-1");
        }
        if (t.compareTo(BigInteger.ZERO) < 0) {
            t = t.add(phiN);
        }
        return t;
    }

    public byte[] getDecryptionExponent(byte[] e, byte[] phiN) {

        byte[] d = new byte[0];

        //TODO: d = multiplicativeInverse of e (mod phi(N))
        // use own umpl of euclidiannded  EGCD algorithm to calculate
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

                newkey = new BigInteger(1, key.getEncoded());
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

        BigInteger b = new BigInteger(1, value.toByteArray());
        return b.toString(16);
    }

    public BigInteger toBigInt(String keyHexString) {

        return new BigInteger(keyHexString.replaceAll("\\s+",""), 16);
    }
}
