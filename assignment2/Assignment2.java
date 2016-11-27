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

        BigInteger e = new BigInteger("65537");

        BigInteger phiN = e;

        BigInteger p = BigInteger.ZERO;
        BigInteger q = BigInteger.ZERO;
        BigInteger n = BigInteger.ZERO;

        System.out.println("Assignment 2");

        // 1. generate two distinct 512-bit probable primes p and q
        p = crh.getProbablePrime(512);
        System.out.println("p: "+ioh.toHex(p) + "\n");

        q = crh.getProbablePrime(512);
        System.out.println("q: "+ioh.toHex(q) + "\n");

        // 2. calculate the product of these two primes N = pq
        n = crh.productOfPrimes(p, q);
        System.out.println("n: "+ioh.toHex(n) + "\n");

        // 3. calculate the euler totient function phi(N)
        phiN = crh.eulerTotientPhi(p, q);
        System.out.println("phi(n): "+ioh.toHex(phiN) + "\n");

        // 4. you will be using an encryption exponent e = 65537, so you will
        // need to ensure it is relatively prime to phi(N). If it is not, go
        // back to step 1 and generate new values for p and q.
        int i = 0;
        while(!crh.areRelativelyPrime(e, phiN)) {

            // 1. generate two distinct 512-bit probable primes p and q
            p = crh.getProbablePrime(512);
            System.out.println("p: "+ioh.toHex(p) + "\n");

            q = crh.getProbablePrime(512);
            System.out.println("q: "+ioh.toHex(q) + "\n");

            // 2. calculate the product of these two primes N = pq
            n = crh.productOfPrimes(p, q);
            System.out.println("n: "+ioh.toHex(n) + "\n");

            // 3. calculate the euler totient function phi(N)
            phiN = crh.eulerTotientPhi(p, q);
            System.out.println("phi(n): "+ioh.toHex(phiN) + "\n");

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

        // 6. You should then write code to implement a decryption method which
        // calculates c^d (mod N). You should use your own implementation of the
        // chinese remainder theorem to calculate this more efficiently; this
        // can also make use of your multiplicative inverse implementation.

        // Done

        // 7. Once your implementation is complete, you should create a zip file
        // containing all your code and digitally sign a digest of this file as
        // follows:

        // 7.1. Generate a 256-bit digest of the zip file using SHA-256
        String filename = "Assignment2.zip";
        byte[] fileBytes = ioh.readFile(filename);

        BigInteger c = new BigInteger(1, fileBytes);
        System.out.println("File: " + ioh.toHex(c) + "\n");

        BigInteger digest = crh.sha256(c);
        System.out.println("Digest: " + ioh.toHex(digest) + "\n");

        // 7.2. Apply your decryption method to this digest. Note that for the
        // purpose of this assignment no padding should be added to the digest
        BigInteger signedDigest = crh.modExpCRT(c, d, p, q, n);
        System.out.println("Signed digest w/ CRT: " + ioh.toHex(signedDigest) + "\n");

        // Values to send
        ioh.writeAsHex(n, "n.hex");
        // zipped code file
        ioh.writeAsHex(signedDigest, "signedDigest.hex");
        // declaration of sole work
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

    public BigInteger modExpCRT(BigInteger c, BigInteger d, BigInteger p, BigInteger q, BigInteger n) {
        // calculate c ^ d (mod N), using CRT. We take N in via its factors,
        // p and q.

        BigInteger tmp = p;
        p = tmp.min(q);
        q = tmp.max(q);

        BigInteger step1 = c.modPow(d.mod(p.subtract(BigInteger.ONE)), p);
        BigInteger step2 = c.modPow(d.mod(q.subtract(BigInteger.ONE)), q);

        BigInteger modInvQ = multiplicativeInverse(q, p);

        return step2.add(q.multiply(modInvQ.multiply(step1.subtract(step2)).mod(p)));
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
