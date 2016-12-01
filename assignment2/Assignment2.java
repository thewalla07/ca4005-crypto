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
        if (args.length == 1) {
            filename = args[0];
        }
        byte[] fileBytes = ioh.readFile(filename);

        BigInteger c = new BigInteger(1, fileBytes);
        System.out.println("File: " + ioh.toHex(c) + "\n");

        BigInteger digest = crh.sha256(c);
        System.out.println("Digest: " + ioh.toHex(digest) + "\n");

        // 7.2. Apply your decryption method to this digest. Note that for the
        // purpose of this assignment no padding should be added to the digest
        BigInteger signedDigest = crh.modExpCRT(digest, d, p, q);
        System.out.println("Signed digest w/ CRT: " + ioh.toHex(signedDigest) + "\n");

        // Values to send for assignment submission
        // zipped code file
        // declaration of sole work
        ioh.writeAsHex(signedDigest, "signedDigest.hex");
        ioh.writeAsHex(n, "n.hex");

        /************
        *
        *   Done
        *
        ************/
        // Values for my own testing purposes

        ioh.writeAsHex(d, "d.hex");
        ioh.writeAsHex(e, "e.hex");

        BigInteger unsignedDigest = signedDigest.modPow(e, n);

        ioh.writeAsHex(digest, "digest.hex");
        ioh.writeAsHex(unsignedDigest, "unsignedDigest.hex");
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

        /*
            from notes: if p and q are both prime and p != q, then
            phi(pq) = (p - 1)(q - 1)

            since I pre check for primality of p and q when they are
            generated, I will not check them again here, I assume
            that any values passed in are probable primes.
        */

        if (p.compareTo(q) == 0) {

            return BigInteger.ZERO;
        }

        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public boolean areRelativelyPrime(BigInteger a, BigInteger b) {

        return euclidianGCD(a, b).compareTo(BigInteger.ONE) == 0;
    }

    public BigInteger euclidianGCD(BigInteger a, BigInteger b) {

        /*
            Theory from the notes:

            r0 = q1r1 + r2
            r1 = q2r2 + r3
                where rk = rk-2 (mod rk-1), and q is some quotient

            these steps can be used progressively to find the gcd of
            r0 and r1.

            In the example from lecture notes:
            gcd(21, 12)
                = gcd(21 mod 12, 12)
                = gcd(9, 12)
                = gcd(9, 12 mod 9)
                = gcd(3, 9)
                = gcd(3, 9 mod 3)
                = gcd(3, 0)
                = 3
            ...it is understood from the above example that
            the gcd is found by performing the following operation
            until one of the values a or b becomes 0;

                max(a, b) = max(a, b) (mod min(a, b))

            at which point the gcd is the remaining non-zero number i.e. the
            max value of a and b.
         */

        while (a.compareTo(BigInteger.ZERO) != 0 && b.compareTo(BigInteger.ZERO) != 0) {

            if (a.compareTo(b) > 0) {

                a = a.mod(b);

            } else {

                b = b.mod(a);
            }
        }

        return a.max(b);
    }

    public BigInteger multiplicativeInverse(BigInteger a, BigInteger b) {

        /*
            To get the multiplicative inverse, we use an extended
            form of the Euclidian GCD function above. Where before
            we would perform a modulus operation to reduce the numbers
            only, now we will want to make use of the quotient remainder
            of these operations.

            I used a combination of the lecture theory and examples at:
            https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
            to learn about the extended euclidian gcd.

            From the lecture notes, we can determine when some 'a'
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

        BigInteger t = BigInteger.ZERO;
        BigInteger r = b;

        BigInteger new_t = BigInteger.ONE;
        BigInteger new_r = a;

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

        if (r.compareTo(BigInteger.ONE) != 0) {

            /*
                the value r is equivalent to the value of the function
                egcd(a, b) if the value is not == 1, then no multiplicative
                inverse exists, so I will return a -1 to be picked up by the
                caller of this function.
            */

            return new BigInteger("-1");
        }

        if (t.compareTo(BigInteger.ZERO) < 0) {

            /*
                we can correct a negative t value simply by adding the original
                b value
            */

            t = t.add(b);
        }

        return t;
    }

    public BigInteger modExpCRT(BigInteger c, BigInteger d, BigInteger p, BigInteger q) {

        /*
            calculate c ^ d (mod N), using CRT. We take N in via its factors,
            p and q.

            steps to perform modular exponentiation were learned from a
            combination of the lecture notes theory and additional learning
            using the resources below:
            https://en.wikipedia.org/wiki/Chinese_remainder_theorem
            https://crypto.stanford.edu/pbc/notes/numbertheory/crt.html
            http://www.cut-the-knot.org/blue/chinese.shtml
            https://www.youtube.com/watch?v=ru7mWZJlRQg
        */

        /*
            calculate c ^ d (mod N) where N = pq:

            We can simplify this process because we know the factors of N.
            First we perform modular exponentiation of:
                c ^ d (mod p)
                c ^ d (mod q)

            These can be made more efficient by the following general equation:

                x ^ y (mod m) = (x mod m) ^ (y mod phi(m))

            It is efficient to calculate phi(p) or phi(q) in our case because
            we know they are (probably) primes.

            However, since BigInteger does not have a function to calculate
            this.pow(BigInteger value), we must use modPow in order to get
            powers. This results in a rearrangement of the above formula to:

                x ^ (y mod phi(m)) (mod m)

            In my own testing, this still results in a performance improvement.
        */

        // Before calculating, we rearrange p and q so that p = min and q = max.
        BigInteger tmp = p;
        p = tmp.min(q);
        q = tmp.max(q);

        // x mod N  = SUM: ai . Ni . yi
        // Ni = N/ni
        // yi = Ni^-1 (mod ni)
        // WHERE  a = integers
        //       n = pairwise primes

        // a1 = (c mod p) ^ (d mod phi(p)).
        // a2 = (c mod q) ^ (d mod phi(q)).
        BigInteger a1 = c.modPow(d.mod(p.subtract(BigInteger.ONE)), p);
        BigInteger a2 = c.modPow(d.mod(q.subtract(BigInteger.ONE)), q);


        // Since N only has 2 factors p and q,
        // N1 = pq/p = q
        // N2 = pq/q = p
        BigInteger n1 = q;
        BigInteger n2 = p;

        // y1 = q^-1 (mod p)
        // y2 = p^-1 (mod q)
        BigInteger y1 = multiplicativeInverse(q, p);
        BigInteger y2 = multiplicativeInverse(p, q);

        /*
            result
                = a1.N1.y1 + a2.N2.y2 (mod pq)
                = a1.n2.y1 + a2.n1.y2 (mod pq)

            ...this can be expanded and simplified to the following:

                = a2 + n2.(n1^-1.(a1-a2) mod n1)

            ...which is slightly more efficient requiring less multiplications.

        */
        BigInteger result = a2.add(q.multiply(y1.multiply(a1.subtract(a2)).mod(p)));

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

        return new BigInteger(1, digestBytes);
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

    public void writeAsHex(BigInteger value, String filename) {

        try {

            PrintWriter out = new PrintWriter(filename);
            out.println(toHex(value));
            out.close();

        } catch (FileNotFoundException e) {

            e.printStackTrace();
        }
    }

    public String toHex(BigInteger value) {

        BigInteger b = new BigInteger(1, value.toByteArray());
        return b.toString(16);
    }
}
