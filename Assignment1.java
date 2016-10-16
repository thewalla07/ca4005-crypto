import java.math.BigInteger;
import java.util.Random;

public class Assignment1 {

    private static int nBits = 1023;

    public static void main(String[] args) {

        System.out.println("Hello, Crypto!");

        System.out.println("Private Key of " + nBits + " bits: " + createNBitKey(nBits));
    }
    
    public static BigInteger createNBitKey(int nBits) {

        return new BigInteger(nBits, new Random());
    }
}
