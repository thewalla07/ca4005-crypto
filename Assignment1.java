import java.math.BigInteger;

public class Assignment1 {

	public static void main(String[] args) {
        
		System.out.println("Hello, Crypto!");

        System.out.println(createNBitKey(4));
	}
    
    public static BigInteger createNBitKey(long n) {
        return new BigInteger(n);
    }
}
