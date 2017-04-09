/**
 * Created by minhduong on 4/1/17.
 */
import java.io.File;
import java.rmi.server.UID;
import java.util.Scanner;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.Random;

public class RSA{
    private int bitLength;//maximum bit length for primes p and q
    private int s; //security parameter used to generate primes
    private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger phiN;
    private BigInteger e, d;
    /**
     RSA Key Generation
     @param bitLength the maximum bit length of primes p and q
     */
    public RSA(int bitLength, int s){
        this.bitLength = bitLength;
        this.s = s;
        // 1. Generate primes to set this.p and this.q
        this.p = Util.probablePrime(bitLength,s);
        this.q = Util.probablePrime(bitLength,s);
        // 2. Compute n
        this.n = p.multiply(q);
        // 3. Compute phiN
        this.phiN = (p.subtract(BigInteger.valueOf(1))).multiply((q.subtract(BigInteger.valueOf(1))));
        // 4. Choose 1< e < phiN such that gcd(e, phiN) =1
        this.e = Util.choose_number_inRange(Util.one, phiN);
        BigInteger[] components = Util.eed(e,phiN);
        while (components[0].compareTo(Util.one) != 0) {
            this.e = Util.choose_number_inRange(Util.one, phiN);
            components = Util.eed(e,phiN);
        }

        // 5. Compute d such that de = 1 mod phiN
        this.d = Util.inverse(e,phiN);
    }
    /**
     You should use your modPow method defined in the Util class
     @param x plaintext
     @return x^e mod n
     */
    public BigInteger encrypt(BigInteger x){
        //To DO
        return Util.modPow(x,e,getN());
    }
    /**
     You should use your modPow method defined in the Util class
     @param y ciphertext
     @return y^d mod n
     */
    public BigInteger decrypt(BigInteger y){
        //TO DO
        return Util.modPow(y,d,getN());

    }
    public BigInteger getN(){
        return n;
    }

    public static void main(String[] args) throws FileNotFoundException{
        RSA rsa = new RSA(500, 5);
        Scanner in = new Scanner(new File(args[0]));
        BigInteger x = new BigInteger(in.nextLine(), 16);
        //Make sure that x < n
        if(x.bitLength() >= rsa.getN().bitLength()){
            System.err.println("bit length of x must be lss than bit length of n");
            System.exit(2);
        }else{
            BigInteger y = rsa.encrypt(x);
            BigInteger z = rsa.decrypt(y);
            System.out.println("plaintext x = " + x.toString(16));
            System.out.println("ciphertext y = " + y.toString(16));
            System.out.println("recovered z = " + z.toString(16));
            System.out.println(x.equals(z));
        }
    }
}