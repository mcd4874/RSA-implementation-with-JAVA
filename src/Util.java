/**
 * Created by minhduong on 4/1/17.
 */
import java.math.BigInteger;
import java.util.Random;

/**
 The Util class provides useful methods needed in the RSA class
 */
public class Util {
    public static final BigInteger zero = BigInteger.valueOf(0);
    public static final BigInteger one = BigInteger.valueOf(1);
    public static final BigInteger two = BigInteger.valueOf(2);
    /**
     The eed method will be used to generate a private key d
     */
//    public static BigInteger[] eed(BigInteger r0, BigInteger r1) {}

   //Modify the following eed method to a BigInteger version
   public static BigInteger[] eed(BigInteger r0, BigInteger r1) {
       BigInteger s0 = BigInteger.valueOf(1), s1 = BigInteger.valueOf(0);
       BigInteger t0 = BigInteger.valueOf(0), t1 = BigInteger.valueOf(1);
       BigInteger[] results = new BigInteger[3];
       while (true) {
           if (r1.equals(BigInteger.valueOf(0))) {
               results[0] = r0;
               results[1] = s0;
               results[2] = t0;
               return results;
           }
           BigInteger q = r0.divide(r1);
           BigInteger r2 = r0.remainder (r1);
           BigInteger s2 = s0.subtract(q.multiply(s1));
           BigInteger t2 = t0.subtract(q.multiply(t1));

           //System.out.println(r2 + " " + s2 + " " + t2);

           //update variables
           s0 = s1;
           s1 = s2;
           t0 = t1;
           t1 = t2;
           r0 = r1;
           r1 = r2;
       }
   }


    public static BigInteger inverse(BigInteger x, BigInteger m) {
        BigInteger [] coefficient = eed(m,x);
        if ( coefficient[0].compareTo(one) != 0) {
            return zero;
        }
        return coefficient[2].mod(m);
    }


    /**
     The modPow method is used for RSA encryption and decryption
     Use recursion to implement the fast exponent idea we discussed (or will discuss soon)
     @return a BigInteger whose value is (x^e mod n)
     */
    public static BigInteger modPow(BigInteger x, BigInteger e, BigInteger n){
        if ( e.equals(BigInteger.valueOf(1))) {
            return x.mod(n);
        } else {
            //check if e%2 == 0
            if (e.mod(BigInteger.valueOf(2)).equals(BigInteger.valueOf(0))) {
                //recursive with e/2 for e%2 == 0
                BigInteger temp = modPow(x, e.divide(BigInteger.valueOf(2)), n);
                // calculate x^2 mod n
                x = (temp.pow(2)).mod(n);
            } else {
                //recursive with (e-1)/2 for e%2 !=0
                BigInteger temp = modPow(x, e.subtract(BigInteger.valueOf(1)).divide(BigInteger.valueOf(2)), n);
                //calculate ((x^2) mod n) *x mod n
                x = (((temp.pow(2)).mod(n)).multiply(x)).mod(n);
            }
            return x;
        }
    }


    public static BigInteger choose_number_inRange(BigInteger lowerBound, BigInteger upperBound){
        Random rng = new Random();
        BigInteger e = new BigInteger(upperBound.bitLength()-1,rng);
        while (e.compareTo(two) == -1){
            e = new BigInteger(upperBound.bitLength()-1,rng);
        }
        return e;
    }

    //assum bitlength >1
    public static BigInteger generatePrimeCandidate(int bitLength){
        Random rng = new Random();
        BigInteger random_number = new BigInteger(bitLength, rng);
        //if the random_number equal to 0 or 1
        while (random_number.compareTo(two) == -1) {
            random_number = new BigInteger(bitLength, rng);
        }
        //if the random number is 2 then it is qualify
        if (random_number.compareTo(two) == 0)
            return random_number;
        // if the number is odd then it qualify
        if ((random_number.mod(two).compareTo(one) == 0)) {
            return random_number;
        } else {
            //change an even to odd number
            return random_number.subtract(one);
        }

    }



    public static boolean PrimalityTest(BigInteger p, int s) {
        if (p.compareTo(two) == 0)
            return true;

        BigInteger r = p;
        int u = 0;
        r = r.subtract(one);
        while ((r.mod(two)).compareTo(zero) == 0){
            r = r.divide(two);
            u++;
        }

        BigInteger uperLimit = p.subtract(two);

        for (int i =1; i<=s; i++) {
            BigInteger a = choose_number_inRange(two,uperLimit);
            BigInteger z = modPow(a,r,p);
            if ((z.compareTo(one) != 0) && (z.compareTo(p.subtract(one)) != 0) ) {
                for (int j=1; j<= u-1; j++) {
                    z = modPow(z, two, p);
                    if (z.compareTo(one) == 0) {
                        return false;
                    }
                }

                if ( z.compareTo(p.subtract(one)) != 0){
                    return false;
                }
            }
        }
        return true;
    }

    /**
     The probablePrime method is used to generate primes p and q in
     RSA key generation
     Use Miller–Rabin Primality Test (Sec 7.6.2) to generate a prime
     @param bitLength maximum bit length of prime to be generated
     @param s security parameter
     @return a probable prime
     */
    public static BigInteger probablePrime(int bitLength, int s){
        BigInteger prime_candidate = generatePrimeCandidate(bitLength);
        //System.out.print("the current generate prime: "+prime_candidate.toString());
        //generate random number with max bit length
        // continuesloy check for prime candidate till it find a prime
        while (!PrimalityTest(prime_candidate,s))
            prime_candidate = generatePrimeCandidate(bitLength);
        return prime_candidate;
    }
}