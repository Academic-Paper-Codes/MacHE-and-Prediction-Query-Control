import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Policy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

public class MacHED {
    public Pairing pairing;
    public Element g;
    public Field G1, GT, Zr;
    public int n;
    public Element[] r;
    public Element[] R;
    public HashMap<String, UserInfo> userList;



    public static class UserInfo {
        String visualAccount;
        Element userSymbol;
        String realAccount;
        
        public UserInfo(String visualAccount, Element userSymbol, String realAccount) {
            this.visualAccount = visualAccount;
            this.userSymbol = userSymbol;
            this.realAccount = realAccount;
        }
    }


    public static class SystemParams {
        Element[] msk;
        PublicParams mpk;
        
        public SystemParams(Element[] msk, PublicParams mpk) {
            this.msk = msk;
            this.mpk = mpk;
        }
    }


    public static class PublicParams {
        Pairing pairing;
        Element g;
        Element[] R;
        
        public PublicParams(Pairing pairing, Element g, Element[] R) {
            this.pairing = pairing;
            this.g = g;
            this.R = R;
        }
    }


    public SystemParams Setup(int lambda, int accountNum) {

        this.pairing = PairingFactory.getPairing("a.properties");
        this.G1 = pairing.getG1();
        this.GT = pairing.getGT();
        this.Zr = pairing.getZr();
        this.g = G1.newRandomElement().getImmutable();
        this.n = accountNum;
        
        // 生成主密钥
        this.r = new Element[n + 1];
        this.R = new Element[n + 1];
        
        // 生成随机值 r_i
        for (int i = 0; i <= n; i++) {
            r[i] = Zr.newRandomElement().getImmutable();

            R[i] = g.powZn(r[i].invert()).getImmutable();
        }

        userList = new HashMap<>();
        

        return new SystemParams(
            r.clone(),
            new PublicParams(pairing, g, R.clone())
        );
    }

    public class KeyGenResult {
        Element[] secretKey;
        String visualAccount;
        Element userSymbol;
        public KeyGenResult(Element[] secretKey, String visualAccount, Element userSymbol) {
            this.secretKey = secretKey;
            this.visualAccount = visualAccount;
            this.userSymbol = userSymbol;
        }
    }

    public KeyGenResult KeyGen(Element[] msk, String userId) {
        String visualAccount = UUID.randomUUID().toString();
        Element userSymbol = Zr.newRandomElement().getImmutable();
        Element[] secretKey = new Element[n + 1];
        Element h1UserId = H1(userId);
        for (int i = 0; i <= n; i++) {
            Element exp = h1UserId.duplicate().powZn(Zr.newElement(i));
            exp = exp.mul(userSymbol).mul(r[i]);
            secretKey[i] = g.powZn(exp).getImmutable();
        }
        userList.put(userId, new UserInfo(visualAccount, userSymbol, userId));
        return new KeyGenResult(secretKey, visualAccount, userSymbol);
    }


    public static class Ciphertext {
        Element[] c2;
        byte[] c3;
        List<String> policy;
        byte[] c1;
        
        public Ciphertext(byte[] c1, Element[] c2, byte[] c3, List<String> policy) {
            this.c1 = c1;
            this.c2 = c2;
            this.c3 = c3;
            this.policy = policy;
        }
    }

    public Ciphertext Encrypt(List<String> policy, HEKeyPair heKeyPair, byte[] message) {
        int policySize = policy.size();
        List<String> fullPolicy = new ArrayList<>(policy);
        for(int i = policySize; i < n; i++) {
            fullPolicy.add("dummy_" + UUID.randomUUID().toString());
        }
        Element alpha = Zr.newRandomElement().getImmutable();
        Element[] coefficients = generatePolynomial(fullPolicy, alpha);
        Element o1 = Zr.newRandomElement().getImmutable();
        byte[] c1 = HEEncrypt(heKeyPair.paillier, message);
        Element[] c2 = new Element[n + 1];
        for(int i = 0; i <=n; i++) {
            if (coefficients[i] == null) {
                System.out.println(i);
                throw new NullPointerException("One or more required values are null!");
            }
            c2[i] = R[i].powZn(o1.mul(coefficients[i])).getImmutable();
        }
        Element gt = pairing.pairing(g, g).powZn(o1.mul(alpha));
        byte[] h2gt = H2(gt);
        byte[] c3 = xor(heKeyPair.paillier.getPublicKey().toByteArray(), h2gt);
        return new Ciphertext(c1, c2, c3, policy);
    }

    public Element[] generatePolynomial(List<String> policy, Element alpha) {
        Element[] coefficients = new Element[n + 1];
        Element[] roots = new Element[n];
        for (int i = 0; i < n; i++) {
            roots[i] = H1(policy.get(i));
        }
        coefficients[0] = alpha;
        Element temp = Zr.newElement(1);

        for (int i = 1; i <= n; i++) {
            for (int j = i - 1; j >= 0; j--) {
                temp = temp.mul(roots[i - 1].negate());
                coefficients[j] = (coefficients[j] != null) ?
                        coefficients[j].add(temp) : temp.duplicate();
            }
        }
        coefficients[n] = temp;
        return coefficients;
    }

    public static class Token {
        String visualAccount;
        String userId;
        
        public Token(String visualAccount, String userId) {
            this.visualAccount = visualAccount;
            this.userId = userId;
        }
    }
    public Token TokenGen(String userId) {
        UserInfo userInfo = userList.get(userId);
        return new Token(userInfo.visualAccount, userId);
    }
    public ProcessedParameters Check(Ciphertext ciphertext, Token token) {
        UserInfo userInfo = userList.get(token.userId);
        if(userInfo == null){
            System.out.println("False");
            return null;
        }
        Element invUserSymbol = userInfo.userSymbol.invert();
        Element[] processedC2 = new Element[n + 1];
        for (int i = 0; i <= n; i++) {
            processedC2[i] = ciphertext.c2[i].powZn(invUserSymbol).getImmutable();
        }
        return new ProcessedParameters(processedC2, ciphertext.c3);
    }


    public static class ProcessedParameters {
        Element[] processedC2;
        byte[] c3;
        
        public ProcessedParameters(Element[] processedC2, byte[] c3) {
            this.processedC2 = processedC2;
            this.c3 = c3;
        }
    }

    public byte[] Request(ProcessedParameters params, Element[] secretKey, byte[] message2) {
        Element gt = GT.newElement(1);
        for(int i = 0; i <= n; i++) {
            if(secretKey[i] == null || params.processedC2[i] == null) {
                throw new IllegalArgumentException("Invalid secret key or processed parameters");
            }
            Element sk = secretKey[i].getImmutable();
            Element pc2 = params.processedC2[i].getImmutable();
            gt = gt.mul(pairing.pairing(sk, pc2));
        }
        byte[] h2gt = H2(gt);
        byte[] pkBytes = xor(params.c3, h2gt);
        return HEEncrypt(pkBytes, message2);

    }


    public byte[] Evaluate(HEKeyPair heKeyPair,byte[] c1, byte[] c2) {
        BigInteger cipher1 = new BigInteger(1, c1);
        BigInteger cipher2 = new BigInteger(1, c2);
        BigInteger result = cipher1.multiply(cipher2).mod(heKeyPair.paillier.n_square);
        return result.toByteArray();
    }
    public byte[] Decrypt(HEKeyPair heKeyPair, byte[] encryptedResult) {
        BigInteger cipher = new BigInteger(1, encryptedResult);
        BigInteger decrypted = heKeyPair.paillier.De(cipher);
        return decrypted.toByteArray();
    }
} 