import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

public class MacHEDI {
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


    public static class Ciphertext {
        byte[] c1;
        Element[] c2;
        byte[] c3;
        Element[] c4;
        Element c5;
        
        public Ciphertext(byte[] c1, Element[] c2, byte[] c3, Element[] c4, Element c5) {
            this.c1 = c1;
            this.c2 = c2;
            this.c3 = c3;
            this.c4 = c4;
            this.c5 = c5;
        }
    }


    public static class Token {
        Element t1;
        Element[] t2;
        String visualAccount;
        
        public Token(Element t1, Element[] t2, String visualAccount) {
            this.t1 = t1;
            this.t2 = t2;
            this.visualAccount = visualAccount;
        }
    }


    public static class KeyGenResult {
        Element[] secretKey;
        String visualAccount;
        Element userSymbol;
        
        public KeyGenResult(Element[] secretKey, String visualAccount, Element userSymbol) {
            this.secretKey = secretKey;
            this.visualAccount = visualAccount;
            this.userSymbol = userSymbol;
        }
    }


    public static class ProcessedParameters {
        Element[] processedC2;
        byte[] c3;
        
        public ProcessedParameters(Element[] processedC2, byte[] c3) {
            this.processedC2 = processedC2;
            this.c3 = c3;
        }
    }


    public SystemParams Setup(int lambda, int accountNum) {
        this.pairing = PairingFactory.getPairing("a.properties");
        this.G1 = pairing.getG1();
        this.GT = pairing.getGT();
        this.Zr = pairing.getZr();
        this.g = G1.newRandomElement().getImmutable();
        this.n = accountNum;
        
        this.r = new Element[n + 1];
        this.R = new Element[n + 1];
        
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
        
        userList.put(visualAccount, new UserInfo(visualAccount, userSymbol, userId));
        
        return new KeyGenResult(secretKey, visualAccount, userSymbol);
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
        Element o2 = Zr.newRandomElement().getImmutable();
        
        byte[] c1 = HEEncrypt(heKeyPair.paillier, message);
        
        Element[] c2 = new Element[n + 1];
        Element[] c4 = new Element[n + 1];
        
        for(int i = 0; i <= n; i++) {
            if (coefficients[i] == null) {
                throw new NullPointerException("One or more required values are null!");
            }
            c2[i] = R[i].powZn(o1.mul(coefficients[i])).getImmutable();
            c4[i] = R[i].powZn(o2.mul(coefficients[i])).getImmutable();
        }
        
        Element gt = pairing.pairing(g, g).powZn(o1.mul(alpha));
        byte[] h2gt = H2(gt);
        byte[] c3 = xor(heKeyPair.paillier.getPublicKey().toByteArray(), h2gt);
        Element c5 = g.powZn(o2.mul(alpha));
        return new Ciphertext(c1, c2, c3, c4, c5);
    }

    public Token TokenGen(String userId, Element[] msk) {
        Element t = Zr.newRandomElement().getImmutable();
        Element t1 = g.powZn(t).getImmutable();
        Element[] t2 = new Element[n + 1];
        UserInfo userInfo = userList.get(userId);
        Element[] secretKey = new Element[n + 1];
        Element h1UserId = H1(userId);
        for (int i = 0; i <= n; i++) {
            Element exp = h1UserId.duplicate().powZn(Zr.newElement(i));
            exp = exp.mul(userInfo.userSymbol).mul(msk[i]);
            secretKey[i] = g.powZn(exp).getImmutable();
            t2[i] = secretKey[i].powZn(t).getImmutable();
        }
        return new Token(t1, t2, userInfo.visualAccount);
    }

    public ProcessedParameters Check(Ciphertext ciphertext, Token token) {
        UserInfo userInfo = userList.get(token.visualAccount);
        if(userInfo == null){
            System.out.println("False");
            return null;
        }
        Element invUserSymbol = userInfo.userSymbol.invert();
        Element leftSide = GT.newElement(1);
        for (int i = 0; i <= n; i++) {
            Element processedC4 = ciphertext.c4[i].powZn(invUserSymbol);
            leftSide = leftSide.mul(pairing.pairing(processedC4, token.t2[i]));
        }
        Element rightSide = pairing.pairing(ciphertext.c5, token.t1);
        if(leftSide != rightSide)  {
            System.out.println("False");
            return null;
        }
        Element[] processedC2 = new Element[n + 1];
        for (int i = 0; i <= n; i++) {
            Element base = ciphertext.c2[i].duplicate();
            processedC2[i] = base.powZn(invUserSymbol).getImmutable();
        }
        return new ProcessedParameters(processedC2, ciphertext.c3);
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

    public byte[] Request(ProcessedParameters params, Element[] secretKey, byte[] message, HEKeyPair heKeyPair) {
        if (params == null || params.processedC2 == null || secretKey == null) {
            throw new IllegalArgumentException("参数不能为空");
        }
        Element[] processedKey = new Element[secretKey.length];
        for (int i = 0; i < secretKey.length; i++) {
            processedKey[i] = secretKey[i].duplicate().getImmutable();
        }
        Element product = GT.newElement(1);
        for (int i = 0; i < secretKey.length; i++) {
            Element e = pairing.pairing(processedKey[i], params.processedC2[i]);
            product = product.mul(e);
        }
        byte[] h2gt = H2(product);
        byte[] pkBytes = xor(params.c3, h2gt);
        BigInteger pkHE = new BigInteger(1, pkBytes);
        BigInteger m = new BigInteger(1, message);
        return HEEncrypt(pkHE, m);
    }

    public byte[] Evaluate(HEKeyPair heKeyPair, byte[] c1, byte[] c2) {
        BigInteger cipher1 = new BigInteger(c1);
        BigInteger cipher2 = new BigInteger(c2);
        BigInteger result = cipher1.multiply(cipher2).mod(heKeyPair.paillier.n_square);
        return result.toByteArray();
    }

    public byte[] Decrypt(HEKeyPair heKeyPair, byte[] ciphertext) {
        BigInteger cipher = new BigInteger(ciphertext);
        BigInteger plaintext = heKeyPair.paillier.De(cipher);
        return plaintext.toByteArray();
    }
} 