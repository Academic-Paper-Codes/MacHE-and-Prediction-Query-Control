import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

public class MacHEIPQC {
    public Pairing pairing;
    public Element g;
    public Field G1, GT, Zr;
    public int n;
    public Element[] r;
    public Element[] R;
    public HashMap<String, UserInfo> userList;
    public HEKeyPair heKeyPair;
    
    // 用户信息类
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

    // 系统参数
    public static class SystemParams {
        public Element[] msk;
        public PublicParams mpk;
        public HEKeyPair hePair;
        
        public SystemParams(Element[] msk, PublicParams mpk, HEKeyPair hePair) {
            this.msk = msk;
            this.mpk = mpk;
            this.hePair = hePair;
        }
    }

    // 公共参数
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

    // 密文类
    public static class Ciphertext {
        public byte[][] c1;
        public Element[] c2;
        public byte[] c3;
        public byte[][] c4;
        public Element[] c5;
        public byte[] c6;
        public byte[][] c7;
        public Element[] c8;
        public byte[] c9;
        public byte[][] c10;
        public Element[] c11;
        public byte[] c12;

        public Element[] c13;
        public Element c14;
        public Element[] c15;
        public Element c16;
        public Element[] c17;
        public Element c18;
        public Element[] c19;
        public Element c20;
        
        public List<String> policy1;
        public List<String> policy2;
        public List<String> policy3;
        public List<String> policy4;
        
        public Ciphertext(
            byte[][] c1, Element[] c2, byte[] c3,
            byte[][] c4, Element[] c5, byte[] c6,
            byte[][] c7, Element[] c8, byte[] c9,
            byte[][] c10, Element[] c11, byte[] c12,
            Element[] c13, Element c14,
            Element[] c15, Element c16,
            Element[] c17, Element c18,
            Element[] c19, Element c20,
            List<String> policy1, List<String> policy2,
            List<String> policy3, List<String> policy4
        ) {
            this.c1 = c1;
            this.c2 = c2;
            this.c3 = c3;
            this.c4 = c4;
            this.c5 = c5;
            this.c6 = c6;
            this.c7 = c7;
            this.c8 = c8;
            this.c9 = c9;
            this.c10 = c10;
            this.c11 = c11;
            this.c12 = c12;
            this.c13 = c13;
            this.c14 = c14;
            this.c15 = c15;
            this.c16 = c16;
            this.c17 = c17;
            this.c18 = c18;
            this.c19 = c19;
            this.c20 = c20;
            this.policy1 = policy1;
            this.policy2 = policy2;
            this.policy3 = policy3;
            this.policy4 = policy4;
        }
    }

    public static class Token {
        String type;
        Element t1;
        Element[] t2;
        String visualAccount;
        public Token(String type, Element t1, Element[] t2, String visualAccount) {
            this.type = type;
            this.t1 = t1;
            this.t2 = t2;
            this.visualAccount = visualAccount;
        }
    }

    public static class ProcessedParameters {
        Element[] processedC;
        byte[] c;
        Element extraParam;

        public ProcessedParameters(Element[] processedC, byte[] c, Element extraParam) {
            this.processedC = processedC;
            this.c = c;
            this.extraParam = extraParam;
        }
    }

    public Ciphertext Encrypt(String[] attrs, HEKeyPair hePair, byte[] message) {
        try {
            // 参数检查
            if (n <= 0 || R == null || R.length != n + 1 || g == null) {
                throw new IllegalStateException("System parameters not properly initialized");
            }
            List<String> policy = Arrays.asList(attrs);
        Element alpha = Zr.newRandomElement().getImmutable();
        Element beta = Zr.newRandomElement().getImmutable();
            Element gamma = Zr.newRandomElement().getImmutable();
            Element delta = Zr.newRandomElement().getImmutable();
            Element[] coefficients = generatePolynomial(policy, alpha);
            Element[] coefficients2 = generatePolynomial(policy, beta);
            Element[] coefficients3 = generatePolynomial(policy, gamma);
            Element[] coefficients4 = generatePolynomial(policy, delta);
            
            if (coefficients == null || coefficients2 == null || 
                coefficients3 == null || coefficients4 == null) {
                throw new IllegalStateException("Failed to generate polynomial coefficients");
            }

            byte[][] c1 = PHEEncrypt(hePair.paillier, message);
            byte[][] c4 = SHEEncrypt(hePair.bfv, message);
            byte[][] c7 = FHEEncrypt(hePair.ckks, message);
            byte[][] c10 = SEEncrypt(hePair.aes, message);
        Element[] c2 = new Element[n + 1];
        Element[] c5 = new Element[n + 1];
        Element[] c8 = new Element[n + 1];
        Element[] c11 = new Element[n + 1];
            for (int i = 0; i <= n; i++) {
                c2[i] = g.powZn(coefficients[i]).getImmutable();
                c5[i] = g.powZn(coefficients2[i]).getImmutable();
                c8[i] = g.powZn(coefficients3[i]).getImmutable();
                c11[i] = g.powZn(coefficients4[i]).getImmutable();
            }
        Element[] c13 = new Element[n + 1];
        Element[] c15 = new Element[n + 1];
        Element[] c17 = new Element[n + 1];
        Element[] c19 = new Element[n + 1];
        for (int i = 0; i <= n; i++) {
                c13[i] = R[i].powZn(alpha).getImmutable();
                c15[i] = R[i].powZn(beta).getImmutable();
                c17[i] = R[i].powZn(gamma).getImmutable();
                c19[i] = R[i].powZn(delta).getImmutable();
            }

            Element c14 = g.powZn(alpha).getImmutable();
            Element c16 = g.powZn(beta).getImmutable();
            Element c18 = g.powZn(gamma).getImmutable();
            Element c20 = g.powZn(delta).getImmutable();
        byte[] c3 = H2(pairing.pairing(g, g).powZn(alpha));
        byte[] c6 = H2(pairing.pairing(g, g).powZn(beta));
            byte[] c9 = H2(pairing.pairing(g, g).powZn(gamma));
            byte[] c12 = H2(pairing.pairing(g, g).powZn(delta));
        return new Ciphertext(
            c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12,
            c13, c14, c15, c16, c17, c18, c19, c20,
                Arrays.asList(attrs), Arrays.asList(attrs), Arrays.asList(attrs), Arrays.asList(attrs)
            );
        } catch (Exception e) {
            System.err.println("Error in Encrypt: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public ProcessedParameters Check(Ciphertext ciphertext, Token token) {
        try {
            UserInfo userInfo = userList.get(token.visualAccount);
            if (userInfo == null) {
                throw new IllegalArgumentException("User not found");
            }
            Element invUserSymbol = userInfo.userSymbol.invert();
            switch (token.type) {
                case "Partially":

                    Element leftSide = GT.newElement(1);
                    for (int i = 0; i <= n; i++) {
                        Element processedC13 = ciphertext.c13[i].powZn(invUserSymbol);
                        leftSide = leftSide.mul(pairing.pairing(processedC13, token.t2[i]));
                    }
                    Element rightSide = pairing.pairing(ciphertext.c14, token.t1);
                    if (!leftSide.equals(rightSide)) {
                        return null;
                    }
                    Element[] processedC2 = new Element[n + 1];
                for (int i = 0; i <= n; i++) {
                        processedC2[i] = ciphertext.c2[i].powZn(invUserSymbol).getImmutable();
                }
                    return new ProcessedParameters(processedC2, ciphertext.c3, null);

                case "Somewhat":
                    leftSide = GT.newElement(1);
                for (int i = 0; i <= n; i++) {
                        Element processedC15 = ciphertext.c15[i].powZn(invUserSymbol);
                    leftSide = leftSide.mul(pairing.pairing(processedC15, token.t2[i]));
                }
                rightSide = pairing.pairing(ciphertext.c16, token.t1);
                    
                    if (!leftSide.equals(rightSide)) {
                        return null;
                    }
                    Element[] processedC5 = new Element[n + 1];
                    for (int i = 0; i <= n; i++) {
                        processedC5[i] = ciphertext.c5[i].powZn(invUserSymbol).getImmutable();
                    }
                    return new ProcessedParameters(processedC5, ciphertext.c6, null);
                    
                case "Fully":
                    leftSide = GT.newElement(1);
                for (int i = 0; i <= n; i++) {
                        Element processedC17 = ciphertext.c17[i].powZn(invUserSymbol);
                    leftSide = leftSide.mul(pairing.pairing(processedC17, token.t2[i]));
                }
                rightSide = pairing.pairing(ciphertext.c18, token.t1);
                    if (!leftSide.equals(rightSide)) {
                        return null;
                    }
                    Element[] processedC8 = new Element[n + 1];
                    for (int i = 0; i <= n; i++) {
                        processedC8[i] = ciphertext.c8[i].powZn(invUserSymbol).getImmutable();
                    }
                    return new ProcessedParameters(processedC8, ciphertext.c9, null);
                case "Complicated":
                    leftSide = GT.newElement(1);
                for (int i = 0; i <= n; i++) {
                        Element processedC19 = ciphertext.c19[i].powZn(invUserSymbol);
                    leftSide = leftSide.mul(pairing.pairing(processedC19, token.t2[i]));
                }
                rightSide = pairing.pairing(ciphertext.c20, token.t1);
                    
                    if (!leftSide.equals(rightSide)) {
                        return null;
                    }
                    Element[] processedC11 = new Element[n + 1];
                    for (int i = 0; i <= n; i++) {
                        processedC11[i] = ciphertext.c11[i].powZn(invUserSymbol).getImmutable();
                    }
                    Element extraParam = G1.newRandomElement().getImmutable();
                    return new ProcessedParameters(processedC11, ciphertext.c12, extraParam);
            default:
                    throw new IllegalArgumentException("Invalid token type: " + token.type);
            }
            
        } catch (Exception e) {
            System.err.println("Error in Check: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public SystemParams Setup(int lambda, int attrNum) {

        this.n = attrNum;
        this.pairing = PairingFactory.getPairing("a.properties");
        this.G1 = pairing.getG1();
        this.GT = pairing.getGT();
        this.Zr = pairing.getZr();
        this.g = G1.newRandomElement().getImmutable();
        this.r = new Element[n + 1];
        this.R = new Element[n + 1];
        Element baseR = Zr.newRandomElement().getImmutable();
        for (int i = 0; i <= n; i++) {
            r[i] = baseR.add(Zr.newElement(i)).getImmutable();
            R[i] = g.powZn(r[i]).getImmutable();
        }
        
        return new SystemParams(
            r.clone(),
            new PublicParams(pairing, g, R.clone()),
            heKeyPair
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

    public Token TokenGen(String userId, String tokenType) {
        try {
            if (userId == null || tokenType == null) {
                throw new IllegalArgumentException("User ID and token type cannot be null");
            }
            UserInfo userInfo = userList.get(userId);
        if (userInfo == null) {
                throw new IllegalArgumentException("User not found: " + userId);
        }
        Element t = Zr.newRandomElement().getImmutable();
        Element t1 = g.powZn(t).getImmutable();
        Element[] secretKey = new Element[n + 1];
        Element h1UserId = H1(userId);
        Element[] t2 = new Element[n + 1];
        for (int i = 0; i <= n; i++) {
                Element exp = h1UserId.duplicate().powZn(Zr.newElement(i));
                exp = exp.mul(userInfo.userSymbol).mul(r[i]);
                secretKey[i] = g.powZn(exp).getImmutable();
                t2[i] = secretKey[i].powZn(t).getImmutable();
            }
            return new Token(tokenType, t1, t2, userInfo.visualAccount);
            
        } catch (Exception e) {
            System.err.println("Error in TokenGen: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    public Element[] generatePolynomial(List<String> policy, Element alpha) {
        Element[] coefficients = new Element[policy.size() + 1];
        coefficients[0] = alpha;
        Element[] roots = new Element[policy.size()];
        for (int i = 0; i < policy.size(); i++) {
            roots[i] = H1(policy.get(i));
        }
        Element temp = Zr.newElement(1);
        for (int i = 0; i < policy.size(); i++) {
            for (int j = i; j >= 0; j--) {
                if (coefficients[j] != null) {
                    coefficients[j + 1] = (coefficients[j + 1] == null) ?
                            coefficients[j].duplicate() : coefficients[j + 1].add(coefficients[j]);
                }
                if (j > 0) {
                    coefficients[j - 1] = (coefficients[j - 1] == null) ?
                            roots[i].negate().mul(coefficients[j]) :
                            coefficients[j - 1].sub(roots[i].mul(coefficients[j]));
                }
            }
        }
        return coefficients;
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
    // 修改构造函数
    public MacHEIPQC(HEKeyPair heKeyPair) {
        this.userList = new HashMap<>();
        this.heKeyPair = heKeyPair;  // 使用共享的实例
    }

}