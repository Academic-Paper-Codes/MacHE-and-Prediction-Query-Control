import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class MacHEPQC {
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
        public Element[] msk;
        public PublicParams mpk;
        public HEKeyPair hePair;
        
        public SystemParams(Element[] msk, PublicParams mpk, HEKeyPair hePair) {
            this.msk = msk;
            this.mpk = mpk;
            this.hePair = hePair;
        }
    }

    public static class PublicParams {
        public Pairing pairing;
        public Element g;
        public Element[] R;
        public int p;
        public Field G, GT, Zr;

        public PublicParams(Pairing pairing, Element g, Element[] R,
                            int p, Field G, Field GT, Field Zr) {
            this.pairing = pairing;
            this.g = g;
            this.R = R;
            this.p = p;
            this.G = G;
            this.GT = GT;
            this.Zr = Zr;
        }
    }
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
        public List<String> policy1;
        public List<String> policy2;
        public List<String> policy3;
        public List<String> policy4;
        
        public Ciphertext(byte[][] c1, Element[] c2, byte[] c3, 
                         byte[][] c4, Element[] c5, byte[] c6,
                         byte[][] c7, Element[] c8, byte[] c9,
                         byte[][] c10, Element[] c11, byte[] c12,
                         List<String> policy1, List<String> policy2,
                         List<String> policy3, List<String> policy4) {
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
            this.policy1 = policy1;
            this.policy2 = policy2;
            this.policy3 = policy3;
            this.policy4 = policy4;
        }
    }

    public static class Token {
        String type;
        String visualAccount;
        String realAccount;

        public Token(String type, String visualAccount, String realAccount) {
            this.type = type;
            this.visualAccount = visualAccount;
            this.realAccount = realAccount;
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
        Element[] processedC;
        byte[] c;
        byte[][] c10;
        public ProcessedParameters(Element[] processedC, byte[] c) {
            this.processedC = processedC;
            this.c = c;
            this.c10 = null;
        }

        public ProcessedParameters(Element[] processedC, byte[] c, byte[][] c10) {
            this.processedC = processedC;
            this.c = c;
            this.c10 = c10;
        }
    }

    public SystemParams Setup(int lambda, int attrNum) {

        this.pairing = PairingFactory.getPairing("a.properties");
        this.G1 = pairing.getG1();
        this.GT = pairing.getGT();
        this.Zr = pairing.getZr();
        this.n = attrNum;
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
                new PublicParams(pairing, g, R.clone(), lambda, G1, GT, Zr),
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

    // Encrypt函数实现
    public Ciphertext Encrypt(String[] attrs, HEKeyPair hePair, byte[] message) {
        try {
            // 参数检查
            if (n <= 0 || R == null || R.length != n + 1 || g == null) {
                throw new IllegalStateException("System parameters not properly initialized");
            }
            List<String> policy1 = new ArrayList<>(Arrays.asList(attrs));
            List<String> policy2 = new ArrayList<>(policy1.subList(0, policy1.size() * 3 / 4));
            List<String> policy3 = new ArrayList<>(policy1.subList(0, policy1.size() * 2 / 4));
            List<String> policy4 = new ArrayList<>(policy1.subList(0, policy1.size() * 1 / 4));
            fillPolicyWithDummy(policy1, n);
            fillPolicyWithDummy(policy2, n);
            fillPolicyWithDummy(policy3, n);
            fillPolicyWithDummy(policy4, n);

        Element alpha = Zr.newRandomElement().getImmutable();
        Element beta = Zr.newRandomElement().getImmutable();
        Element omega = Zr.newRandomElement().getImmutable();
        Element theta = Zr.newRandomElement().getImmutable();

        Element o1 = Zr.newRandomElement().getImmutable();
        Element o2 = Zr.newRandomElement().getImmutable();
        Element o3 = Zr.newRandomElement().getImmutable();
        Element o4 = Zr.newRandomElement().getImmutable();

            byte[][] c1 = PHEEncrypt(hePair.paillier, message);
            byte[][] c4 = SHEEncrypt(hePair.bfv, message);
            byte[][] c7 = FHEEncrypt(hePair.ckks, message);

            Element[] coefficients1 = generatePolynomial(policy1, alpha);
            Element[] coefficients2 = generatePolynomial(policy2, beta);
            Element[] coefficients3 = generatePolynomial(policy3, omega);
            Element[] coefficients4 = generatePolynomial(policy4, theta);

        Element[] c2 = new Element[n + 1];
        Element[] c5 = new Element[n + 1];
        Element[] c8 = new Element[n + 1];
        Element[] c11 = new Element[n + 1];
        
        for (int i = 0; i <= n; i++) {
            c2[i] = R[i].powZn(o1.mul(coefficients1[i])).getImmutable();
            c5[i] = R[i].powZn(o2.mul(coefficients2[i])).getImmutable();
            c8[i] = R[i].powZn(o3.mul(coefficients3[i])).getImmutable();
            c11[i] = R[i].powZn(o4.mul(coefficients4[i])).getImmutable();
        }

        Element gt1 = pairing.pairing(g, g).powZn(o1.mul(alpha));
        Element gt2 = pairing.pairing(g, g).powZn(o2.mul(beta));
        Element gt3 = pairing.pairing(g, g).powZn(o3.mul(omega));
        Element gt4 = pairing.pairing(g, g).powZn(o4.mul(theta));
        
            byte[] c3 = xor(hePair.paillier.getPublicKey().toByteArray(), H2(gt1));
            byte[] c6 = xor(hePair.bfv.getPublicKey(), H2(gt2));
            byte[] c9 = xor(hePair.ckks.getPublicKey(), H2(gt3));
            byte[] c12 = xor(hePair.aes.getKey(), H2(gt4));

            return new Ciphertext(
                c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12,
                policy1, policy2, policy3, policy4
            );

        } catch (Exception e) {
            System.err.println("Error in Encrypt: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public Token TokenGen(String userId, String tokenType) {
        try {
            if (userId == null || tokenType == null) {
                throw new IllegalArgumentException("User ID and token type cannot be null");
            }
            if (!isValidTokenType(tokenType)) {
                throw new IllegalArgumentException("Invalid token type: " + tokenType);
            }
            UserInfo userInfo = null;
            for (UserInfo info : userList.values()) {
                if (info.realAccount.equals(userId)) {
                    userInfo = info;
                    break;
                }
            }
            if (userInfo == null) {
                throw new IllegalArgumentException("User not found: " + userId);
            }
            return new Token(tokenType, userInfo.visualAccount, userInfo.realAccount);
            
        } catch (Exception e) {
            System.err.println("Error in TokenGen: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public ProcessedParameters Check(Ciphertext ciphertext, Token token) {
        try {
            UserInfo userInfo = null;
            for (UserInfo info : userList.values()) {
                if (info.realAccount.equals(token.realAccount)) {
                    userInfo = info;
                    break;
                }
            }
            if (userInfo == null) {
                throw new IllegalArgumentException("User not found");
            }

            Element invUserSymbol = userInfo.userSymbol.invert();

            if (ciphertext.policy1.contains(token.realAccount)) {
                Element[] processedC2 = new Element[n + 1];
                for (int i = 0; i <= n; i++) {
                    processedC2[i] = ciphertext.c2[i].duplicate()
                        .mulZn(invUserSymbol)
                        .getImmutable();
                }
                return new ProcessedParameters(processedC2, ciphertext.c3);

            } else if (ciphertext.policy2.contains(token.realAccount)) {
                Element[] processedC5 = new Element[n + 1];
                for (int i = 0; i <= n; i++) {
                    processedC5[i] = ciphertext.c5[i].duplicate()
                        .mulZn(invUserSymbol)
                        .getImmutable();
                }
                return new ProcessedParameters(processedC5, ciphertext.c6);

            } else if (ciphertext.policy3.contains(token.realAccount)) {
                Element[] processedC8 = new Element[n + 1];
                for (int i = 0; i <= n; i++) {
                    processedC8[i] = ciphertext.c8[i].duplicate()
                        .mulZn(invUserSymbol)
                        .getImmutable();
                }
                return new ProcessedParameters(processedC8, ciphertext.c9);

            } else if (ciphertext.policy4.contains(token.realAccount)) {
                Element[] processedC11 = new Element[n + 1];
                for (int i = 0; i <= n; i++) {
                    processedC11[i] = ciphertext.c11[i].duplicate()
                        .mulZn(invUserSymbol)
                        .getImmutable();
                }
                return new ProcessedParameters(processedC11, ciphertext.c12, ciphertext.c10);
            }
            System.err.println("User " + token.realAccount + " is not in any policy set");
            return null;
        } catch (Exception e) {
            System.err.println("Error in Check: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public MacHEPQC(HEKeyPair heKeyPair) {
        this.userList = new HashMap<>();
        this.heKeyPair = heKeyPair;
    }

    public byte[] Query(String tokenType, byte[] encryptedModel, byte[] encryptedData, int dataCount) {
        try {
            byte[] result = null;
            
            switch (tokenType) {
                case "Partially":
                    for (int i = 0; i < dataCount; i++) {
                        result = heKeyPair.paillier.homomorphicOperation(
                            new BigInteger(1, encryptedModel),
                            new BigInteger(1, encryptedData)
                        ).toByteArray();
                    }
                    break;
                case "Somewhat":
                    for (int i = 0; i < dataCount; i++) {
                        result = heKeyPair.bfv.homomorphicOperation(
                            encryptedModel,
                            encryptedData
                        );
                    }
                    break;
                case "Fully":
                    for (int i = 0; i < dataCount; i++) {
                        result = heKeyPair.ckks.homomorphicOperation(
                            encryptedModel,
                            encryptedData
                        );
                    }
                    break;
                case "complicated":
                    for (int i = 0; i < dataCount; i++) {
                        result = heKeyPair.aes.homomorphicOperation(
                                encryptedModel,
                                encryptedData
                        );
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Invalid token type: " + tokenType);
            }
            return result;
            
        } catch (Exception e) {
            System.err.println("Error in Query: " + e.getMessage());
            e.printStackTrace();
            return new byte[0];
        }
    }
}

