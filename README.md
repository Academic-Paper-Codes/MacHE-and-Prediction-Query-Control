# MacHE-and-Prediction-Query-Control

This repository contains the Java implementation of MacHE (Multi-Account Homomorphic Encryption) schemes and their applications in AI prediction query control systems. The codebase implements four core components: basic MacHE, privacy-preserving MacHE\*, and their respective prediction query control extensions (MacHE-PQC and MacHE\* -PQC). 

## Project Structure

### MacHE.java
The core implementation of the basic MacHE scheme that enables data owners to generate ciphertexts for multiple targeted accounts. This file contains the fundamental algorithms for multi-account homomorphic encryption.

**Key Functions:**

- `Setup(int lambda, int accountNum)` - Initializes system parameters with security parameter λ and maximum account number
- `KeyGen(Element[] msk, String userId)` - Generates secret keys for users with virtual account mapping
- `Encrypt(List<String> policy, HEKeyPair heKeyPair, byte[] message)` - Creates encrypted data with access control policies using polynomial functions
- `TokenGen(String userId)` - Generates access tokens for users
- `Check(Ciphertext ciphertext, Token token)` - Verifies user permissions and processes ciphertext parameters
- `Request(ProcessedParameters params, Element[] secretKey, byte[] message2)` - Allows authorized users to encrypt additional data
- `Evaluate(HEKeyPair heKeyPair, byte[] c1, byte[] c2)` - Performs homomorphic operations on encrypted data
- `Decrypt(HEKeyPair heKeyPair, byte[] encryptedResult)` - Decrypts evaluation results

### MacHE-Star.java
Implementation of MacHE* that extends MacHE with account privacy preservation. This variant hides targeted accounts in polynomial coefficients to prevent attackers from inferring which accounts are authorized.

**Key Functions:**
- `Setup(int lambda, int accountNum)` - System initialization with enhanced privacy parameters
- `KeyGen(Element[] msk, String userId)` - User key generation with privacy-preserving mechanisms
- `Encrypt(List<String> policy, HEKeyPair heKeyPair, byte[] message)` - Privacy-preserving encryption with hidden access policies
- `TokenGen(String userId, Element[] msk)` - Generates encrypted access tokens to hide user identity
- `Check(Ciphertext ciphertext, Token token)` - Privacy-preserving access control verification using bilinear pairing equations
- `Request(ProcessedParameters params, Element[] secretKey, byte[] message, HEKeyPair heKeyPair)` - Secure data request processing
- `Evaluate(HEKeyPair heKeyPair, byte[] c1, byte[] c2)` - Homomorphic evaluation operations
- `Decrypt(HEKeyPair heKeyPair, byte[] ciphertext)` - Result decryption

### MacHE-PQC.java
MacHE-based Prediction Query Control system that enables different accounts to have different AI model access rights. Implements downward compatible permissions where higher-privilege users can access lower-level models.

**Key Functions:**
- `Setup(int lambda, int attrNum)` - Initializes PQC system with multiple encryption schemes
- `KeyGen(Element[] msk, String userId)` - Generates keys for users with attribute-based access
- `Encrypt(String[] attrs, HEKeyPair hePair, byte[] message)` - Multi-level encryption supporting four different access levels
- `TokenGen(String userId, String tokenType)` - Creates typed tokens for different prediction query levels
- `Check(Ciphertext ciphertext, Token token)` - Validates access rights for specific prediction query types
- `Query(String tokenType, byte[] encryptedModel, byte[] encryptedData, int dataCount)` - Executes AI prediction queries based on user permissions

**Supported Models:**

- **Partially HE**: Such as Paillier encryption for basic homomorphic operations
- **Somewhat HE**: Such as BFV encryption for moderate complexity computations
- **Fully HE**: Such as CKKS encryption for complex AI model inference
- **Complicated**: Such as AES-based symmetric encryption for high-performance scenarios

### MacHE-Star-PQC.java
The privacy-preserving version of MacHE-PQC that combines account privacy protection with prediction query control. Provides the highest level of security by hiding both user identities and access patterns.

**Key Functions:**
- `Setup(int lambda, int attrNum)` - System setup with privacy-preserving PQC parameters
- `KeyGen(Element[] msk, String userId)` - Privacy-aware user key generation
- `Encrypt(String[] attrs, HEKeyPair hePair, byte[] message)` - Multi-level encryption with hidden access policies
- `TokenGen(String userId, String tokenType)` - Generates encrypted tokens that hide user identity and query type
- `Check(Ciphertext ciphertext, Token token)` - Privacy-preserving verification using zero-knowledge-like proofs
- Advanced polynomial-based access control with account privacy preservation

**Supported Models:**
- **Partially HE**: Such as Paillier encryption for basic homomorphic operations
- **Somewhat HE**: Such as BFV encryption for moderate complexity computations
- **Fully HE**: Such as CKKS encryption for complex AI model inference
- **Complicated**: Such as AES-based symmetric encryption for high-performance scenarios
- Support for complex AI model inference with privacy guarantees

## Dependencies

- **JPBC Library**: Java Pairing-Based Cryptography library for bilinear pairing operations
- **Java 8+**: Required for proper execution

## Installation

1. Clone this repository:
```bash
git clone https://github.com/Academic-Paper-Codes/MacHE-and-Prediction-Query-Control.git
cd MacHE-and-Prediction-Query-Control
```

2. Ensure JPBC library is properly configured in your Java project
3. Configure the `a.properties` file for pairing parameters

## Contribution

If you want to contribute code to this project, please follow these steps:

1. Fork this repository
2. Create your feature branch (`git checkout -b feature-branch`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature-branch`)
5. Create a Pull Request

## Contact

For questions or support, please open an issue in this repository or contact the authors.
