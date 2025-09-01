import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.concurrent.*;

public class CryptoAdvanced {
    private static final String[] SYMMETRIC_ALGORITHMS = {
        "AES", "DES", "DESede", "Blowfish", "RC4", "ChaCha20"
    };
    
    private static final String[] HASH_ALGORITHMS = {
        "MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512"
    };
    
    private static final String[] ASYMMETRIC_ALGORITHMS = {
        "RSA", "DSA", "EC", "DH"
    };
    
    private static final int[] KEY_SIZES = {128, 192, 256, 512, 1024, 2048, 4096};
    
    private final Map<String, Object> results = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(8);
    
    public static void main(String[] args) {
        CryptoAdvanced crypto = new CryptoAdvanced();
        
        if (args.length == 0) {
            crypto.showUsage();
            return;
        }
        
        try {
            switch (args[0].toLowerCase()) {
                case "encrypt":
                    if (args.length < 5) {
                        System.out.println("Usage: java CryptoAdvanced encrypt <algorithm> <mode> <key> <input> <output>");
                        return;
                    }
                    crypto.encrypt(args[1], args[2], args[3], args[4], args.length > 5 ? args[5] : "output.enc");
                    break;
                    
                case "decrypt":
                    if (args.length < 5) {
                        System.out.println("Usage: java CryptoAdvanced decrypt <algorithm> <mode> <key> <input> <output>");
                        return;
                    }
                    crypto.decrypt(args[1], args[2], args[3], args[4], args.length > 5 ? args[5] : "output.dec");
                    break;
                    
                case "hash":
                    if (args.length < 3) {
                        System.out.println("Usage: java CryptoAdvanced hash <algorithm> <input>");
                        return;
                    }
                    crypto.hash(args[1], args[2]);
                    break;
                    
                case "generate":
                    if (args.length < 2) {
                        System.out.println("Usage: java CryptoAdvanced generate <algorithm> [keySize]");
                        return;
                    }
                    int keySize = args.length > 2 ? Integer.parseInt(args[2]) : 256;
                    crypto.generateKey(args[1], keySize);
                    break;
                    
                case "benchmark":
                    crypto.runBenchmarks();
                    break;
                    
                case "analyze":
                    if (args.length < 2) {
                        System.out.println("Usage: java CryptoAdvanced analyze <input>");
                        return;
                    }
                    crypto.analyzeFile(args[1]);
                    break;
                    
                case "crack":
                    if (args.length < 3) {
                        System.out.println("Usage: java CryptoAdvanced crack <hash> <wordlist>");
                        return;
                    }
                    crypto.crackHash(args[1], args[2]);
                    break;
                    
                default:
                    crypto.showUsage();
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            crypto.shutdown();
        }
    }
    
    private void showUsage() {
        System.out.println("XILLEN Advanced Cryptography Tool v1.0");
        System.out.println("=====================================");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  encrypt <algorithm> <mode> <key> <input> [output]  - Encrypt file");
        System.out.println("  decrypt <algorithm> <mode> <key> <input> [output]  - Decrypt file");
        System.out.println("  hash <algorithm> <input>                          - Calculate hash");
        System.out.println("  generate <algorithm> [keySize]                    - Generate key");
        System.out.println("  benchmark                                         - Run performance tests");
        System.out.println("  analyze <input>                                   - Analyze file entropy");
        System.out.println("  crack <hash> <wordlist>                          - Crack hash");
        System.out.println();
        System.out.println("Algorithms:");
        System.out.println("  Symmetric: " + String.join(", ", SYMMETRIC_ALGORITHMS));
        System.out.println("  Hash: " + String.join(", ", HASH_ALGORITHMS));
        System.out.println("  Asymmetric: " + String.join(", ", ASYMMETRIC_ALGORITHMS));
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java CryptoAdvanced encrypt AES CBC mykey123 input.txt output.enc");
        System.out.println("  java CryptoAdvanced hash SHA-256 input.txt");
        System.out.println("  java CryptoAdvanced generate RSA 2048");
        System.out.println("  java CryptoAdvanced benchmark");
    }
    
    public void encrypt(String algorithm, String mode, String key, String inputFile, String outputFile) throws Exception {
        System.out.println("Encrypting " + inputFile + " using " + algorithm + "/" + mode + "...");
        
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] inputData = readFile(inputFile);
        
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, algorithm);
        
        if (mode.equals("ECB")) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } else {
            byte[] iv = generateIV(cipher.getBlockSize());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            
            byte[] encrypted = cipher.doFinal(inputData);
            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
            
            writeFile(outputFile, result);
            System.out.println("Encryption completed. Output: " + outputFile);
            return;
        }
        
        byte[] encrypted = cipher.doFinal(inputData);
        writeFile(outputFile, encrypted);
        System.out.println("Encryption completed. Output: " + outputFile);
    }
    
    public void decrypt(String algorithm, String mode, String key, String inputFile, String outputFile) throws Exception {
        System.out.println("Decrypting " + inputFile + " using " + algorithm + "/" + mode + "...");
        
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] inputData = readFile(inputFile);
        
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, algorithm);
        
        if (mode.equals("ECB")) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decrypted = cipher.doFinal(inputData);
            writeFile(outputFile, decrypted);
        } else {
            int blockSize = cipher.getBlockSize();
            byte[] iv = Arrays.copyOfRange(inputData, 0, blockSize);
            byte[] encrypted = Arrays.copyOfRange(inputData, blockSize, inputData.length);
            
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            
            byte[] decrypted = cipher.doFinal(encrypted);
            writeFile(outputFile, decrypted);
        }
        
        System.out.println("Decryption completed. Output: " + outputFile);
    }
    
    public void hash(String algorithm, String inputFile) throws Exception {
        System.out.println("Calculating " + algorithm + " hash for " + inputFile + "...");
        
        byte[] inputData = readFile(inputFile);
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hash = digest.digest(inputData);
        
        String hexHash = bytesToHex(hash);
        System.out.println(algorithm + " hash: " + hexHash);
        
        results.put("hash_" + algorithm, hexHash);
    }
    
    public void generateKey(String algorithm, int keySize) throws Exception {
        System.out.println("Generating " + algorithm + " key with size " + keySize + "...");
        
        if (algorithm.equals("RSA") || algorithm.equals("DSA")) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
            keyGen.initialize(keySize);
            KeyPair pair = keyGen.generateKeyPair();
            
            System.out.println("Public key: " + bytesToHex(pair.getPublic().getEncoded()));
            System.out.println("Private key: " + bytesToHex(pair.getPrivate().getEncoded()));
            
            results.put("public_key", pair.getPublic().getEncoded());
            results.put("private_key", pair.getPrivate().getEncoded());
            
        } else if (algorithm.equals("AES") || algorithm.equals("DES") || algorithm.equals("Blowfish")) {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(keySize);
            SecretKey key = keyGen.generateKey();
            
            System.out.println("Generated key: " + bytesToHex(key.getEncoded()));
            results.put("symmetric_key", key.getEncoded());
            
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }
    
    public void runBenchmarks() throws Exception {
        System.out.println("Running cryptography benchmarks...");
        System.out.println("==================================");
        
        Map<String, Long> benchmarks = new HashMap<>();
        
        for (String algorithm : SYMMETRIC_ALGORITHMS) {
            if (algorithm.equals("ChaCha20")) continue;
            
            try {
                long startTime = System.currentTimeMillis();
                benchmarkSymmetric(algorithm);
                long endTime = System.currentTimeMillis();
                benchmarks.put(algorithm, endTime - startTime);
            } catch (Exception e) {
                System.out.println("Failed to benchmark " + algorithm + ": " + e.getMessage());
            }
        }
        
        for (String algorithm : HASH_ALGORITHMS) {
            try {
                long startTime = System.currentTimeMillis();
                benchmarkHash(algorithm);
                long endTime = System.currentTimeMillis();
                benchmarks.put("hash_" + algorithm, endTime - startTime);
            } catch (Exception e) {
                System.out.println("Failed to benchmark hash " + algorithm + ": " + e.getMessage());
            }
        }
        
        System.out.println("\nBenchmark Results:");
        System.out.println("==================");
        benchmarks.entrySet().stream()
            .sorted(Map.Entry.comparingByValue())
            .forEach(entry -> System.out.printf("%-20s: %d ms%n", entry.getKey(), entry.getValue()));
    }
    
    private void benchmarkSymmetric(String algorithm) throws Exception {
        byte[] testData = new byte[1024 * 1024];
        new Random().nextBytes(testData);
        
        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        for (int i = 0; i < 100; i++) {
            cipher.doFinal(testData);
        }
    }
    
    private void benchmarkHash(String algorithm) throws Exception {
        byte[] testData = new byte[1024 * 1024];
        new Random().nextBytes(testData);
        
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        
        for (int i = 0; i < 1000; i++) {
            digest.digest(testData);
        }
    }
    
    public void analyzeFile(String inputFile) throws Exception {
        System.out.println("Analyzing file: " + inputFile);
        System.out.println("========================");
        
        byte[] data = readFile(inputFile);
        
        System.out.println("File size: " + data.length + " bytes");
        System.out.println("Entropy: " + String.format("%.4f", calculateEntropy(data)));
        System.out.println("Compression ratio: " + String.format("%.2f", calculateCompressionRatio(data)));
        
        Map<Byte, Integer> byteFrequency = calculateByteFrequency(data);
        System.out.println("Most common bytes:");
        byteFrequency.entrySet().stream()
            .sorted(Map.Entry.<Byte, Integer>comparingByValue().reversed())
            .limit(10)
            .forEach(entry -> System.out.printf("  0x%02X: %d times%n", entry.getKey(), entry.getValue()));
        
        results.put("file_analysis", Map.of(
            "size", data.length,
            "entropy", calculateEntropy(data),
            "compression_ratio", calculateCompressionRatio(data)
        ));
    }
    
    public void crackHash(String hash, String wordlistFile) throws Exception {
        System.out.println("Attempting to crack hash: " + hash);
        System.out.println("Using wordlist: " + wordlistFile);
        System.out.println("=====================================");
        
        if (!wordlistFile.endsWith(".txt")) {
            throw new IllegalArgumentException("Wordlist must be a .txt file");
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(wordlistFile))) {
            String line;
            int attempts = 0;
            
            while ((line = reader.readLine()) != null) {
                attempts++;
                
                if (attempts % 10000 == 0) {
                    System.out.println("Tried " + attempts + " passwords...");
                }
                
                String[] algorithms = {"MD5", "SHA-1", "SHA-256"};
                for (String algorithm : algorithms) {
                    try {
                        MessageDigest digest = MessageDigest.getInstance(algorithm);
                        byte[] testHash = digest.digest(line.getBytes(StandardCharsets.UTF_8));
                        String testHashHex = bytesToHex(testHash);
                        
                        if (testHashHex.equalsIgnoreCase(hash)) {
                            System.out.println("Hash cracked!");
                            System.out.println("Algorithm: " + algorithm);
                            System.out.println("Password: " + line);
                            System.out.println("Attempts: " + attempts);
                            return;
                        }
                    } catch (Exception e) {
                        continue;
                    }
                }
            }
            
            System.out.println("Hash not found in wordlist after " + attempts + " attempts.");
            
        } catch (FileNotFoundException e) {
            System.err.println("Wordlist file not found: " + wordlistFile);
        }
    }
    
    private double calculateEntropy(byte[] data) {
        Map<Byte, Integer> frequency = calculateByteFrequency(data);
        double entropy = 0.0;
        int length = data.length;
        
        for (int count : frequency.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        
        return entropy;
    }
    
    private double calculateCompressionRatio(byte[] data) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
                gzip.write(data);
            }
            
            byte[] compressed = baos.toByteArray();
            return (double) compressed.length / data.length;
            
        } catch (IOException e) {
            return 1.0;
        }
    }
    
    private Map<Byte, Integer> calculateByteFrequency(byte[] data) {
        Map<Byte, Integer> frequency = new HashMap<>();
        
        for (byte b : data) {
            frequency.merge(b, 1, Integer::sum);
        }
        
        return frequency;
    }
    
    private byte[] generateIV(int blockSize) {
        byte[] iv = new byte[blockSize];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    private byte[] readFile(String filename) throws IOException {
        try (FileInputStream fis = new FileInputStream(filename)) {
            return fis.readAllBytes();
        }
    }
    
    private void writeFile(String filename, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }
}
