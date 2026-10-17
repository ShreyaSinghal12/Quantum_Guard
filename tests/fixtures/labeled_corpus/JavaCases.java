class JavaCases {
    void run() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Signature s = Signature.getInstance("SHA256withECDSA");
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        // KeyPairGenerator.getInstance("RSA") in a comment
        String algo = "RSA";
        KeyPairGenerator dyn = KeyPairGenerator.getInstance(algo);
    }
}
