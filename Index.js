public static void main(String[] args) throws Exception {
//        JCPInit.initProviders(false);
        Security.addProvider(new JCP());
        Security.addProvider(new RevCheck());
        byte[] encoded = Base64.getEncoder().encodeToString("Hello World".getBytes(StandardCharsets.UTF_8)).getBytes();
        byte[] sign = sign(
                "alias", // key alias
                "".toCharArray(), // key password
                encoded // data to be signed
        );

        Encoder encoder = new Encoder();
        System.out.println(encoder.encode((sign)));
    }

    public static byte[] sign(String alias, char[] password, byte[] data) throws Exception {

        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);

        keyStore.load(null, null);

        PrivateKey privateKey = (PrivateKey)
                keyStore.getKey(alias, password);

        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");

        System.setProperty("com.sun.security.enableAIAcaIssuers", "true");
        System.setProperty("ru.CryptoPro.reprov.enableAIAcaIssuers", "true");

        Certificate[] certificates = keyStore
                .getCertificateChain(alias);

        List<X509Certificate> chain =
                new ArrayList<X509Certificate>();
        
        for (Certificate cert : certificates) {
            chain.add((X509Certificate) cert);
        }

        CAdESSignature cAdESSignature = new CAdESSignature(true);

        cAdESSignature.addSigner(
                JCP.PROVIDER_NAME, // signature provider // провайдер подписи
                JCP.GOST_DIGEST_2012_256_OID,
                JCP.GOST_PARAMS_EXC_2012_256_KEY_OID,
                privateKey, // signing key // ключ подписанта
                chain,      // signing certificate chain // цепочка сертификатов подписанта
                CAdESType.CAdES_BES,
                null,
                false,
                null,
                null,
                null, // no CRL files
                true  // add the signing certificate chain to the signature // добавить цепочку подписанта в подпись
        );

        ByteArrayOutputStream signatureStream
                = new ByteArrayOutputStream();

        try (signatureStream) {
            cAdESSignature.open(signatureStream);
            cAdESSignature.update(data);
            cAdESSignature.close();
        }

        return signatureStream.toByteArray();
    }
