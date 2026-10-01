import com.android.apksig.ApkSigner;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;

public class KeepV1Signer {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("usage: input output key_pk8_der cert_der");
            System.exit(1);
        }
        Path input = Paths.get(args[0]);
        Path output = Paths.get(args[1]);

        byte[] pk8 = Files.readAllBytes(Paths.get(args[2]));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pk8));

        byte[] certDer = Files.readAllBytes(Paths.get(args[3]));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

        ApkSigner.SignerConfig signerConfig =
                new ApkSigner.SignerConfig.Builder("signer", priv,
                        Collections.singletonList(cert)).build();

        new ApkSigner.Builder(Collections.singletonList(signerConfig))
                .setInputApk(input.toFile())
                .setOutputApk(output.toFile())
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setOtherSignersSignaturesPreserved(true)
                .build()
                .sign();

        System.out.println("KEEP_V1_SIGN_OK");
    }
}
