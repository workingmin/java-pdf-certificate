package com.example.pdf.certificate;

import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONValue;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.Banner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;

@SpringBootApplication
public class PDFCertificateApplication implements CommandLineRunner {

	@Value("${pdf}")
	private String pdf;

	public static void main(String[] args) {
		SpringApplication application = new SpringApplication(PDFCertificateApplication.class);
		application.setBannerMode(Banner.Mode.OFF);
		application.run(args);
	}

	@Override
	public void run(String... args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		PdfReader reader = new PdfReader(new FileInputStream(pdf));
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
		if(names.size() == 0) {
			System.out.println("no signature");
			return;
		}

		ArrayList<HashMap<String, Object>> a = new ArrayList<>();
		for (String name : names) {
			PdfPKCS7 pkcs7 = fields.verifySignature(name, "BC");
			X509Certificate certificate = pkcs7.getSigningCertificate();

			HashMap<String, Object> m = new HashMap<String, Object>();

			m.put("digest-algorithm", pkcs7.getDigestAlgorithm());
			m.put("digest-algorithm-id", pkcs7.getDigestAlgorithmOid());
			m.put("digest-encryption-algorithm-id", pkcs7.getDigestEncryptionAlgorithmOid());
			m.put("encryption-algorithm", pkcs7.getEncryptionAlgorithm());
			m.put("hash-algorithm", pkcs7.getHashAlgorithm());
			m.put("location", pkcs7.getLocation());
			m.put("reason", pkcs7.getReason());
			m.put("sign-date", new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(pkcs7.getSignDate().getTime()));
			m.put("sign-name", pkcs7.getSignName());
			m.put("timestamp-date", new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(pkcs7.getTimeStampDate().getTime()));
			m.put("version", certificate.getVersion());
			m.put("serial-number", certificate.getSerialNumber());
			m.put("issuer-dn", certificate.getIssuerDN().getName());
			m.put("start-date", new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(certificate.getNotBefore()));
			m.put("final-date", new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(certificate.getNotAfter()));
			m.put("subject-dn", certificate.getSubjectDN().getName());
			m.put("public-key", certificate.getPublicKey().getFormat());
			m.put("signature-algorithm", certificate.getSigAlgName());

			a.add(m);
		}
		String s = JSONValue.toJSONString(a);
		System.out.println(s);
	}
}
