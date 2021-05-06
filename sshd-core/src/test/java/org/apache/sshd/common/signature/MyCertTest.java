package org.apache.sshd.common.signature;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

public class MyCertTest {

  @Test
  public void test() throws Exception {


    final File certFile = new File("/Users/alec.stewart/personal/repos/docker-sshd-testing/keys/user/user01_rsa_2048-cert.pub");
    final File pubKeyFile = new File("/Users/alec.stewart/personal/repos/docker-sshd-testing/keys/user/user01_rsa_2048.pub");

    try (final FileInputStream certInputStream = new FileInputStream(certFile); final FileInputStream pubKeyInputStream = new FileInputStream(pubKeyFile)) {

      final byte[] certBytes = IoUtils.toByteArray(certInputStream);
      final String certLine = GenericUtils.replaceWhitespaceAndTrim(new String(certBytes, StandardCharsets.UTF_8));

      final PublicKeyEntry certPublicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(certLine);
      final PublicKey certPublicKey = certPublicKeyEntry.resolvePublicKey(null, null, null);

      final byte[] pubKeyBytes = IoUtils.toByteArray(pubKeyInputStream);
      final String pubKeyLine = GenericUtils.replaceWhitespaceAndTrim(new String(pubKeyBytes, StandardCharsets.UTF_8));

      final PublicKeyEntry pubKeyPublicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(pubKeyLine);
      final PublicKey pubKeyPublicKey = pubKeyPublicKeyEntry.resolvePublicKey(null, null, null);

      final Path path = new File("/Users/alec.stewart/personal/repos/docker-sshd-testing/keys/user").toPath();

      final FileKeyPairProvider keyPairProvider = new FileKeyPairProvider(path.resolve("user01_rsa_2048"));

      final KeyPair keypair = keyPairProvider.loadKeys(null).iterator().next();

      final PrivateKey privateKey = keypair.getPrivate();

      final SshClient client = SshClient.setUpDefaultClient();



      client.setKeyIdentityProvider(new KeyIdentityProvider() {
        @Override
        public Iterable<KeyPair> loadKeys(SessionContext session) throws IOException, GeneralSecurityException {

          final KeyPair certKeypair = new KeyPair(certPublicKey, privateKey);
          final KeyPair standardKeypair = new KeyPair(pubKeyPublicKey, privateKey);

          final ArrayList<KeyPair> list = new ArrayList<>();
          list.add(certKeypair);
//          list.add(standardKeypair);

          return list;
        }
      });

      client.start();

      try (final ClientSession session = client.connect("user01", "localhost", 2222).verify().getSession()) {
        session.auth().verify(5L, TimeUnit.MINUTES);

        System.out.println("here");

      }


      System.out.println("here");
    }


  }
}
