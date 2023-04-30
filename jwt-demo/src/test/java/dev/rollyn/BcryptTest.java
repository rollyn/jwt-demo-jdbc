package dev.rollyn;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class BcryptTest {

    @Test
    public void generateBcrypt() {
        String password = "password";
        char[] bcryptChars = BCrypt.withDefaults().hashToChar(12, password.toCharArray());
        System.out.println(bcryptChars);
        BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), bcryptChars);
        System.out.println("Verified: "+result.verified);

    }

    @Test
    public void randomCredential() {
        int length = 20;
        boolean useLetters = true;
        boolean useNumbers = true;
        String generatedString = RandomStringUtils.random(length, useLetters, useNumbers);

        System.out.println(generatedString);
    }

    @Test
    public void randomBase64Credential() {
        Random random = ThreadLocalRandom.current();
        byte[] r = new byte[30]; //Means 2048 bit
        random.nextBytes(r);
        String s = Base64.encodeBase64String(r);
        System.out.println(s);
    }
}
