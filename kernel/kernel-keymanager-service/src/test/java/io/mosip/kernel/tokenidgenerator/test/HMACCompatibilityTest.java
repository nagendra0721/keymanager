package io.mosip.kernel.tokenidgenerator.test;

import io.mosip.kernel.core.util.HMACUtils;
import io.mosip.kernel.core.util.HMACUtils2;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * Verifies that HMACUtils (old) and HMACUtils2 (new) produce the same hash
 * for the same input, confirming the TokenIDGenerator migration is correct.
 *
 * HMACUtils  : caller must pre-hash → digestAsPlainText(generateHash(input))
 * HMACUtils2 : hashes internally   → digestAsPlainText(input)
 */
public class HMACCompatibilityTest {

    private static final String UIN           = "9876543210";
    private static final String UIN_SALT      = "testUinSalt";
    private static final String PARTNER_CODE  = "PARTNER001";
    private static final String PARTNER_SALT  = "testPartnerSalt";

    @Test
    public void testHMACUtils1AndHMACUtils2ProduceSameHash() throws Exception {

        // --- HMACUtils (old pattern) ---
        String uinHashOld = HMACUtils.digestAsPlainText(
                HMACUtils.generateHash((UIN + UIN_SALT).getBytes(StandardCharsets.UTF_8)));
        String hashOld = HMACUtils.digestAsPlainText(
                HMACUtils.generateHash((PARTNER_SALT + PARTNER_CODE + uinHashOld).getBytes(StandardCharsets.UTF_8)));

        // --- HMACUtils2 (new pattern) ---
        String uinHashNew = HMACUtils2.digestAsPlainText(
                (UIN + UIN_SALT).getBytes(StandardCharsets.UTF_8));
        String hashNew = HMACUtils2.digestAsPlainText(
                (PARTNER_SALT + PARTNER_CODE + uinHashNew).getBytes(StandardCharsets.UTF_8));

        // Print both for visual verification
        System.out.println("=== HMACUtils (old) ===");
        System.out.println("uinHash : " + uinHashOld);
        System.out.println("hash    : " + hashOld);

        System.out.println("=== HMACUtils2 (new) ===");
        System.out.println("uinHash : " + uinHashNew);
        System.out.println("hash    : " + hashNew);

        System.out.println("=== Match? ===");
        System.out.println("uinHash match : " + uinHashOld.equals(uinHashNew));
        System.out.println("hash match    : " + hashOld.equals(hashNew));

        // Assert both produce identical results
        Assert.assertEquals("uinHash mismatch between HMACUtils and HMACUtils2", uinHashOld, uinHashNew);
        Assert.assertEquals("final hash mismatch between HMACUtils and HMACUtils2", hashOld, hashNew);
    }
}