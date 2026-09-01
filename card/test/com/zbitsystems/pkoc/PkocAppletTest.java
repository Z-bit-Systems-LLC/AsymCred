/*
 * PKOC Applet Tests — validates the full SELECT → AUTHENTICATE flow
 * against the PSIA PKOC NFC Card 1.1 specification.
 *
 * Runs on jCardSim (no physical hardware required).
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Z-bit Systems, LLC
 */
package com.zbitsystems.pkoc;

import com.licel.jcardsim.base.Simulator;

import javacard.framework.AID;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class PkocAppletTest {

    private static final byte[] PKOC_AID = {
        (byte) 0xA0, 0x00, 0x00, 0x08, (byte) 0x98, 0x00, 0x00, 0x01
    };

    private static final byte[] SELECT_PKOC = {
        0x00, (byte) 0xA4, 0x04, 0x00, 0x08,
        (byte) 0xA0, 0x00, 0x00, 0x08, (byte) 0x98, 0x00, 0x00, 0x01,
        0x00
    };

    private Simulator simulator;

    @Before
    public void setUp() {
        simulator = new Simulator();
        AID appletAid = new AID(PKOC_AID, (short) 0, (byte) PKOC_AID.length);
        simulator.installApplet(appletAid, PkocApplet.class);
        simulator.selectApplet(appletAid);
    }

    @Test
    public void testSelectReturnsProtocolVersion() {
        byte[] response = simulator.transmitCommand(SELECT_PKOC);

        // Last two bytes should be SW 90 00
        assertEquals("SW1 should be 0x90", (byte) 0x90, response[response.length - 2]);
        assertEquals("SW2 should be 0x00", (byte) 0x00, response[response.length - 1]);

        // Response data (excluding SW): 5C 02 01 01
        assertTrue("Response should have at least 6 bytes (4 data + 2 SW)", response.length >= 6);
        assertEquals("Tag should be 0x5C", (byte) 0x5C, response[0]);
        assertEquals("Length should be 0x02", (byte) 0x02, response[1]);
        assertEquals("Major version should be 0x01", (byte) 0x01, response[2]);
        assertEquals("Minor version should be 0x01", (byte) 0x01, response[3]);
    }

    @Test
    public void testAuthenticateReturnsPublicKeyAndSignature() {
        // First SELECT to get protocol version
        byte[] selectResp = simulator.transmitCommand(SELECT_PKOC);
        assertSW9000(selectResp);

        // Build and send AUTHENTICATE
        byte[] authCmd = buildAuthenticateApdu(randomTransactionId());
        byte[] response = simulator.transmitCommand(authCmd);
        assertSW9000(response);

        // Data length = response.length - 2 (SW)
        int dataLen = response.length - 2;

        // Parse public key TLV: 5A 41 [65 bytes]
        assertEquals("First tag should be 0x5A (public key)", (byte) 0x5A, response[0]);
        assertEquals("Public key length should be 0x41 (65)", (byte) 0x41, response[1]);
        assertEquals("Public key should start with 0x04 (uncompressed)", (byte) 0x04, response[2]);

        // Parse signature TLV: 9E 40 [64 bytes]
        assertEquals("Second tag should be 0x9E (signature)", (byte) 0x9E, response[67]);
        assertEquals("Signature length should be 0x40 (64)", (byte) 0x40, response[68]);

        // Total data: 2 + 65 + 2 + 64 = 133 bytes
        assertEquals("Response data should be 133 bytes", 133, dataLen);
    }

    @Test
    public void testSignatureIsVerifiable() throws Exception {
        // SELECT
        byte[] selectResp = simulator.transmitCommand(SELECT_PKOC);
        assertSW9000(selectResp);

        // AUTHENTICATE with known transaction ID
        byte[] transactionId = new byte[16];
        for (int i = 0; i < 16; i++) {
            transactionId[i] = (byte) (i + 1);
        }

        byte[] authCmd = buildAuthenticateApdu(transactionId);
        byte[] response = simulator.transmitCommand(authCmd);
        assertSW9000(response);

        // Extract public key (65 bytes at offset 2)
        byte[] publicKeyBytes = new byte[65];
        System.arraycopy(response, 2, publicKeyBytes, 0, 65);

        // Extract raw signature (64 bytes at offset 69)
        byte[] rawSignature = new byte[64];
        System.arraycopy(response, 69, rawSignature, 0, 64);

        // Convert raw R||S to DER for Java verification
        byte[] derSignature = rawRSToDer(rawSignature);

        // Reconstruct the EC public key
        ECPublicKey ecPubKey = reconstructPublicKey(publicKeyBytes);

        // Verify signature over the transaction ID
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(ecPubKey);
        verifier.update(transactionId);
        assertTrue("Signature should verify against transaction ID", verifier.verify(derSignature));
    }

    @Test
    public void testConsistentPublicKeyAcrossAuthentications() {
        simulator.transmitCommand(SELECT_PKOC);

        // First AUTHENTICATE
        byte[] resp1 = simulator.transmitCommand(buildAuthenticateApdu(randomTransactionId()));
        assertSW9000(resp1);

        byte[] pubKey1 = new byte[65];
        System.arraycopy(resp1, 2, pubKey1, 0, 65);

        // Second AUTHENTICATE
        byte[] resp2 = simulator.transmitCommand(buildAuthenticateApdu(randomTransactionId()));
        assertSW9000(resp2);

        byte[] pubKey2 = new byte[65];
        System.arraycopy(resp2, 2, pubKey2, 0, 65);

        assertArrayEquals("Public key should be consistent across authentications", pubKey1, pubKey2);
    }

    @Test
    public void testDifferentSignaturesForDifferentTransactions() {
        simulator.transmitCommand(SELECT_PKOC);

        byte[] txId1 = new byte[16];
        txId1[0] = 0x01;
        byte[] txId2 = new byte[16];
        txId2[0] = 0x02;

        byte[] resp1 = simulator.transmitCommand(buildAuthenticateApdu(txId1));
        byte[] resp2 = simulator.transmitCommand(buildAuthenticateApdu(txId2));

        assertSW9000(resp1);
        assertSW9000(resp2);

        byte[] sig1 = new byte[64];
        byte[] sig2 = new byte[64];
        System.arraycopy(resp1, 69, sig1, 0, 64);
        System.arraycopy(resp2, 69, sig2, 0, 64);

        boolean sigsDiffer = false;
        for (int i = 0; i < 64; i++) {
            if (sig1[i] != sig2[i]) {
                sigsDiffer = true;
                break;
            }
        }
        assertTrue("Different transaction IDs should produce different signatures", sigsDiffer);
    }

    @Test
    public void testUnsupportedInstructionReturnsError() {
        byte[] badCmd = {(byte) 0x80, (byte) 0xFF, 0x00, 0x00};
        byte[] response = simulator.transmitCommand(badCmd);

        // SW should be 6D00 (INS not supported)
        int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        assertEquals("Unsupported INS should return 6D00", 0x6D00, sw);
    }

    @Test
    public void testAuthenticateWithTruncatedDataReturnsError() {
        // Send AUTHENTICATE with only 10 bytes of data (too short)
        byte[] shortData = new byte[10];
        byte[] cmd = new byte[5 + shortData.length + 1];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0x80;
        cmd[2] = 0x00;
        cmd[3] = 0x01;
        cmd[4] = (byte) shortData.length;
        System.arraycopy(shortData, 0, cmd, 5, shortData.length);
        cmd[cmd.length - 1] = 0x00;

        byte[] response = simulator.transmitCommand(cmd);
        int sw = getSW(response);
        assertNotEquals("Truncated data should not return 9000", 0x9000, sw);
    }

    @Test
    public void testAuthenticateMissingTransactionIdReturnsError() {
        // Build data with only protocol version and reader ID (no 0x4C tag)
        byte[] data = new byte[56];
        int pos = 0;

        // Skip transaction ID, start with protocol version
        data[pos++] = 0x5C;
        data[pos++] = 0x02;
        data[pos++] = 0x01;
        data[pos++] = 0x01;

        // Reader ID
        data[pos++] = 0x4D;
        data[pos++] = 0x20;
        // 32 zero bytes already there

        byte[] cmd = new byte[5 + data.length + 1];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0x80;
        cmd[2] = 0x00;
        cmd[3] = 0x01;
        cmd[4] = (byte) data.length;
        System.arraycopy(data, 0, cmd, 5, data.length);
        cmd[cmd.length - 1] = 0x00;

        byte[] response = simulator.transmitCommand(cmd);
        int sw = getSW(response);
        assertNotEquals("Missing transaction ID should not return 9000", 0x9000, sw);
    }

    // --- Helper methods ---

    private byte[] randomTransactionId() {
        byte[] txId = new byte[16];
        new java.security.SecureRandom().nextBytes(txId);
        return txId;
    }

    private byte[] buildAuthenticateApdu(byte[] transactionId) {
        byte[] data = new byte[56]; // 0x38
        int pos = 0;

        // Transaction ID: 4C 10 [16 bytes]
        data[pos++] = 0x4C;
        data[pos++] = 0x10;
        System.arraycopy(transactionId, 0, data, pos, 16);
        pos += 16;

        // Protocol Version: 5C 02 01 01
        data[pos++] = 0x5C;
        data[pos++] = 0x02;
        data[pos++] = 0x01;
        data[pos++] = 0x01;

        // Reader Identifier: 4D 20 [32 zero bytes]
        data[pos++] = 0x4D;
        data[pos++] = 0x20;
        // Remaining 32 bytes are already zeros

        // Build full APDU: 80 80 00 01 38 [data] 00
        byte[] apdu = new byte[5 + data.length + 1];
        apdu[0] = (byte) 0x80; // CLA
        apdu[1] = (byte) 0x80; // INS AUTHENTICATE
        apdu[2] = 0x00;        // P1
        apdu[3] = 0x01;        // P2
        apdu[4] = (byte) data.length; // Lc
        System.arraycopy(data, 0, apdu, 5, data.length);
        apdu[apdu.length - 1] = 0x00; // Le

        return apdu;
    }

    private void assertSW9000(byte[] response) {
        assertEquals("SW should be 9000", 0x9000, getSW(response));
    }

    private int getSW(byte[] response) {
        return ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
    }

    private ECPublicKey reconstructPublicKey(byte[] uncompressedPoint) throws Exception {
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(uncompressedPoint, 1, x, 0, 32);
        System.arraycopy(uncompressedPoint, 33, y, 0, 32);

        ECPoint point = new ECPoint(
            new java.math.BigInteger(1, x),
            new java.math.BigInteger(1, y)
        );

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(pubSpec);
    }

    /**
     * Convert raw R||S (64 bytes) to DER-encoded ECDSA signature for Java verification.
     */
    private byte[] rawRSToDer(byte[] rawRS) {
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(rawRS, 0, r, 0, 32);
        System.arraycopy(rawRS, 32, s, 0, 32);

        byte[] derR = integerToDer(r);
        byte[] derS = integerToDer(s);

        int seqLen = derR.length + derS.length;
        byte[] der = new byte[2 + seqLen];
        der[0] = 0x30;
        der[1] = (byte) seqLen;
        System.arraycopy(derR, 0, der, 2, derR.length);
        System.arraycopy(derS, 0, der, 2 + derR.length, derS.length);

        return der;
    }

    private byte[] integerToDer(byte[] value) {
        boolean needsPad = (value[0] & 0x80) != 0;
        int len = needsPad ? value.length + 1 : value.length;

        byte[] result = new byte[2 + len];
        result[0] = 0x02;
        result[1] = (byte) len;

        if (needsPad) {
            result[2] = 0x00;
            System.arraycopy(value, 0, result, 3, value.length);
        } else {
            System.arraycopy(value, 0, result, 2, value.length);
        }

        return result;
    }
}
