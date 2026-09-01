/*
 * PKOC JavaCard Applet
 *
 * Implements the PSIA PKOC NFC Card 1.1 specification:
 *   - SELECT (AID A000000898000001): returns protocol version TLV
 *   - AUTHENTICATE (CLA=80, INS=80): signs transaction ID with on-card P-256 key,
 *     returns public key + ECDSA signature in raw R||S format
 *
 * Key generation happens once at install time. The private key never leaves the card.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Z-bit Systems, LLC
 */
package com.zbitsystems.pkoc;

import javacard.framework.*;
import javacard.security.*;

public class PkocApplet extends Applet {

    // PKOC protocol version 1.1
    private static final byte PROTOCOL_VERSION_MAJOR = (byte) 0x01;
    private static final byte PROTOCOL_VERSION_MINOR = (byte) 0x01;

    // TLV tags per PSIA PKOC 1.1 spec
    private static final byte TAG_TRANSACTION_ID = (byte) 0x4C;
    private static final byte TAG_PROTOCOL_VERSION = (byte) 0x5C;
    private static final byte TAG_READER_ID = (byte) 0x4D;
    private static final byte TAG_PUBLIC_KEY = (byte) 0x5A;
    private static final byte TAG_SIGNATURE = (byte) 0x9E;

    // APDU instruction codes
    private static final byte INS_AUTHENTICATE = (byte) 0x80;

    // Expected lengths
    private static final short LEN_TRANSACTION_ID = (short) 16;
    private static final short LEN_READER_ID = (short) 32;
    private static final short LEN_PUBLIC_KEY = (short) 65;   // Uncompressed P-256
    private static final short LEN_RAW_SIGNATURE = (short) 64; // R(32) || S(32)
    private static final short LEN_R = (short) 32;
    private static final short LEN_S = (short) 32;

    // Maximum DER-encoded ECDSA signature size for P-256: 72 bytes
    private static final short MAX_DER_SIG_LEN = (short) 72;

    // AUTHENTICATE response size: 5A 41 [65] 9E 40 [64] = 133 bytes
    private static final short AUTH_RESPONSE_LEN = (short) (2 + LEN_PUBLIC_KEY + 2 + LEN_RAW_SIGNATURE);

    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;
    private final byte[] publicKeyBytes;
    private final Signature ecdsaSha256;
    private final byte[] tempBuffer;

    // NIST P-256 curve parameters
    private static final byte[] P256_P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    private static final byte[] P256_A = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
    };

    private static final byte[] P256_B = {
        (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
        (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
        (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
        (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
    };

    private static final byte[] P256_G = {
        (byte) 0x04,
        (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47,
        (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2,
        (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
        (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
        (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B,
        (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16,
        (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE,
        (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5
    };

    private static final byte[] P256_N = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
        (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
    };

    private PkocApplet() {
        // Set up P-256 key pair
        KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        privateKey = (ECPrivateKey) keyPair.getPrivate();
        publicKey = (ECPublicKey) keyPair.getPublic();

        setP256Parameters(privateKey);
        setP256Parameters(publicKey);

        // Generate key pair — private key never leaves the card
        keyPair.genKeyPair();

        // Cache the uncompressed public key (04 || X || Y)
        publicKeyBytes = new byte[LEN_PUBLIC_KEY];
        publicKey.getW(publicKeyBytes, (short) 0);

        // ECDSA with SHA-256 (output is DER-encoded, converted to raw R||S before response)
        ecdsaSha256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ecdsaSha256.init(privateKey, Signature.MODE_SIGN);

        // Transient working buffer for DER signature before conversion
        tempBuffer = JCSystem.makeTransientByteArray((short) (MAX_DER_SIG_LEN + 16), JCSystem.CLEAR_ON_DESELECT);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        PkocApplet applet = new PkocApplet();
        if (bLength > 0) {
            applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        } else {
            applet.register();
        }
    }

    public boolean select() {
        return true;
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            handleSelect(apdu);
            return;
        }

        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (cla == (byte) 0x80 && ins == INS_AUTHENTICATE) {
            handleAuthenticate(apdu);
            return;
        }

        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    /**
     * Handle SELECT: respond with protocol version TLV.
     * Response: 5C 02 01 01
     */
    private void handleSelect(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        buffer[0] = TAG_PROTOCOL_VERSION;
        buffer[1] = (byte) 0x02;
        buffer[2] = PROTOCOL_VERSION_MAJOR;
        buffer[3] = PROTOCOL_VERSION_MINOR;

        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    /**
     * Handle AUTHENTICATE: validate incoming TLVs, sign the transaction ID,
     * respond with public key + raw ECDSA signature.
     *
     * Command data (56 bytes):
     *   4C 10 [16-byte transaction ID]
     *   5C 02 [protocol version]
     *   4D 20 [32-byte reader identifier]
     *
     * Response:
     *   5A 41 [65-byte uncompressed public key]
     *   9E 40 [64-byte raw R||S signature]
     */
    private void handleAuthenticate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short bytesRead = apdu.setIncomingAndReceive();
        short cdataOffset = apdu.getOffsetCdata();
        short cdataLength = apdu.getIncomingLength();

        // Validate minimum command data length (2+16 + 2+2 + 2+32 = 56)
        if (cdataLength < (short) 56) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Ensure all data is received
        while (bytesRead < cdataLength) {
            bytesRead += apdu.receiveBytes(bytesRead);
        }

        // Parse transaction ID (tag 0x4C, expected 16 bytes)
        short txIdOffset = findTlvValue(buffer, cdataOffset, cdataLength, TAG_TRANSACTION_ID);
        if (txIdOffset < (short) 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short txIdLen = (short) (buffer[(short) (txIdOffset - 1)] & 0xFF);
        if (txIdLen != LEN_TRANSACTION_ID) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Protocol version TLV must be present (tag 0x5C) — silently accept any value
        // for forward compatibility
        short pvOffset = findTlvValue(buffer, cdataOffset, cdataLength, TAG_PROTOCOL_VERSION);
        if (pvOffset < (short) 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Sign the transaction ID with ECDSA-SHA256 (produces DER-encoded signature)
        short derSigLen = ecdsaSha256.sign(buffer, txIdOffset, txIdLen, tempBuffer, (short) 0);

        // Build response in buffer
        short offset = 0;

        // Public key TLV: 5A 41 [65 bytes]
        buffer[offset++] = TAG_PUBLIC_KEY;
        buffer[offset++] = (byte) 0x41;
        offset = Util.arrayCopyNonAtomic(publicKeyBytes, (short) 0, buffer, offset, LEN_PUBLIC_KEY);

        // Signature TLV: 9E 40 [64 bytes raw R||S]
        buffer[offset++] = TAG_SIGNATURE;
        buffer[offset++] = (byte) 0x40;
        offset = derToRawRS(tempBuffer, (short) 0, derSigLen, buffer, offset);

        apdu.setOutgoingAndSend((short) 0, offset);
    }

    /**
     * Search for a TLV tag in the given data range.
     * Returns the offset of the value field, or -1 if not found.
     * Silently skips unrecognized tags (forward compatibility per spec).
     */
    private static short findTlvValue(byte[] data, short offset, short length, byte tag) {
        short end = (short) (offset + length);
        while (offset < (short) (end - 1)) {
            byte t = data[offset++];
            short l = (short) (data[offset++] & 0xFF);

            if ((short) (offset + l) > end) {
                break;
            }

            if (t == tag) {
                return offset;
            }
            offset += l;
        }
        return (short) -1;
    }

    /**
     * Convert a DER-encoded ECDSA signature to raw R||S (64 bytes fixed).
     *
     * DER format: 30 [seqLen] 02 [rLen] [R] 02 [sLen] [S]
     * Raw format: [R padded to 32 bytes] [S padded to 32 bytes]
     */
    private static short derToRawRS(byte[] der, short derOffset, short derLen, byte[] out, short outOffset) {
        short pos = (short) (derOffset + 2); // Skip 30 [seqLen]

        // R component
        pos++; // Skip 0x02 tag
        short rLen = (short) (der[pos++] & 0xFF);
        outOffset = copyComponent(der, pos, rLen, out, outOffset);
        pos += rLen;

        // S component
        pos++; // Skip 0x02 tag
        short sLen = (short) (der[pos++] & 0xFF);
        outOffset = copyComponent(der, pos, sLen, out, outOffset);

        return outOffset;
    }

    /**
     * Copy a DER integer component into a fixed 32-byte output field.
     * Handles leading zero removal (DER pads positive integers with 0x00)
     * and left-padding when the value is shorter than 32 bytes.
     */
    private static short copyComponent(byte[] src, short srcOffset, short srcLen, byte[] dst, short dstOffset) {
        if (srcLen > LEN_R) {
            // Leading zero byte(s) from DER encoding — skip them
            short skip = (short) (srcLen - LEN_R);
            srcOffset += skip;
            srcLen = LEN_R;
        }

        if (srcLen < LEN_R) {
            // Left-pad with zeros
            short pad = (short) (LEN_R - srcLen);
            Util.arrayFillNonAtomic(dst, dstOffset, pad, (byte) 0);
            dstOffset += pad;
        }

        Util.arrayCopyNonAtomic(src, srcOffset, dst, dstOffset, srcLen);
        return (short) (dstOffset + srcLen);
    }

    /**
     * Set NIST P-256 domain parameters on an EC key object.
     */
    private static void setP256Parameters(ECKey key) {
        key.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        key.setA(P256_A, (short) 0, (short) P256_A.length);
        key.setB(P256_B, (short) 0, (short) P256_B.length);
        key.setG(P256_G, (short) 0, (short) P256_G.length);
        key.setR(P256_N, (short) 0, (short) P256_N.length);
        key.setK((short) 1);
    }
}
