package com.reactspring.kcdsa;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.reactspring.common.KCDSA;
import com.reactspring.common.KISA_KCDSA;

public class RCTKcdsa extends ReactContextBaseJavaModule {
    public RCTKcdsa(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RCTKcdsa";
    }

    int p[] = {
            0xcbf3fa53, 0xdee5655e, 0x91b58c31, 0xf384c97c, 0x72787f6d, 0x888cd115, 0xc5cf0b38, 0x6c0ebd08,
            0x55d8b713, 0xafcc9f50, 0x886af3b9, 0x83380bf2, 0x6e6397e0, 0x03a2182b, 0x93b711c3, 0x13403b8b,
            0xc721528a, 0x291cbefb, 0x59310b09, 0xa3600ff4, 0x4292d75c, 0x7e790228, 0xc54bbe29, 0x56980bd4,
            0x4cf36adb, 0x1e829c76, 0x98763c5a, 0x3233444f, 0x1a028260, 0x14f4f431, 0xa811e70b, 0x2a18ad17,
            0xe66d4e5d, 0x0c1160a0, 0x0a6828da, 0x031fe7d5, 0x93bb0397, 0x57f7fa0f, 0xb06e0e90, 0x828b4f8f,
            0x1b9cc9ae, 0x7e3788d5, 0x7593b18b, 0x51a5cdfc, 0x2e1c416b, 0x380709ea, 0x302f5894, 0x47dcf43f,
            0xa5529ea3, 0x94351cfe, 0xff235694, 0x3ff5000c, 0xe582ccfc, 0xb34af9be, 0xf042e399, 0x3bc0e916,
            0xa5448e9f, 0x3a4f10c6, 0xdd92751b, 0xb729b800, 0x8c9f803e, 0x46661df5, 0xc95d11be, 0x8da8c1b5
    };
    int q[] = {
            0x79a51f53, 0x537f32cc, 0x2a3bb997, 0xe54650f2, 0xfd1be7fe, 0x1ec103cd, 0x864f1884
    };
    int g[] = {
            0x85681c4e, 0x9b64673f, 0x5e3734e7, 0xf2c9dea3, 0x6ac5de17, 0x400be9e9, 0xf9127cb4, 0x3b9cbe48,
            0x1a7b45c8, 0x2784afe4, 0xef546241, 0x79c04707, 0x387e7ec9, 0x185c8258, 0xf2317f45, 0x3d1704ee,
            0x2c0580b0, 0x21512d5d, 0xe81661f3, 0x85cc9ce2, 0x9147eeaf, 0x167b9434, 0xb5c7653a, 0x27ed1912,
            0x7813d054, 0xe281f7fe, 0xbd9be354, 0xe7db16fc, 0xe63c605e, 0x358896c4, 0x9d3c3c6f, 0x22c6a3f9,
            0x74ef4839, 0x5bc72556, 0xe68ba17d, 0x17c999db, 0x69850a56, 0xf3480183, 0x6c62f4ec, 0xf36618f7,
            0x5104ad03, 0x6953c0c8, 0x2baeb6f0, 0xbada8da6, 0x0b954f25, 0xf7704e99, 0xea7f8002, 0x2f6e7ee8,
            0x367e4ec7, 0x3ea302d2, 0x1b2dfb0a, 0x854fd93c, 0xb24b45cd, 0x68c1eb57, 0xb6e9eb03, 0x7a225044,
            0x0d00c14a, 0x67a6f61c, 0x3edb21aa, 0xd385a357, 0x8b079e4a, 0x7a9a5a96, 0x7a414d16, 0x0e9be1f8
    };
    byte pbSrc[] = {
            0x73, 0x61, 0x6c, 0x64, 0x6a, 0x66, 0x61, 0x77, 0x70, 0x33, 0x39, 0x39, 0x75, 0x33, 0x37, 0x34,
            0x72, 0x30, 0x39, 0x38, 0x75, 0x39, 0x38, 0x5e, 0x25, 0x5e, 0x25, 0x68, 0x6b, 0x72, 0x67, 0x6e,
            0x3b, 0x6c, 0x77, 0x6b, 0x72, 0x70, 0x34, 0x37, 0x74, 0x39, 0x33, 0x63, 0x25, 0x24, 0x38, 0x39,
            0x34, 0x33, 0x39, 0x38, 0x35, 0x39, 0x6b, 0x6a, 0x64, 0x6d, 0x6e, 0x76, 0x63, 0x6d, 0x20, 0x63,
            0x76, 0x6b, 0x20, 0x6f, 0x34, 0x75, 0x30, 0x39, 0x72, 0x20, 0x34, 0x6a, 0x20, 0x6f, 0x6a, 0x32,
            0x6f, 0x75, 0x74, 0x32, 0x30, 0x39, 0x78, 0x66, 0x71, 0x77, 0x3b, 0x6c, 0x2a, 0x26, 0x21, 0x5e,
            0x23, 0x40, 0x55, 0x23, 0x2a, 0x23, 0x24, 0x29, 0x28, 0x23, 0x20, 0x7a, 0x20, 0x78, 0x6f, 0x39,
            0x35, 0x37, 0x74, 0x63, 0x2d, 0x39, 0x35, 0x20, 0x35, 0x20, 0x76, 0x35, 0x6f, 0x69, 0x75, 0x76,
            0x39, 0x38, 0x37, 0x36, 0x20, 0x36, 0x20, 0x76, 0x6a, 0x20, 0x6f, 0x35, 0x69, 0x75, 0x76, 0x2d,
            0x30, 0x35, 0x33, 0x2c, 0x6d, 0x63, 0x76, 0x6c, 0x72, 0x6b, 0x66, 0x77, 0x6f, 0x72, 0x65, 0x74
    };
    byte msg[] = {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6d,
            0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x4b, 0x43, 0x44, 0x53, 0x41,
            0x20, 0x75, 0x73, 0x61, 0x67, 0x65, 0x21
    };
    byte kInput[] = {
            0x1b, (byte)0xf1, 0x23, (byte)0xb0, 0x27, 0x52, (byte)0xe2, (byte)0xc9, (byte)0xed, (byte)0x81, 0x51, 0x74, 0x69, (byte)0xf2, 0x0b, 0x0c,
            0x19, (byte)0xa9, (byte)0x97, (byte)0xa4
    };
    int plen = 2048, qlen = 224;
    KISA_KCDSA kcdsa = new KISA_KCDSA();

    @ReactMethod
    public void KISA_KCDSA_GenerateKeyPair(int hash, Promise promise) {
        // KCDSA 알고리즘의 키 쌍(개인키, 공개키) 생성 함수
        // hash (1:SHA_224, 2:SHA_256)
        try {
            KCDSA.KISA_KCDSA_CreateObject(kcdsa);
            KCDSA.KISA_KCDSA_set_params(kcdsa, p, 64, q, 7, g, 64, null, 0, null, 0);
            int ret = KCDSA.KISA_KCDSA_GenerateKeyPair(kcdsa, pbSrc, 160, qlen, hash);

//            - 0 : 파라미터 생성 성공
//            - 2 : 치명적인 오류 발생
//            - 3 : 유효하지 않은 KCDSA 객체 포인터 입력
            promise.resolve(ret);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void KISA_KCDSA_sign(String msg, int hash, Promise promise) {
        // KCDSA 알고리즘 전자서명 생성 함수
        // hash (1:SHA_224, 2:SHA_256)
        byte[] sign = new byte[56];

        try {
            KCDSA.KISA_KCDSA_sign(kcdsa, msg.getBytes(), msg.getBytes().length, sign, hash, kInput, 20);

            // sign : 전자서명값 (R,S)
            promise.resolve(bytesToHex (sign));
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void KISA_KCDSA_verify(String msg, String sign, int hash, Promise promise) {
        // KCDSA 알고리즘 전자서명 검증 함수
        // hash (1:SHA_224, 2:SHA_256)
        try {
            int ret = KCDSA.KISA_KCDSA_verify(kcdsa, msg.getBytes(), msg.getBytes().length, hexToBytes (sign), hexToBytes (sign).length, hash);

//		    - 0 : 전자서명 검증 성공
//		    - 1 : 전자서명 검증 실패
//		    - 2 : 치명적인 오류 발생
//		    - 3 : 유효하지 않은 KCDSA 구조체 포인터 입력
//		    - 4 : 유효하지 않은 알고리즘 파라미터 입력
            promise.resolve(ret);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() == 0) {
            return null;
        }

        byte[] ba = new byte[hex.length() / 2];
        for (int i = 0; i < ba.length; i++) {
            ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return ba;
    }
}