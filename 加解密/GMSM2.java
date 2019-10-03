/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gmsm2;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author lfx
 */
public class GMSM2 {
    // 获取一条SM2曲线参数
    private final static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");

    /**
     * SM2 PKCS8证书解密
     * @param privateKey
     * @param data
     * @return
     */
    public static byte[] sm2Pkcs8Decrypt(byte[] privateKey, byte[] data) {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            PrivateKey pk = keyFactory.generatePrivate(keySpec);

            SM2Engine localSM2Engine = new SM2Engine();
            BCECPrivateKey sm2PriK = (BCECPrivateKey) pk;
            ECParameterSpec localECParameterSpec = sm2PriK.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                            localECParameterSpec.getG(), localECParameterSpec.getN());
            ECPrivateKeyParameters localECPrivateKeyParameters = new ECPrivateKeyParameters(sm2PriK.getD(),
                            localECDomainParameters);
            localSM2Engine.init(false, localECPrivateKeyParameters);

            return localSM2Engine.processBlock(data, 0, data.length);
        } catch (Exception e) {
            System.out.println("sm2Pkcs8Decrypt解密时出现异常:");
            System.out.println(e);
        }
        return null;
    }
    /**
     * SM2证书明文加密算法
     * @param publicKey
     * @param data
     * @return
     */
    public static byte[] sm2Encrypt(byte[] publicKey, byte[] data) {
        // 获取一条SM2曲线参数
        // 构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(x9ECParameters.getCurve(),
                x9ECParameters.getG(), x9ECParameters.getN());
        // 提取公钥点
        ECPoint pukPoint = x9ECParameters.getCurve().decodePoint(publicKey);
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, domainParameters);

        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));

        byte[] arrayOfBytes = null;
        try {
            arrayOfBytes = sm2Engine.processBlock(data, 0, data.length);
        } catch (Exception e) {
            System.out.println("sm2Encrypt加密时出现异常:");
            System.out.println(e);
        }
        return arrayOfBytes;
    }
    /**
     * SM2证书明文解密
     * @param privateKey
     * @param data
     * @return
     */
    public static byte[] sm2Decrypt(byte[] privateKey, byte[] data) {
        // 构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(x9ECParameters.getCurve(),
                x9ECParameters.getG(), x9ECParameters.getN());

        BigInteger privateKeyD = new BigInteger(Hex.toHexString(privateKey), 16);
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD, domainParameters);

        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, privateKeyParameters);

        try {
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (Exception e) {
            System.out.println("sm2Decrypt解密时出现异常:");
            System.out.println(e);
        }
        return null;
    }
    /**
     * PKCS8证书解密
     */
    private static void test(){
        // PKCS8证书
        String privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgRa/7gWPvpZCWrcIvJuVWKR992ahASh139Fk+tArEVtugCgYIKoEcz1UBgi2hRANCAAThZNt5X+mEGMhXKXIopXv/j4gxOsa9PRnMciJnaJJuuWZ6jedkZQxFVQOTBL1GCc0qYRQQW42XYghXKgMAonwr";
        // 密文：备注这个是旧版RM2密文，标记位：字符串二进制码首位是04
        String data = "BIF+COkQaO7f+Gmar1fNaN59TbSG4RCrKnGmVTVf+aVoYEqpP5UccajiQwMtSF1SVIfAzBXVBKr21f9IWDQb0yeRwR/a57yMXsX36piPncju3x0PGuitNXPbV2Ed4d3d7yqZujkLncZ2V0CMDcNROtv2vO8xz60OJe5F/I+fQ0Xy";
        byte[] key = sm2Pkcs8Decrypt(Base64.decode(privateKey), Base64.decode(data));
        System.out.printf("test:{\"result\":\"%s\"}\n", new String(key));
    }
    /**
     * RM2明文证书 加解密
     */
    private static void test2(){
        // 证书明文
        String priKey = "45affb8163efa59096adc22f26e556291f7dd9a8404a1d77f4593eb40ac456db";
        // 密文：备注这个是旧版RM2密文，标记位：字符串二进制码首位是04
        String data = "BIF+COkQaO7f+Gmar1fNaN59TbSG4RCrKnGmVTVf+aVoYEqpP5UccajiQwMtSF1SVIfAzBXVBKr21f9IWDQb0yeRwR/a57yMXsX36piPncju3x0PGuitNXPbV2Ed4d3d7yqZujkLncZ2V0CMDcNROtv2vO8xz60OJe5F/I+fQ0Xy";
        byte[] key = sm2Decrypt(Hex.decode(priKey), Base64.decode(data));
        System.out.printf("test2: {\"result\":\"%s\"}\n", new String(key));
        
        // 证书公钥明文: 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥
        String pubKey = "04e164db795fe98418c857297228a57bff8f88313ac6bd3d19cc72226768926eb9667a8de764650c4555039304bd4609cd2a6114105b8d976208572a0300a27c2b";
        data = "313233";
        byte[] crypt = sm2Encrypt(Hex.decode(pubKey), Hex.decode(data));
        key = sm2Decrypt(Hex.decode(priKey), crypt);
        System.out.printf("test2: {\"result\":\"%s\"}\n", new String(key));
    }
        
    public static void main(String[] args){
        if(args.length == 1 && args[0].equals("debug")){
            test();
            test2();
            return ;
        }
        else if(args.length != 2){
            for(int index = 0; index < args.length; index++)
                System.out.println(args[index]);
            System.out.println("java -jar *.jar key data");
            return ;
        }
        // PKCS8证书
        // String privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgRa/7gWPvpZCWrcIvJuVWKR992ahASh139Fk+tArEVtugCgYIKoEcz1UBgi2hRANCAAThZNt5X+mEGMhXKXIopXv/j4gxOsa9PRnMciJnaJJuuWZ6jedkZQxFVQOTBL1GCc0qYRQQW42XYghXKgMAonwr";
        // String random = "BIF+COkQaO7f+Gmar1fNaN59TbSG4RCrKnGmVTVf+aVoYEqpP5UccajiQwMtSF1SVIfAzBXVBKr21f9IWDQb0yeRwR/a57yMXsX36piPncju3x0PGuitNXPbV2Ed4d3d7yqZujkLncZ2V0CMDcNROtv2vO8xz60OJe5F/I+fQ0Xy";
        String privateKey = args[0];
        String data = args[1];
        byte[] key = sm2Pkcs8Decrypt(Base64.decode(privateKey), Base64.decode(data));
        System.out.printf("{\"result\":\"%s\"}", new String(key));
    }
    
}
