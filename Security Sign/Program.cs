using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Security_Sign
{
    class Program
    {
        static CngKey aliceKey;//Alice密钥对
        static CngKey bobKey;//bob密钥对
        static byte[] alicePubKeyBlob;
        static byte[] bobPubKeyBlob;
        static void Main(string[] args)
        {
            CreateKeys();
            byte[] encrytpedData = AliceSendsData("secret message");
            BobReceivesData(encrytpedData);
            Console.ReadKey();
        }
        static void CreateKeys() {
            /*
             * 使用EC Diffie Hellman 256算法创建2个密钥对，一个Bob的，一个Alice的       
             */
            aliceKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            bobKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            /*
             * 分别导出Alice和Bob的密钥对
             */
            alicePubKeyBlob = aliceKey.Export(CngKeyBlobFormat.EccPublicBlob);
            bobPubKeyBlob = bobKey.Export(CngKeyBlobFormat.EccPublicBlob);

        
        }

        private static byte[] AliceSendsData(string message) {
            Console.WriteLine("Alice sends message:{0}",message);
            //将文本字符串转换为字节数组
            byte[] rawData = Encoding.UTF8.GetBytes(message);
            byte[] encryptedData = null;
            //创建一个ECDiffieHellman对象，用Alice的密钥初始化它
            using(var aliceAlgorithm=new ECDiffieHellmanCng(aliceKey))
            using (CngKey bobPubKey = CngKey.Import(bobPubKeyBlob, CngKeyBlobFormat.EccPublicBlob)) {
                /*
                 * Alice调用DeriveKeyMaterial方法，从而使用其密钥对和Bob的公钥
                 * 返回的对称密钥使用对称算法AES加密数据
                 */
                byte[] symmKey = aliceAlgorithm.DeriveKeyMaterial(bobPubKey);
                Console.WriteLine("Alice creates this symmetric key with "+
                    "Bobs public key information:{0}",Convert.ToBase64String(symmKey));
                /*
                 * AesCryptoServiceProvider需要1.密钥对和2.一个初始化适量
                 * EC Diffie Hellman算法交换 1.对称密钥 2.初始化矢量IV
                 */

                var aes = new AesCryptoServiceProvider();
                aes.Key = symmKey;//提供密钥对
                aes.GenerateIV();//生成初始化矢量 
                using(ICryptoTransform encryptor=aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream()) {
                    var cs = new CryptoStream(ms,encryptor,CryptoStreamMode.Write);
                    //把初始化矢量写入内存中
                    ms.Write(aes.IV,0,aes.IV.Length);
                    //把加密数据写入内存中
                    cs.Write(rawData,0,rawData.Length);
                    //关闭加密流
                    cs.Close();
                    //将内存中的数据传给encryptedData
                    encryptedData = ms.ToArray();
                
                
                }
                aes.Clear();
            
            }
            Console.WriteLine("Alice:message is encrypted:{0}",Convert.ToBase64String(encryptedData));
            Console.WriteLine();
            return encryptedData;
        
        }

        private static void BobReceivesData(byte[] encryptedData) {
            Console.WriteLine("Bob receives encrypted data");
            byte[] rawData = null;

            var aes = new AesCryptoServiceProvider();
            int nBytes=aes.BlockSize>>3;
            byte[] iv=new byte[nBytes];
            for (int i = 0; i < iv.Length; i++)
                iv[i] = encryptedData[i];

            using(var bobAlgorithm=new ECDiffieHellmanCng(bobKey))
            using (CngKey alicePubKey = CngKey.Import(alicePubKeyBlob, CngKeyBlobFormat.EccPublicBlob)) {
                byte[] symmKey = bobAlgorithm.DeriveKeyMaterial(alicePubKey);
                Console.WriteLine("Bob creates this symmetric key with "+
                    "Alices public key information:{0}",Convert.ToBase64String(symmKey));

                aes.Key = symmKey;
                aes.IV = iv;
                 using(ICryptoTransform decryptor=aes.CreateDecryptor())
                 using (MemoryStream ms = new MemoryStream()) {
                     var cs = new CryptoStream(ms,decryptor,CryptoStreamMode.Write);
                     cs.Write(encryptedData,nBytes,encryptedData.Length-nBytes);
                     cs.Close();

                     rawData = ms.ToArray();

                     Console.WriteLine("Bob decrypts message to:{0}",Encoding.UTF8.GetString(rawData));
                 
                 }
                 aes.Clear();
            
            }

        
        }
        static byte[] CreateSignature(byte[] data, CngKey key) {
            //使用密钥对对签名消息【字节】进行加密
            var signingAlg = new ECDsaCng(key);
            byte[] signature = signingAlg.SignData(data);//返回加密之后的签名消息【字节】
            signingAlg.Clear();

            return signature;
        
        }
        /*
         * 验证签名消息和加密之后的签名消息是否一致
         */
        static bool VerifySignature(byte[] data, byte[] signature, byte[] pubKey) {
            bool retValue = false;
            //使用公钥创建一个密钥对
            using (CngKey key = CngKey.Import(pubKey, CngKeyBlobFormat.GenericPublicBlob)) {
                //创建ECDSA类，目的是为了验证签名是否正确
                var signingAlg = new ECDsaCng(key);
                //验证签名信息和加密之后的签名信息是否正确
                retValue = signingAlg.VerifyData(data,signature);
                signingAlg.Clear();
            
            }
            return retValue;
        }
    }
}
