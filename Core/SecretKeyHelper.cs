using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Fast.Core
{
    public struct RSAKEY
    {
        /// <summary>
        /// 公钥
        /// </summary>
        public string PublicKey
        {
            get;
            set;
        }
        /// <summary>
        /// 私钥
        /// </summary>
        public string PrivateKey
        {
            get;
            set;
        }
    }

    public class SecretKeyHelper
    {
        /// <summary>
        /// 生成公、私钥
        /// </summary>
        /// <returns></returns>
        public RSAKEY GetKey()
        {
            //RSA密钥对的构造器  
            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();

            //RSA密钥构造器的参数  
            RsaKeyGenerationParameters param = new RsaKeyGenerationParameters(
                Org.BouncyCastle.Math.BigInteger.ValueOf(3),
                new Org.BouncyCastle.Security.SecureRandom(),
                1024,   //密钥长度  
                25);
            //用参数初始化密钥构造器  
            keyGenerator.Init(param);
            //产生密钥对  
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            //获取公钥和密钥  
            AsymmetricKeyParameter publicKey = keyPair.Public;
            AsymmetricKeyParameter privateKey = keyPair.Private;

            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);


            Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();

            byte[] publicInfoByte = asn1ObjectPublic.GetEncoded("UTF-8");
            Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded("UTF-8");

            RSAKEY item = new RSAKEY()
            {
                PublicKey = Convert.ToBase64String(publicInfoByte),
                PrivateKey = Convert.ToBase64String(privateInfoByte)
            };
            SaveKeyToFile("public", item.PublicKey);
            SaveKeyToFile("private", item.PrivateKey);
            return item;

        }

        /// <summary>
        /// 保存密钥
        /// </summary>
        /// <param name="key"></param>
        /// <param name="file_path"></param>
        private void SaveKeyToFile(string name, string key, string file_path = null)
        {
            string _path = $"{Path.GetDirectoryName(typeof(Program).Assembly.Location)}/{name}.key";
            FileStream _file;
            if (!File.Exists(_path))
                _file = File.Create(_path);
            else
                return;
            byte[] _byte = Encoding.UTF8.GetBytes(key);
            if (_file.Length < 1)
                _file.Write(_byte);
            _file.Close();
            _file.Dispose();
        }

        /// <summary>
        /// 获取公钥
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        private AsymmetricKeyParameter GetPublicKeyParameter(string token)
        {
            string key = token.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] publicInfoByte = Convert.FromBase64String(key);
            Asn1Object pubKeyObj = Asn1Object.FromByteArray(publicInfoByte);//这里也可以从流中读取，从本地导入   
            AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(publicInfoByte);
            return pubKey;
        }

        /// <summary>
        /// 获取私钥
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        private AsymmetricKeyParameter GetPrivateKeyParameter()
        {
            string key = File.ReadAllText($"{Path.GetDirectoryName(typeof(Program).Assembly.Location)}/private.key").Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] privateInfoByte = Convert.FromBase64String(key);
            // Asn1Object priKeyObj = Asn1Object.FromByteArray(privateInfoByte);//这里也可以从流中读取，从本地导入   
            // PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(privateInfoByte);
            return priKey;
        }

        /// <summary>
        /// 私钥加密
        /// </summary>
        /// <param name="ticket">需要加密字符串</param>
        /// <param name="key">私钥</param>
        /// <returns></returns>
        public string EncryptByPrivateKey(string ticket, string key)
        {
            //非对称加密算法，加解密用  
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());


            //加密  
            try
            {
                engine.Init(true, GetPrivateKeyParameter());
                byte[] byteData = System.Text.Encoding.UTF8.GetBytes(ticket);
                var ResultData = engine.ProcessBlock(byteData, 0, byteData.Length);
                return Convert.ToBase64String(ResultData);
            }
            catch (Exception ex)
            {
                return ex.Message;

            }
        }

        /// <summary>
        /// 公钥解密
        /// </summary>
        /// <param name="token">加密token</param>
        /// <param name="key">公钥</param>
        /// <returns></returns>
        public string DecryptByPublicKey(string token, string key)
        {
            token = token.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            //非对称加密算法，加解密用  
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            //解密  

            try
            {
                engine.Init(false, GetPublicKeyParameter(key));
                byte[] byteData = Convert.FromBase64String(token);
                var ResultData = engine.ProcessBlock(byteData, 0, byteData.Length);
                return System.Text.Encoding.UTF8.GetString(ResultData);

            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }
}
