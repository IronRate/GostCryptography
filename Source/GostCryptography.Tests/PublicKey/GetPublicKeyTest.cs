using GostCryptography.Cryptography;
using GostCryptography.Cryptography.GOST2012;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GostCryptography.Tests.PublicKey
{
    [TestFixture(Description = "Получение открытого ключа")]
    public class GetPublicKeyTest
    {
        [Test]
        public void Fetch3410_2001()
        {
            GostCryptoConfig.ProviderType = ProviderTypes.CryptoPro;
            var certificate = TestCertificates.GetCertificate3410_2001();
            var publicKey = (Gost3410AsymmetricAlgorithmBase)certificate.GetPublicKeyAlgorithm();

            Assert.NotNull(publicKey);
            Assert.AreEqual(512, publicKey.KeySize);
        }

        [Test]
        public void Fetch3410_2012_256()
        {
            GostCryptoConfig.ProviderType = ProviderTypes.CryptoPro;
            var certificate = TestCertificates.GetCertificate3410_2012_256();
            var publicKey = (Gost3410_2012_256_AsymmetricAlgorithmBase)certificate.GetPublicKeyAlgorithm();

            Assert.NotNull(publicKey);
            Assert.AreEqual(512, publicKey.KeySize);
        }

        [Test]
        public void Fetch3410_2012_512()
        {
            GostCryptoConfig.ProviderType = ProviderTypes.CryptoPro;
            var certificate = TestCertificates.GetCertificate3410_2012_512();
            var publicKey = (Gost3410_2012_512_AsymmetricAlgorithmBase)certificate.GetPublicKeyAlgorithm();

            Assert.NotNull(publicKey);
            Assert.AreEqual(1024, publicKey.KeySize);
        }
    }
}
