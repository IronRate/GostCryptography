using GostCryptography.Properties;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace GostCryptography.Cryptography.GOST2012
{
    public sealed class Gost2012_512_SignatureFormatter : AsymmetricSignatureFormatter
    {
        private Gost3410_2012_512_AsymmetricAlgorithmBase _privateKey;

        #region Constructor

        public Gost2012_512_SignatureFormatter()
        {

        }

        public Gost2012_512_SignatureFormatter(AsymmetricAlgorithm privateKey):this()
        {
            SetKey(privateKey);
        }

        #endregion

        public override byte[] CreateSignature(byte[] hash)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

            var reverseSignature = _privateKey.CreateSignature(hash);
            Array.Reverse(reverseSignature);

            return reverseSignature;
        }

        public override void SetHashAlgorithm(string strName)
        {

        }

        public override void SetKey(AsymmetricAlgorithm privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }

            if (!(privateKey is Gost3410_2012_512_AsymmetricAlgorithmBase))
            {
                throw ExceptionUtility.ArgumentOutOfRange(nameof(privateKey), Resources.ShouldSupportGost3410_2012_512);
            }

            _privateKey = (Gost3410_2012_512_AsymmetricAlgorithmBase)privateKey;

        }

    }
}
