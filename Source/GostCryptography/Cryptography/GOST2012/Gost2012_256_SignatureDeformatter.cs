using GostCryptography.Properties;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace GostCryptography.Cryptography.GOST2012
{
    public sealed class Gost2012_256_SignatureDeformatter : AsymmetricSignatureDeformatter
    {
        private Gost3410_2012_256_AsymmetricAlgorithmBase _publicKey;

        #region Constructor

        public Gost2012_256_SignatureDeformatter()
        {

        }

        public Gost2012_256_SignatureDeformatter(AsymmetricAlgorithm publicKey):this()
        {
            SetKey(publicKey);
        }


        #endregion

        public override void SetHashAlgorithm(string strName)
        {
            
        }

        public override void SetKey(AsymmetricAlgorithm publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }

            if (!(publicKey is Gost3410_2012_256_AsymmetricAlgorithmBase))
            {
                throw ExceptionUtility.ArgumentOutOfRange(nameof(publicKey), Resources.ShouldSupportGost3410_2012_256);
            }

            _publicKey = (Gost3410_2012_256_AsymmetricAlgorithmBase)publicKey;


        }

        public override bool VerifySignature(byte[] hash, byte[] signature)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            var reverseSignature = (byte[])signature.Clone();
            Array.Reverse(reverseSignature);

            return _publicKey.VerifySignature(hash, reverseSignature);
        }
    }
}
