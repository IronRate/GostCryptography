using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace GostCryptography.Cryptography.GOST2012
{
    public sealed class Gost2012_512_SignatureDeformatter: AsymmetricSignatureDeformatter
    {
        #region Constructor

        public Gost2012_512_SignatureDeformatter()
        {

        }

        public Gost2012_512_SignatureDeformatter(AsymmetricAlgorithm publicKey):this()
        {
            SetKey(publicKey);
        }

        #endregion

        public override void SetHashAlgorithm(string strName)
        {
            throw new NotImplementedException();
        }

        public override void SetKey(AsymmetricAlgorithm key)
        {
            throw new NotImplementedException();
        }

        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
        {
            throw new NotImplementedException();
        }

    }
}
