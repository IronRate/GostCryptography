using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace GostCryptography.Cryptography.GOST2012
{
    public sealed class Gost2012_256_SignatureFormatter : AsymmetricSignatureFormatter
    {
        #region Constructor

        public Gost2012_256_SignatureFormatter()
        {

        }

        public Gost2012_256_SignatureFormatter(AsymmetricAlgorithm privateKey):this()
        {
            SetKey(privateKey);
        }
        
        #endregion

        public override byte[] CreateSignature(byte[] rgbHash)
        {
            throw new NotImplementedException();
        }

        public override void SetHashAlgorithm(string strName)
        {
            throw new NotImplementedException();
        }

        public override void SetKey(AsymmetricAlgorithm key)
        {
            throw new NotImplementedException();
        }

    }
}
