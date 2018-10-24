using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace GostCryptography.Cryptography.GOST2012
{
    public sealed class Gost2012_512_SignatureDescription : SignatureDescription
    {
        public Gost2012_512_SignatureDescription()
        {
            KeyAlgorithm = typeof(Gost3410_2012_512_AsymmetricAlgorithm).AssemblyQualifiedName;
            DigestAlgorithm = typeof(Gost3411_2012_512_HashAlgorithm).AssemblyQualifiedName;
            FormatterAlgorithm = typeof(Gost2012_512_SignatureFormatter).AssemblyQualifiedName;
            DeformatterAlgorithm = typeof(Gost2012_512_SignatureDeformatter).AssemblyQualifiedName;
        }
    }
}
