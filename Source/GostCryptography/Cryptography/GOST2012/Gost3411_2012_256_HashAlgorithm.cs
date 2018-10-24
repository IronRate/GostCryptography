using System.Security;

using GostCryptography.Native;

namespace GostCryptography.Cryptography.GOST2012
{
    /// <summary>
    /// Реализация алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
    /// </summary>
    public class Gost3411_2012_256_HashAlgorithm : Gost3411HashAlgorithmBase
    {
        [SecuritySafeCritical]
        public Gost3411_2012_256_HashAlgorithm()
        {
        }

        [SecuritySafeCritical]
        protected override SafeHashHandleImpl CreateHashHandle()
        {
            return CryptoApiHelper.CreateHash_3411_2012_256(CryptoApiHelper.ProviderHandle);
        }
    }
}