namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Типы криптографических провайдеров.
	/// </summary>
	public enum ProviderTypes:int
	{
        None=0,

		/// <summary>
		/// Идентификатор типа криптографического провайдера VipNet.
		/// </summary>
		VipNet = 2,

		/// <summary>
		/// Идентификатор типа криптографического провайдера CryptoPro.
		/// </summary>
		CryptoPro = 75,

        /// <summary>
        /// Идентифиактор типа криптографического провайдера CryptoPro 2012 с размером ключа 512 бит
        /// </summary>
        CryptoPro_2012_256=80,

        /// <summary>
        /// Идентифиактор типа криптографического провайдера CryptoPro 2012 с размером ключа 1024 бит
        /// </summary>
        CryptoPro_2012_512=81
	}
}