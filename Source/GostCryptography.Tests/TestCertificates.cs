using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Cryptography;

namespace GostCryptography.Tests
{
	static class TestCertificates
	{
		/// <summary>
		/// Имя хранилища для поиска тестового сертификата.
		/// </summary>
		/// <remarks>
		/// Значение равно <see cref="StoreName.My"/>.
		/// </remarks>
		public const StoreName CertStoreName = StoreName.My;

		/// <summary>
		/// Местоположение для поиска тестового сертификата.
		/// </summary>
		/// <remarks>
		/// Значение равно <see cref="StoreLocation.LocalMachine"/>.
		/// </remarks>
		public const StoreLocation CertStoreLocation = StoreLocation.LocalMachine;

		/// <summary>
		/// Сертификат ГОСТ Р 34.10-2001 с закрытым ключем.
		/// </summary>
		private static readonly X509Certificate2 GostCetificate3410_2001 = FindGostCertificate3410_2001();

        private static readonly X509Certificate2 GostCertificate3410_2012_256 = FindGostCertificate3410_2012_512();


		/// <summary>
		/// Возвращает тестовый контейнер ключей ГОСТ.
		/// </summary>
		/// <remarks>
		/// Для простоты берется контейнер ключей сертификата, однако можно явно указать контейнер, например так:
		/// <code>
		/// var keyContainer1 = new CspParameters(ProviderTypes.VipNet, null, "MyVipNetContainer");
		/// var keyContainer2 = new CspParameters(ProviderTypes.CryptoPro, null, "MyCryptoProContainer");
		/// </code>
		/// </remarks>
		public static CspParameters GetKeyContainer()
		{
			return GostCetificate3410_2001.GetPrivateKeyInfo();
		}

		/// <summary>
		/// Возвращает тестовый сертификат ГОСТ с закрытым ключем.
		/// </summary>
		public static X509Certificate2 GetCertificate()
		{
			return GostCetificate3410_2001;
		}


		private static X509Certificate2 FindGostCertificate3410_2001()
		{
			// Для тестирования берется первый найденный сертификат ГОСТ с закрытым ключем.

			var store = new X509Store(CertStoreName, CertStoreLocation);
			store.Open(OpenFlags.ReadOnly);

			try
			{
				foreach (var certificate in store.Certificates)
				{
					if (certificate.HasPrivateKey && certificate.SignatureAlgorithm.Value == "1.2.643.2.2.3")
					{
						return certificate;
					}
				}
			}
			finally
			{
				store.Close();
			}

			return null;
		}

        private static X509Certificate2 FindGostCertificate3410_2012_256()
        {
            // Для тестирования берется первый найденный сертификат ГОСТ с закрытым ключем.

            var store = new X509Store(CertStoreName, CertStoreLocation);
            store.Open(OpenFlags.ReadOnly);

            try
            {
                foreach (var certificate in store.Certificates)
                {
                    if (certificate.HasPrivateKey && certificate.SignatureAlgorithm.Value == "1.2.643.2.2.3")
                    {
                        return certificate;
                    }
                }
            }
            finally
            {
                store.Close();
            }

            return null;
        }
    }
}