﻿using GostCryptography.Tests.Properties;
using GostCryptography.Xml;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace GostCryptography.Tests.Xml.Sign
{
    [TestFixture(Description = "Подпись и проверка подписи всего XML документа с использованием сертификата")]
    public sealed class SignedXmlDocument2012_512_Test
    {
        [Test]
        public void ShouldSignXml()
        {
            GostCryptography.Cryptography.GostCryptoConfig.ProviderType = Cryptography.ProviderTypes.CryptoPro_2012_512;
            // Given
            var signingCertificate = TestCertificates.GetCertificate3410_2012_512();

            if (signingCertificate != null)
            {
                var xmlDocument = CreateXmlDocument();

                // When
                var signedXmlDocument = SignXmlDocument(xmlDocument, signingCertificate);

                // Then
                Assert.IsTrue(VerifyXmlDocumentSignature(signedXmlDocument));
            }
        }

        private static XmlDocument CreateXmlDocument()
        {
            var document = new XmlDocument();
            document.LoadXml(Resources.SignedXmlExample);
            return document;
        }

        private static XmlDocument SignXmlDocument(XmlDocument xmlDocument, X509Certificate2 signingCertificate)
        {
            // Создание подписчика XML-документа
            var signedXml = new GostSignedXml(xmlDocument);

            // Установка ключа для создания подписи
            signedXml.SetSigningCertificate(signingCertificate);

            // Ссылка на весь документ и указание алгоритма хэширования
            var dataReference = new Reference { Uri = "", DigestMethod = GostSignedXml.XmlDsigGost3411_2012_512Url };

            // Метод преобразования для подписи всего документа
            dataReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

            // Установка ссылки на узел
            signedXml.AddReference(dataReference);

            // Установка информации о сертификате, который использовался для создания подписи
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(signingCertificate));
            signedXml.KeyInfo = keyInfo;

            // Вычисление подписи
            signedXml.ComputeSignature();

            // Получение XML-представления подписи
            var signatureXml = signedXml.GetXml();

            // Добавление подписи в исходный документ
            xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(signatureXml, true));

            return xmlDocument;
        }

        private static bool VerifyXmlDocumentSignature(XmlDocument signedXmlDocument)
        {
            // Создание подписчика XML-документа
            var signedXml = new GostSignedXml(signedXmlDocument);

            // Поиск узла с подписью
            var nodeList = signedXmlDocument.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);

            // Загрузка найденной подписи
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Проверка подписи
            return signedXml.CheckSignature();
        }
    }
}
