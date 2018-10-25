using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace GostCryptography.Cryptography.GOST2012
{
    public sealed class Gost2012_256_KeyValue:KeyInfoClause
    {
        #region Constructor

        public Gost2012_256_KeyValue()
        {
            Key = new Gost3410_2012_256_AsymmetricAlgorithm();

        }

        public Gost2012_256_KeyValue(AsymmetricAlgorithm key)
        {
            Key = key;
        }

        #endregion

        public AsymmetricAlgorithm Key { get; private set; }

        public override void LoadXml(XmlElement element)
        {
            if (element == null)
            {
                throw new ArgumentNullException("element");
            }

            Key.FromXmlString(element.OuterXml);
        }

        public override XmlElement GetXml()
        {
            var document = new XmlDocument { PreserveWhitespace = true };
            var element = document.CreateElement("KeyValue", SignedXml.XmlDsigNamespaceUrl);
            element.InnerXml = Key.ToXmlString(false);
            return element;
        }


    }
}
