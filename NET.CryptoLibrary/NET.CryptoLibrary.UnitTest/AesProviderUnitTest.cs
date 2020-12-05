using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ncl.net.cryptolybrary.Encryption.AES;
using ncl.net.cryptolybrary.Encryption.PBKDF2;

namespace NET.CryptoLibrary.UnitTest
{
    [TestClass]
    public class AesProviderUnitTest
    {
        [TestMethod]
        public void EncryptStringTest()
        {
            string STRING_EncryptedString = AesProvider.AES_CBC_Encryption_Rand_IV("0123456789qwertyuiopasdfghjklzxcvbnm", "mykey");       
            Assert.IsTrue(STRING_EncryptedString != null && STRING_EncryptedString.Length > 0);
        }

        [TestMethod]
        public void EncryptBufferTest()
        {
            byte[] vBYTE_EncryptedBuffer = AesProvider.AES_CBC_Encryption_Rand_IV(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, "mykey");
            Assert.IsNotNull(vBYTE_EncryptedBuffer);
        }

        [TestMethod]
        public void EncryptDecryptStringTest()
        {
            string STRING_EncryptionKey = "thisIsMyP@55w0rd";
            string STRING_ToEncrypt = "0123456789qwertyuiopasdfghjklzxcvbnm";
            string STRING_EncryptedString = AesProvider.AES_CBC_Encryption_Rand_IV(STRING_ToEncrypt, STRING_EncryptionKey);
            string STRING_DecryptedString = AesProvider.AES_CBC_Decryption_Rand_IV(STRING_EncryptedString, STRING_EncryptionKey);
            Assert.IsTrue(STRING_DecryptedString.Equals(STRING_ToEncrypt));
        }

        [TestMethod]
        public void EncryptDecryptBufferTest()
        {
            string STRING_EncryptionKey = "thisIsMyP@55w0rd";
            byte[] vBYTE_ToEncrypt = Encoding.UTF8.GetBytes("0123456789qwertyuiopasdfghjklzxcvbnm");//new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
            byte[] vBYTE_EncryptedBuffer = AesProvider.AES_CBC_Encryption_Rand_IV(vBYTE_ToEncrypt, STRING_EncryptionKey);
            byte[] vBYTE_DecryptedBuffer = AesProvider.AES_CBC_Decryption_Rand_IV(vBYTE_EncryptedBuffer, STRING_EncryptionKey);
            Assert.IsTrue(vBYTE_ToEncrypt.SequenceEqual(vBYTE_DecryptedBuffer));
        }

        [TestMethod]
        public void T2_001_HashAndVerify()
        {
            string STRING_HashedString = PBKDF2Provider.Generate("!//Lab2020");
            Assert.IsTrue(PBKDF2Provider.IsValid("!//Lab2020", STRING_HashedString));
        }
    }
}
