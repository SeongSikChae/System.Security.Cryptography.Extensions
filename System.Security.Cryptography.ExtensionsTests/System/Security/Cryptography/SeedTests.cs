namespace System.Security.Cryptography.Tests
{
	using Text;

	[TestClass]
	public class SeedTests
	{
		[TestMethod]
		public void CreateTest()
		{
			using Seed seed = Seed.Create();
		}

		[TestMethod]
		public void CreateAlgorithmNameTest()
		{
			{
				using Seed seed = Seed.Create("Seed");
			}

			{
				Assert.ThrowsException<ArgumentException>(() =>
				{
					using Seed seed = Seed.Create("Seeda");
				});
			}

			{
				using Seed seed = Seed.Create("System.Security.Cryptography.Seed");
			}
		}

		[TestMethod]
		public void CbcEncryptDecryptTest()
		{
			using Seed seed = Seed.Create("Seed");
			seed.GenerateKey();
			seed.GenerateIV();

			byte[] plain = new byte[16];
			byte[] encrypted = seed.EncryptCbc(plain, seed.IV);
			byte[] decrypted = seed.DecryptCbc(encrypted, seed.IV);
			for (int index = 0; index < plain.Length; index++)
				Assert.AreEqual(plain[index], decrypted[index]);
		}

		[TestMethod]
		public void CfbEncryptDecryptTest()
		{
			using Seed seed = Seed.Create("Seed");
			seed.GenerateKey();
			seed.GenerateIV();

			byte[] plain = new byte[16];
			byte[] encrypted = seed.EncryptCfb(plain, seed.IV);
			byte[] decrypted = seed.DecryptCfb(encrypted, seed.IV);
			for (int index = 0; index < plain.Length; index++)
				Assert.AreEqual(plain[index], decrypted[index]);
		}

		[TestMethod]
		public void EcbEncryptDecryptTest()
		{
			using Seed seed = Seed.Create("Seed");
			seed.GenerateKey();
			byte[] plain = new byte[16];
			byte[] encrypted = seed.EncryptEcb(plain, PaddingMode.PKCS7);
			byte[] decrypted = seed.DecryptEcb(encrypted, PaddingMode.PKCS7);
			for (int index = 0; index < plain.Length; index++)
				Assert.AreEqual(plain[index], decrypted[index]);
		}

		[TestMethod]
		public void OfbEncryptDecryptTest()
		{
			using Seed seed = Seed.Create("Seed");
			seed.Mode = CipherMode.OFB;
			seed.Padding = PaddingMode.None;
			seed.Key = Encoding.UTF8.GetBytes("ABCDEF123:45GHIJ");
			seed.IV = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
			using ICryptoTransform transform = seed.CreateEncryptor();
			byte[] block = Encoding.UTF8.GetBytes("asdf1234");
			byte[] outputBlock = transform.TransformFinalBlock(block, 0, block.Length);
			string output = Convert.ToBase64String(outputBlock);
			Assert.AreEqual("1dn9D/APZxM=", output);
		}
	}
}