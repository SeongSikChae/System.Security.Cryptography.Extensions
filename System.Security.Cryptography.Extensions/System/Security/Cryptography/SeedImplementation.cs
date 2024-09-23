using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace System.Security.Cryptography
{
	internal sealed class SeedImplementation : Seed
	{
		public sealed override ICryptoTransform CreateEncryptor()
		{
			return CreateTransform(Key, IV, encrypting: true);
		}

		public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
		{
			return CreateTransform(rgbKey, rgbIV, encrypting: true);
		}

		public override ICryptoTransform CreateDecryptor()
		{
			return CreateTransform(Key, IV, encrypting: false);
		}

		public sealed override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
		{
			return CreateTransform(rgbKey, rgbIV, encrypting: false);
		}

		public sealed override void GenerateIV()
		{
			IV = RandomNumberGenerator.GetBytes(BlockSize / BitsPerByte);
		}

		public sealed override void GenerateKey()
		{
			CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator("SEED");
			KeyGenerationParameters parameters = new KeyGenerationParameters(new SecureRandom(), KeySize);
			generator.Init(parameters);
			Key = generator.GenerateKey();
		}

		protected sealed override void Dispose(bool disposing)
		{
		}

		private SeedTransform CreateTransform(byte[] rgbKey, byte[]? rgbIV, bool encrypting)
		{
			return CreateTransform(rgbKey, rgbIV, encrypting, Mode, Padding);
		}

		private SeedTransform CreateTransform(byte[] rgbKey, byte[]? rgbIV, bool encrypting, CipherMode cipherMode, PaddingMode paddingMode)
		{
			ArgumentNullException.ThrowIfNull(rgbKey);

			long keySize = rgbKey.Length * (long)BitsPerByte;
			if (keySize > int.MaxValue || !((int)keySize).IsLegalSize(this.LegalBlockSizes))
				throw new ArgumentException($"invalid key size '{nameof(rgbKey)}'");
			if (rgbIV is not null)
			{
				long ivSize = rgbIV.Length * (long)BitsPerByte;
				if (ivSize != BlockSize)
					throw new ArgumentException($"invalid iv size '{nameof(rgbIV)}'");
			}
			if (cipherMode == CipherMode.CFB)
				ValidateCFBFeedbackSize(FeedbackSize);

			return new SeedTransform(rgbKey, rgbIV, cipherMode, paddingMode, encrypting);
		}

		private static void ValidateCFBFeedbackSize(int feedback)
		{
			if (feedback != 8 && feedback != 128)
				throw new CryptographicException("not supported feedback size");
		}

		private const int BitsPerByte = 8;

		protected override bool TryEncryptCbcCore(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
		{
			try
			{
				using ICryptoTransform transform = CreateTransform(Key, IV, true, CipherMode.CBC, paddingMode);
				byte[] block = transform.TransformFinalBlock(plaintext.ToArray(), 0, plaintext.Length);
				block.CopyTo(destination);
				bytesWritten = block.Length;
				return true;
			}
			catch (Exception)
			{
				bytesWritten = -1;
				return false;
			}
		}

		protected override bool TryDecryptCbcCore(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
		{
			try
			{
				using ICryptoTransform transform = CreateTransform(Key, IV, false, CipherMode.CBC, paddingMode);
				byte[] block = transform.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);
				block.CopyTo(destination);
				bytesWritten = block.Length;
				return true;
			}
			catch (Exception)
			{
				bytesWritten = -1;
				return false;
			}
		}

		protected override bool TryEncryptCfbCore(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode, int feedbackSizeInBits, out int bytesWritten)
		{
			try
			{
				using ICryptoTransform transform = CreateTransform(Key, IV, true, CipherMode.CFB, paddingMode);
				byte[] block = transform.TransformFinalBlock(plaintext.ToArray(), 0, plaintext.Length);
				block.CopyTo(destination);
				bytesWritten = block.Length;
				return true;
			}
			catch (Exception)
			{
				bytesWritten = -1;
				return false;
			}
		}

		protected override bool TryDecryptCfbCore(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode, int feedbackSizeInBits, out int bytesWritten)
		{
			try
			{
				using ICryptoTransform transform = CreateTransform(Key, IV, false, CipherMode.CFB, paddingMode);
				byte[] block = transform.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);
				block.CopyTo(destination);
				bytesWritten = block.Length;
				return true;
			}
			catch (Exception)
			{
				bytesWritten = -1;
				return false;
			}
		}

		protected override bool TryEncryptEcbCore(ReadOnlySpan<byte> plaintext, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
		{
			try
			{
				using ICryptoTransform transform = CreateTransform(Key, IV, true, CipherMode.ECB, paddingMode);
				byte[] block = transform.TransformFinalBlock(plaintext.ToArray(), 0, plaintext.Length);
				block.CopyTo(destination);
				bytesWritten = block.Length;
				return true;
			}
			catch (Exception)
			{
				bytesWritten = -1;
				return false;
			}
		}

		protected override bool TryDecryptEcbCore(ReadOnlySpan<byte> ciphertext, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
		{
			try
			{
				using ICryptoTransform transform = CreateTransform(Key, IV, false, CipherMode.ECB, paddingMode);
				byte[] block = transform.TransformFinalBlock(ciphertext.ToArray(), 0, ciphertext.Length);
				block.CopyTo(destination);
				bytesWritten = block.Length;
				return true;
			}
			catch (Exception)
			{
				bytesWritten = -1;
				return false;
			}
		}
	}
}
