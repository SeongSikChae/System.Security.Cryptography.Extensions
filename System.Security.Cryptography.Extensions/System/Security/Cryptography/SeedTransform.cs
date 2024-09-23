using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace System.Security.Cryptography
{
	internal class SeedTransform : ICryptoTransform
	{
		public SeedTransform(byte[] rgbKey, byte[]? rgbIV, CipherMode cipherMode, PaddingMode paddingMode, bool encrypting)
		{
			KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter(ALGORITHM, rgbKey);
			string paddingModeStr;
			switch (paddingMode)
			{
				case PaddingMode.None:
					paddingModeStr = "NOPADDING";
					break;
				case PaddingMode.PKCS7:
					paddingModeStr = "PKCS7PADDING";
					break;
				case PaddingMode.Zeros:
					paddingModeStr = "ZEROBYTEPADDING";
					break;
				case PaddingMode.ANSIX923:
					paddingModeStr = "X923PADDING";
					break;
				case PaddingMode.ISO10126:
					paddingModeStr = "ISO10126PADDING";
					break;
				default:
					paddingModeStr = "PKCS7PADDING";
					break;
			}
			cipher = CipherUtilities.GetCipher($"{ALGORITHM}/{Enum.GetName(cipherMode)}/{paddingModeStr}");
			if (rgbIV is null || cipherMode == CipherMode.ECB)
				cipher.Init(encrypting, keyParameter);
			else
				cipher.Init(encrypting, new ParametersWithIV(keyParameter, rgbIV));
		}

		private const string ALGORITHM = "SEED";
		private readonly IBufferedCipher cipher;

		public bool CanReuseTransform => true;

		public bool CanTransformMultipleBlocks => true;

		public int InputBlockSize => cipher.GetBlockSize();

		public int OutputBlockSize => cipher.GetBlockSize();

		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			return cipher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
		}

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			return cipher.DoFinal(inputBuffer, inputOffset, inputCount);
		}

		public void Dispose()
		{
		}
	}
}
