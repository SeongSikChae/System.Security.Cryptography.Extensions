namespace System.Security.Cryptography
{
	using Runtime.Versioning;

	/// <summary>
	/// Abstract on KISA SEED algorithm
	/// </summary>
	public abstract class Seed : SymmetricAlgorithm
	{
		/// <summary>
		/// Abstract Construstor
		/// </summary>
		protected Seed()
		{
			LegalBlockSizesValue = (KeySizes[])s_legalBlockSizes.Clone();
			LegalKeySizesValue = (KeySizes[])s_legalKeySizes.Clone();

			BlockSizeValue = 128;
			FeedbackSizeValue = 8;
			KeySizeValue = 128;
			ModeValue = CipherMode.CBC;
			Padding = PaddingMode.PKCS7;
		}

		private static readonly KeySizes[] s_legalBlockSizes = { new KeySizes(128, 128, 0) };
		private static readonly KeySizes[] s_legalKeySizes = { new KeySizes(128, 128, 64) };

		/// <summary>
		/// Creation of KISA SEED algorithm implementation
		/// </summary>
		/// <returns></returns>
		[UnsupportedOSPlatform("browser")]
		public static new Seed Create()
		{
			return new SeedImplementation();
		}

		/// <summary>
		/// Creation of KISA SEED algorithm implementation by Algorithm Name
		/// </summary>
		/// <param name="algorithmName"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentException"></exception>
		public static new Seed Create(string algorithmName)
		{
			return algorithmName switch
			{
				"Seed" or "System.Security.Cryptography.Seed" => new SeedImplementation(),
				_ => throw new ArgumentException("unknown algorithm name"),
			};
		}

		/// <summary>
		/// Cipher Mode Property
		/// </summary>
		public override CipherMode Mode { get; set; }
	}
}
