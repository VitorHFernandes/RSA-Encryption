using System;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Linq;
using System.Globalization;
using System.Collections.Generic;
using System.IO;

namespace ConsoleApp1
{
    class Program
    {
        public static int PinBlockGenerate2(string conta,  string senha, out string pinblock)
        {
            String firstBlock;
            String secondBlock;
            var plainPinBlock = "";

            pinblock = "";
            //if (conta.Length != 16)
            //{
            //    return 1001; // cartão inválido
            //}

            //if (senha.Length != 4))
            //{
            //    return 1002; // senha inválida
            //}
            firstBlock = "04" + senha + "FFFFFFFFFF";
            //secondBlock = "000000" + conta;
            secondBlock = conta;

            secondBlock = "0000" + secondBlock.Substring(3, 12);


            var binaryFirstBlock = HexStringToBinary(firstBlock);
            var binarySecondBlock = HexStringToBinary(secondBlock);

            Console.WriteLine("BLOCO 1 BINARIO: [{0}]", binaryFirstBlock);
            Console.WriteLine("BLOCO 2 BINARIO: [{0}]", binarySecondBlock);

            plainPinBlock = BinaryStringToHex(XorBins(binaryFirstBlock, binarySecondBlock));

            Console.WriteLine("PINBLOCK 2 HEX: [{0}]", plainPinBlock);

            //plainPinBlock = hexFirstBlock ^ hexSecondBlock;


            try
            {
                //Create a UnicodeEncoder to convert between byte array and string.
                UnicodeEncoding ByteConverter = new UnicodeEncoding();

                //Create byte arrays to hold original, encrypted, and decrypted data.
                byte[] dataToEncrypt = hextoByte(plainPinBlock);
                byte[] encryptedData;

                //Create a new instance of RSACryptoServiceProvider to generate
                //public and private key data.
                using (RSACryptoServiceProvider RSA = DecodeX509PublicKey(Convert.FromBase64String(GetKey())))
                {
                    //Pass the data to ENCRYPT, the public key information 
                    //(using RSACryptoServiceProvider.ExportParameters(false),
                    //and a boolean flag specifying no OAEP padding.
                    encryptedData = RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);

                    //Display the decrypted plaintext to the console. 
                    //Console.WriteLine("Encrypted plaintext: {0}", encryptedData);
                }
                pinblock = Convert.ToBase64String(encryptedData); 
            }
            catch (ArgumentNullException)
            {
                //Catch this exception in case the encryption did
                //not succeed.
                Console.WriteLine("Encryption failed.");
            }
            int retorno = 0;
            if (senha == "Teste")
                retorno = 100;
            return retorno;
        }


        static string GetKey()
        {
            return File.ReadAllText("FernandesPublicKey_HML.pem").Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "");
            //.Replace("\n", "");
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }

        public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];
            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            MemoryStream mem = new MemoryStream(x509key);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;

            try
            {

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;

                seq = binr.ReadBytes(15);       //read the Sequence OID
                if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8203)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;

                bt = binr.ReadByte();
                if (bt != 0x00)     //expect null byte next
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                byte lowbyte = 0x00;
                byte highbyte = 0x00;

                if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                    lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                else if (twobytes == 0x8202)
                {
                    highbyte = binr.ReadByte(); //advance 2 bytes
                    lowbyte = binr.ReadByte();
                }
                else
                    return null;
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                int modsize = BitConverter.ToInt32(modint, 0);

                byte firstbyte = binr.ReadByte();
                binr.BaseStream.Seek(-1, SeekOrigin.Current);

                if (firstbyte == 0x00)
                {   //if first byte (highest order) of modulus is zero, don't include it
                    binr.ReadByte();    //skip this null byte
                    modsize -= 1;   //reduce modulus buffer size by 1
                }

                byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                    return null;
                int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                byte[] exponent = binr.ReadBytes(expbytes);

                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAKeyInfo = new RSAParameters();
                RSAKeyInfo.Modulus = modulus;
                RSAKeyInfo.Exponent = exponent;
                RSA.ImportParameters(RSAKeyInfo);
                return RSA;
            }
            catch (Exception)
            {
                return null;
            }

            finally { binr.Close(); }

        }

        static void Main(string[] args)
        {
            string cartao;
            string senha;
            Console.Write("CARTÃO: ");
            cartao = Console.ReadLine();
            Console.Write("SENHA: ");
            senha = Console.ReadLine();

            String pinblock;
            Console.WriteLine("PROCESSANDO...");
            int retorno = (PinBlockGenerate2(cartao, senha, out pinblock));
            if (retorno != 0)
            {
                Console.WriteLine("ERRO RETORNO: [{0}]", retorno);
            }
            else
            {
                Console.WriteLine("PINBLOCK ENCRIPTADO (BASE65): [{0}]", pinblock);

            }
            Console.ReadLine();

        }
        
        private static byte[] hextoByte(String hex)
        {
            string hexData = hex;
            byte[] bytes = new byte[hexData.Length / 2];

            for (int i = 0; i < hexData.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hexData.Substring(i, 2), 16);

            return bytes;
        }

        private static readonly Dictionary<char, string> hexCharacterToBinary = new Dictionary<char, string> {
            { '0', "0000" },
            { '1', "0001" },
            { '2', "0010" },
            { '3', "0011" },
            { '4', "0100" },
            { '5', "0101" },
            { '6', "0110" },
            { '7', "0111" },
            { '8', "1000" },
            { '9', "1001" },
            { 'A', "1010" },
            { 'B', "1011" },
            { 'C', "1100" },
            { 'D', "1101" },
            { 'E', "1110" },
            { 'F', "1111" }
        };

        private static readonly Dictionary<string, char> binaryCharacterToHex = new Dictionary<string, char> {
            { "0000", '0' },
            { "0001", '1' },
            { "0010", '2' },
            { "0011", '3' },
            { "0100", '4' },
            { "0101", '5' },
            { "0110", '6' },
            { "0111", '7' },
            { "1000", '8' },
            { "1001", '9' },
            { "1010", 'A' },
            { "1011", 'B' },
            { "1100", 'C' },
            { "1101", 'D' },
            { "1110", 'E' },
            { "1111", 'F' }
        };

        static string HexStringToBinary(string hex)
        {
            StringBuilder result = new StringBuilder();
            foreach (char c in hex)
            {
                // This will crash for non-hex characters. You might want to handle that differently.
                result.Append(hexCharacterToBinary[char.ToUpper(c)]);
            }
            return result.ToString();
        }

        static string BinaryStringToHex(string binary)
        {
            StringBuilder result = new StringBuilder();
            

            foreach (string c in Enumerable.Range(0, binary.Length / 4).Select(i => binary.Substring(i * 4, 4)))
            {
                // This will crash for non-hex characters. You might want to handle that differently.
                result.Append(binaryCharacterToHex[c]);
            }
            return result.ToString();
        }

        private static string XorBins(string bin1, string bin2)
        {
            int len = Math.Max(bin1.Length, bin2.Length);
            string res = "";
            bin1 = bin1.PadLeft(len, '0');
            bin2 = bin2.PadLeft(len, '0');

            for (int i = 0; i < len; i++)
                res += bin1[i] == bin2[i] ? '0' : '1';

            return res;
        }

        private static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(512))
                {

                    //Import the RSA Key information. This only needs
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);

                }
                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }
    }
}
