using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace ExternalIdentityServerAspNetIdentity.Services
{

    /*
     *https://gist.github.com/mykeels/408a26fb9411aff8fb7506f53c77c57a#file-rsakeyservice-cs
     *https://stackoverflow.com/questions/49042474/addsigningcredential-for-identityserver4
     *Perhaps generate key and store in redis / dynamodb or other for scalling out auth servers
     *Maybe remove timestamp / file, and place somewhere else. But helps security wise
     *Perhaps make interface that supports different storage types
     *Nuget packages so other people can use similar approach
     */

    public class RsaKeyService
    {
        /// <summary>
        /// This points to a JSON file in the format: 
        /// {
        ///  "Modulus": "",
        ///  "Exponent": "",
        ///  "P": "",
        ///  "Q": "",
        ///  "DP": "",
        ///  "DQ": "",
        ///  "InverseQ": "",
        ///  "D": ""
        /// }
        /// </summary>
        private string File
        {
            get
            {
                return Path.Combine(_environment.ContentRootPath, "rsakey.json");
            }
        }
        private readonly IWebHostEnvironment _environment;
        private readonly TimeSpan _timeSpan;

        public RsaKeyService(IWebHostEnvironment environment, TimeSpan timeSpan)
        {
            _environment = environment;
            _timeSpan = timeSpan;
        }

        public bool NeedsUpdate()
        {
            if (System.IO.File.Exists(File))
            {
                var creationDate = System.IO.File.GetCreationTime(File);
                return DateTime.Now.Subtract(creationDate) > _timeSpan;
            }
            return true;
        }

        public RSAParameters GetRandomKey()
        {
            using var rsa = new RSACryptoServiceProvider(2048);
            try
            {
                return rsa.ExportParameters(true);
            }
            finally
            {
                rsa.PersistKeyInCsp = false;
            }
        }

        public RsaKeyService GenerateKeyAndSave(bool forceUpdate = false)
        {
            if (forceUpdate || NeedsUpdate())
            {
                var p = GetRandomKey();
                RSAParametersWithPrivate t = new RSAParametersWithPrivate();
                t.SetParameters(p);
                System.IO.File.WriteAllText(File, JsonConvert.SerializeObject(t, Formatting.Indented));
            }
            return this;
        }

        /// <summary>
        /// 
        /// Generate 
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public RSAParameters GetKeyParameters()
        {
            if (!System.IO.File.Exists(File)) throw new FileNotFoundException("Check configuration - cannot find auth key file: " + File);
            var keyParams = JsonConvert.DeserializeObject<RSAParametersWithPrivate>(System.IO.File.ReadAllText(File));
            return keyParams.ToRSAParameters();
        }

        public RsaSecurityKey GetKey()
        {
            if (NeedsUpdate()) GenerateKeyAndSave();
            var provider = new RSACryptoServiceProvider();
            provider.ImportParameters(GetKeyParameters());
            return new RsaSecurityKey(provider);
        }


        /// <summary>
        /// Util class to allow restoring RSA parameters from JSON as the normal
        /// RSA parameters class won't restore private key info.
        /// </summary>
        private class RSAParametersWithPrivate
        {
            public byte[] D { get; set; }
            public byte[] DP { get; set; }
            public byte[] DQ { get; set; }
            public byte[] Exponent { get; set; }
            public byte[] InverseQ { get; set; }
            public byte[] Modulus { get; set; }
            public byte[] P { get; set; }
            public byte[] Q { get; set; }

            public void SetParameters(RSAParameters p)
            {
                D = p.D;
                DP = p.DP;
                DQ = p.DQ;
                Exponent = p.Exponent;
                InverseQ = p.InverseQ;
                Modulus = p.Modulus;
                P = p.P;
                Q = p.Q;
            }
            public RSAParameters ToRSAParameters()
            {
                return new RSAParameters()
                {
                    D = D,
                    DP = DP,
                    DQ = DQ,
                    Exponent = Exponent,
                    InverseQ = InverseQ,
                    Modulus = Modulus,
                    P = P,
                    Q = Q

                };
            }
        }
    }
}
