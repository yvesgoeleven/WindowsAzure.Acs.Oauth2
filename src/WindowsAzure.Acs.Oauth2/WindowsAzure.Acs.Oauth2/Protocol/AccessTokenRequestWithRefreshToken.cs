using System;

namespace WindowsAzure.Acs.Oauth2.Protocol
{
    [Serializable]
    public class AccessTokenRequestWithRefreshToken
        : AccessTokenRequest
    {
        public string RefreshToken
        {
            get
            {
                return base.Parameters["refresh_token"];
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentNullException("value");
                }
                base.Parameters["refresh_token"] = value;
            }
        }

        public string Code
        {
            get
            {
                return base.Parameters["code"];
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentNullException("value");
                }
                base.Parameters["code"] = value;
            }
        }

        public Uri RedirectUri
        {
            get
            {
                if (base.Parameters["redirect_uri"] != null)
                {
                    return new Uri(base.Parameters["redirect_uri"]);
                }
                return null;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                if (!value.IsAbsoluteUri)
                {
                    throw new ArgumentException(string.Format(Resources.ID3709, value.AbsoluteUri), "value");
                }
                base.Parameters["redirect_uri"] = value.AbsoluteUri;
            }
        }

        public AccessTokenRequestWithRefreshToken(Uri baseUri)
            : base(baseUri)
        {
        }

        public override void Validate()
        {
            if (string.IsNullOrEmpty(this.RefreshToken))
            {
                throw new OAuthMessageException(Resources.ID3752);
            }
            base.Validate();
        }
    }
}