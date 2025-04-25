const {
  EdDSAJwsVerifier,
  FailFast,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  IotaIdentityClient,
  Resolver,
  Jwt
} = require('@iota/identity-wasm/node')
const { Client } = require('@iota/sdk-wasm/node')

const client = new Client({
  primaryNode: process.env.API_ENDPOINT,
  localPow: true
})

exports.verifyVC = async (req, res) => {
  try {
    const { credentialJwt } = req.body

    const jwtObj = new Jwt(credentialJwt)
    const didClient = new IotaIdentityClient(client)
    const resolver = new Resolver({ client: didClient })

    const holderDID = JwtCredentialValidator.extractIssuerFromJwt(jwtObj)
    const didDocument = await resolver.resolve(holderDID.toString())

    const decoded_credential = new JwtCredentialValidator(
      new EdDSAJwsVerifier()
    ).validate(
      jwtObj,
      didDocument,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError
    )

    res.status(200).json({
      message: 'VC verified successfully',
      credential: JSON.parse(decoded_credential.intoCredential(), null, 2)
    })
  } catch (error) {
    console.error('Error verifying VC:', error)
    res.status(500).json({
      message: 'Failed to verify VC',
      error: error.message
    })
  }
}
