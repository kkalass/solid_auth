import 'package:solid_auth/src/jwt/dart_jsonwebtoken.dart';
import 'package:solid_auth/src/rsa/rsa_api.dart';
import 'package:uuid/uuid.dart';

/// Generate dPoP token for the authentication
String genDpopToken(String endPointUrl, KeyPair rsaKeyPair,
    dynamic publicKeyJwk, String httpMethod) {
  /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-03
  /// Unique identifier for DPoP proof JWT
  /// Here we are using a version 4 UUID according to https://datatracker.ietf.org/doc/html/rfc4122
  var uuid = const Uuid();
  final String tokenId = uuid.v4();

  /// Initialising token head and body (payload)
  /// https://solid.github.io/solid-oidc/primer/#authorization-code-pkce-flow
  /// https://datatracker.ietf.org/doc/html/rfc7519
  var tokenHead = {"alg": "RS256", "typ": "dpop+jwt", "jwk": publicKeyJwk};

  var tokenBody = {
    "htu": endPointUrl,
    "htm": httpMethod,
    "jti": tokenId,
    "iat": (DateTime.now().millisecondsSinceEpoch / 1000).round()
  };

  /// Create a json web token
  final jwt = JWT(
    tokenBody,
    header: tokenHead,
  );

  /// Sign the JWT using private key
  var dpopToken = jwt.sign(RSAPrivateKey(rsaKeyPair.privateKey),
      algorithm: JWTAlgorithm.RS256);

  return dpopToken;
}
