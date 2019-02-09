<?php namespace Model\JWT;

use Model\Core\Module;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;

class JWT extends Module
{
	/**
	 * Standard claims:
	 *
	 *
	 * - "iss" (Issuer) Claim
	 *
	 * The "iss" (issuer) claim identifies the principal that issued the
	 * JWT.  The processing of this claim is generally application specific.
	 * The "iss" value is a case-sensitive string containing a StringOrURI
	 * value.  Use of this claim is OPTIONAL.
	 *
	 * - "sub" (Subject) Claim
	 *
	 * The "sub" (subject) claim identifies the principal that is the
	 * subject of the JWT.  The claims in a JWT are normally statements
	 * about the subject.  The subject value MUST either be scoped to be
	 * locally unique in the context of the issuer or be globally unique.
	 * The processing of this claim is generally application specific.  The
	 * "sub" value is a case-sensitive string containing a StringOrURI
	 * value.  Use of this claim is OPTIONAL.
	 *
	 * - "aud" (Audience) Claim
	 *
	 * The "aud" (audience) claim identifies the recipients that the JWT is
	 * intended for.  Each principal intended to process the JWT MUST
	 * identify itself with a value in the audience claim.  If the principal
	 * processing the claim does not identify itself with a value in the
	 * "aud" claim when this claim is present, then the JWT MUST be
	 * rejected.  In the general case, the "aud" value is an array of case-
	 * sensitive strings, each containing a StringOrURI value.  In the
	 * special case when the JWT has one audience, the "aud" value MAY be a
	 * single case-sensitive string containing a StringOrURI value.  The
	 * interpretation of audience values is generally application specific.
	 * Use of this claim is OPTIONAL.
	 *
	 * - "exp" (Expiration Time) Claim
	 *
	 * The "exp" (expiration time) claim identifies the expiration time on
	 * or after which the JWT MUST NOT be accepted for processing.  The
	 * processing of the "exp" claim requires that the current date/time
	 * MUST be before the expiration date/time listed in the "exp" claim.
	 * Implementers MAY provide for some small leeway, usually no more than
	 * a few minutes, to account for clock skew.  Its value MUST be a number
	 * containing a NumericDate value.  Use of this claim is OPTIONAL.
	 *
	 * - "nbf" (Not Before) Claim
	 *
	 * The "nbf" (not before) claim identifies the time before which the JWT
	 * MUST NOT be accepted for processing.  The processing of the "nbf"
	 * claim requires that the current date/time MUST be after or equal to
	 * the not-before date/time listed in the "nbf" claim.  Implementers MAY
	 * provide for some small leeway, usually no more than a few minutes, to
	 * account for clock skew.  Its value MUST be a number containing a
	 * NumericDate value.  Use of this claim is OPTIONAL.
	 *
	 * - "iat" (Issued At) Claim
	 *
	 * The "iat" (issued at) claim identifies the time at which the JWT was
	 * issued.  This claim can be used to determine the age of the JWT.  Its
	 * value MUST be a number containing a NumericDate value.  Use of this
	 * claim is OPTIONAL.
	 *
	 * - "jti" (JWT ID) Claim
	 *
	 * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	 * The identifier value MUST be assigned in a manner that ensures that
	 * there is a negligible probability that the same value will be
	 * accidentally assigned to a different data object; if the application
	 * uses multiple issuers, collisions MUST be prevented among values
	 * produced by different issuers as well.  The "jti" claim can be used
	 * to prevent the JWT from being replayed.  The "jti" value is a case-
	 * sensitive string.  Use of this claim is OPTIONAL.
	 *
	 *
	 * @param array $content
	 * @return string
	 */
	public function build(array $content): string
	{
		$builder = new Builder();

		$standardClaims = [
			'iss',
			'sub',
			'aud',
			'exp',
			'nbf',
			'iat',
			'jti',
		];

		if (isset($content['iss']))
			$builder->setIssuer($content['iss']);
		if (isset($content['sub']))
			$builder->setSubject($content['sub']);
		if (isset($content['aud']))
			$builder->setAudience($content['aud']);
		if (isset($content['exp']))
			$builder->setExpiration($content['exp']);
		if (isset($content['nbf']))
			$builder->setNotBefore($content['nbf']);
		if (isset($content['iat']))
			$builder->setIssuedAt($content['iat']);
		if (isset($content['jti']))
			$builder->setId($content['jti']);

		foreach ($standardClaims as $claim) {
			if (isset($content[$claim]))
				unset($content[$claim]);
		}

		foreach ($content as $claim => $value)
			$builder->set($claim, $value);


		$signer = new Sha512();
		$key = $this->getKey();
		$builder->sign($signer, $key);

		$token = $builder->getToken();

		return (string)$token;
	}

	/**
	 * @param string $stringToken
	 * @return array|null
	 */
	public function verify(string $stringToken): ?array
	{
		$token = (new Parser())->parse($stringToken);

		$signer = new Sha512();
		$key = $this->getKey();
		if (!$token->verify($signer, $key))
			return null;

		$data = new ValidationData();
		if (!$token->validate($data))
			return null;

		return $token->getClaims();
	}

	/**
	 * @return string
	 */
	private function getKey(): string
	{
		if (file_exists(INCLUDE_PATH . 'model' . DIRECTORY_SEPARATOR . 'JWT' . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'token-key.php')) {
			$key = file_get_contents(INCLUDE_PATH . 'model' . DIRECTORY_SEPARATOR . 'JWT' . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'token-key.php');
		} else {
			$key = $this->model->_RandToken->getToken('jwt', 64);
			file_put_contents(INCLUDE_PATH . 'model' . DIRECTORY_SEPARATOR . 'JWT' . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'token-key.php', $key);
		}

		return $key;
	}
}
