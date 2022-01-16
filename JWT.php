<?php namespace Model\JWT;

use Firebase\JWT\Key;
use Model\Core\Module;
use Firebase\JWT\JWT as FirebaseJWT;

class JWT extends Module
{
	/**
	 * @param array $content
	 * @return string
	 */
	public function build(array $content): string
	{
		return FirebaseJWT::encode(
			$content,
			$this->getKey(),
			'HS512'
		);
	}

	/**
	 * @param string $stringToken
	 * @return array|null
	 */
	public function verify(string $stringToken): ?array
	{
		return (array)FirebaseJWT::decode($stringToken, new Key($this->getKey(), 'HS512'));
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
