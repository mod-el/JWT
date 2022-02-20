<?php namespace Model\JWT;

use Model\Core\Module_Config;

class Config extends Module_Config
{
	/**
	 */
	protected function assetsList()
	{
		$this->addAsset('config', 'config.php', function () {
			return '<?php
$config = [
	\'fixed-key\' => null,
	\'redis-class\' => null,
	\'redis-prefix\' => null,
];
';
		});
	}

	public function getConfigData(): ?array
	{
		return [];
	}
}
