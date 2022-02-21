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
	\'redis\' => false,
];
';
		});
	}

	public function getConfigData(): ?array
	{
		return [
			'fixed-key' => ['label' => 'Chiave JWT fissa?', 'default' => null],
			'redis' => ['label' => 'Uso di Redis y/n', 'default' => false],
		];
	}
}
