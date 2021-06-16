<?php
namespace MediaWiki\Extension\NaylorAMS;

use GlobalVarConfig;

class Config extends GlobalVarConfig {
	public function __construct() {
		parent::__construct('wgNaylorAMS_');
	}

	/**
	 * Factory method for MediaWikiServices
	 * @return Config
	 */
	public static function newInstance() {
		return new self();
	}
}
