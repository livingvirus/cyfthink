<?php
// 开始运行时间和内存使用
define('START_TIME', microtime(true));
define('START_MEM', memory_get_usage());
// 系统常量
defined('DS') or define('DS', DIRECTORY_SEPARATOR);
defined('THINK_PATH') or define('THINK_PATH', dirname(__FILE__) . DS);
defined('APP_PATH') or define('APP_PATH', dirname($_SERVER['SCRIPT_FILENAME']) . DS);
defined('APP_NAMESPACE') or define('APP_NAMESPACE', 'app');
defined('COMMON_MODULE') or define('COMMON_MODULE', 'common');
defined('RUNTIME_PATH') or define('RUNTIME_PATH', dirname(APP_PATH) . DS . 'runtime' . DS);
defined('LOG_PATH') or define('LOG_PATH', RUNTIME_PATH . 'log' . DS);
defined('CACHE_PATH') or define('CACHE_PATH', RUNTIME_PATH . 'cache' . DS);
defined('TEMP_PATH') or define('TEMP_PATH', RUNTIME_PATH . 'temp' . DS);
defined('EXT') or define('EXT', '.php');
defined('MODEL_LAYER') or define('MODEL_LAYER', 'model');
defined('VIEW_LAYER') or define('VIEW_LAYER', 'view');
defined('CONTROLLER_LAYER') or define('CONTROLLER_LAYER', 'controller');
defined('APP_DEBUG') or define('APP_DEBUG', false); // 是否调试模式
defined('APP_HOOK') or define('APP_HOOK', false); // 是否开启HOOK
defined('ENV_PREFIX') or define('ENV_PREFIX', 'T_'); // 环境变量的配置前缀

// 环境常量
define('IS_WIN', strstr(PHP_OS, 'WIN') ? 1 : 0);
define('IS_CLI', PHP_SAPI == 'cli' ? 1 : 0);
define('IS_AJAX', (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') ? true : false);
define('NOW_TIME', $_SERVER['REQUEST_TIME']);
