<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006~2016 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st <liu21st@gmail.com>
// +----------------------------------------------------------------------

namespace think;

class Loader
{
    // 类名映射
    protected static $map = [];
    // 加载列表
    protected static $load = [];
    // 命名空间
    protected static $namespace = [];
    // PSR-4
    private static $prefixLengthsPsr4 = [];
    private static $prefixDirsPsr4    = [];
    // PSR-0
    private static $prefixesPsr0 = [];

    /**
     * 实例化（分层）模型
     * @param string $name Model名称
     * @param string $layer 业务层名称
     * @return Object
     */
    public static function model($name = '', $layer = MODEL_LAYER)
    {
        if (empty($name)) {
            return new Model;
        }
        static $_model = [];
        if (isset($_model[$name . $layer])) {
            return $_model[$name . $layer];
        }
        if (strpos($name, '/')) {
            list($module, $name) = explode('/', $name, 2);
        } else {
            $module = MODULE_NAME;
        }
        $class = self::parseClass($module, $layer, $name);
        $name  = basename($name);
        if (class_exists($class)) {
            $model = new $class($name);
        } else {
            $class = str_replace('\\' . $module . '\\', '\\' . COMMON_MODULE . '\\', $class);
            if (class_exists($class)) {
                $model = new $class($name);
            } else {
                Log::record('实例化不存在的类：' . $class, 'notic');
                $model = new Model($name);
            }
        }
        $_model[$name . $layer] = $model;
        return $model;
    }

    /**
     * 字符串命名风格转换
     * type 0 将Java风格转换为C的风格 1 将C风格转换为Java的风格
     * @param string $name 字符串
     * @param integer $type 转换类型
     * @return string
     */
    public static function parseName($name, $type = 0)
    {
        if ($type) {
            return ucfirst(preg_replace_callback('/_([a-zA-Z])/', function ($match) {return strtoupper($match[1]);}, $name));
        } else {
            return strtolower(trim(preg_replace("/[A-Z]/", "_\\0", $name), "_"));
        }
    }

    /**
     * 解析应用类的类名
     * @param string $module 模块名
     * @param string $layer 层名 controller model ...
     * @param string $name 类名
     * @return string
     */
    public static function parseClass($module, $layer, $name)
    {
        $name  = str_replace(['/', '.'], '\\', $name);
        $array = explode('\\', $name);
        $class = self::parseName(array_pop($array), 1);
        $path  = $array ? implode('\\', $array) . '\\' : '';
        return APP_NAMESPACE . '\\' . $module . '\\' . $layer . '\\' . $path . $class;
    }
}
