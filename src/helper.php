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

//------------------------
// ThinkPHP 助手函数
//-------------------------

// 获取多语言变量
function L($name, $vars = [], $lang = '')
{
    return \think\Lang::get($name, $vars, $lang);
}

// 获取配置参数
function C($name = '', $value = null, $range = '')
{
    if (is_null($value) && is_string($name)) {
        return \think\Config::get($name, $range);
    } else {
        return \think\Config::set($name, $value, $range);
    }
}

// 获取输入数据 支持默认值和过滤
function I($key, $default = null, $filter = '', $merge = false)
{
    if (0 === strpos($key, '?')) {
        $key = substr($key, 1);
        $has = '?';
    } else {
        $has = '';
    }
    if ($pos = strpos($key, '.')) {
        // 指定参数来源
        $method = substr($key, 0, $pos);
        if (in_array($method, ['get', 'post', 'put', 'param', 'request', 'session', 'cookie', 'server', 'globals', 'env', 'path', 'file'])) {
            $key = substr($key, $pos + 1);
        } else {
            $method = 'param';
        }
    } else {
        // 默认为自动判断
        $method = 'param';
    }
    return \think\Input::$method($has . $key, $default, $filter, $merge);
}

/**
 * 记录时间（微秒）和内存使用情况
 * @param string $start 开始标签
 * @param string $end 结束标签
 * @param integer $dec 小数位
 * @return mixed
 */
function G($start, $end = '', $dec = 6)
{
    if ('' == $end) {
        \think\Debug::remark($start);
    } else {
        return 'm' == $dec ? \think\Debug::getRangeMem($start, $end) : \think\Debug::getRangeTime($start, $end, $dec);
    }
}

/**
 * 浏览器友好的变量输出
 * @param mixed $var 变量
 * @param boolean $echo 是否输出 默认为true 如果为false 则返回输出字符串
 * @param string $label 标签 默认为空
 * @return void|string
 */
function dump($var, $echo = true, $label = null)
{
    return \think\Debug::dump($var, $echo, $label);
}

function session($name, $value = '')
{
    if (is_array($name)) {
        // 初始化
        \think\Session::init($name);
    } elseif (is_null($name)) {
        // 清除
        \think\Session::clear($value);
    } elseif ('' === $value) {
        // 获取
        return \think\Session::get($name);
    } elseif (is_null($value)) {
        // 删除session
        return \think\Session::delete($name);
    } else {
        // 设置session
        return \think\Session::set($name, $value);
    }
}

function cookie($name, $value = '')
{
    if (is_array($name)) {
        // 初始化
        \think\Cookie::init($name);
    } elseif (is_null($name)) {
        // 清除
        \think\Cookie::clear($value);
    } elseif ('' === $value) {
        // 获取
        return \think\Cookie::get($name);
    } elseif (is_null($value)) {
        // 删除session
        return \think\Cookie::delete($name);
    } else {
        // 设置session
        return \think\Cookie::set($name, $value);
    }
}

/**
 * 缓存管理
 * @param mixed $name 缓存名称，如果为数组表示进行缓存设置
 * @param mixed $value 缓存值
 * @param mixed $options 缓存参数
 * @return mixed
 */
function S($name, $value = '', $options = null)
{
    if (is_array($options)) {
        // 缓存操作的同时初始化
        \think\Cache::connect($options);
    } elseif (is_array($name)) {
        // 缓存初始化
        return \think\Cache::connect($name);
    }
    if ('' === $value) {
        // 获取缓存
        return \think\Cache::get($name);
    } elseif (is_null($value)) {
        // 删除缓存
        return \think\Cache::rm($name);
    } else {
        // 缓存数据
        if (is_array($options)) {
            $expire = isset($options['expire']) ? $options['expire'] : null; //修复查询缓存无法设置过期时间
        } else {
            $expire = is_numeric($options) ? $options : null; //默认快捷缓存设置过期时间
        }
        return \think\Cache::set($name, $value, $expire);
    }
}

/**
 * 记录日志信息
 * @param mixed $log log信息 支持字符串和数组
 * @param string $level 日志级别
 * @return void|array
 */
function trace($log = '[think]', $level = 'log')
{
    if ('[think]' === $log) {
        return \think\Log::getLog();
    } else {
        \think\Log::record($log, $level);
    }
}
